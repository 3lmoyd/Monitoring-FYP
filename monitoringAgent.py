# central server (Flask + SQLite + basic APIs + dashboard)

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, Response, redirect


BASE_DIR = Path(__file__).parent.resolve()
DB_PATH  = BASE_DIR / "telemetry.db"
API_KEY  = "CHANGE_ME_SUPER_SECRET"  

# Oman timezone
OMAN_TZ = timezone(timedelta(hours=4))

# Local TI: trusted IPs
LOCAL_TI = {
    "10.10.1.5":  "kali",
    "10.10.1.6":  "win11",
    "10.10.1.10": "server",
}

# Metric thresholds
CPU_TH  = 80.0
MEM_TH  = 80.0
DISK_TH = 80.0

# update alert 
METRIC_DELTA_RESEND = 5.0

app = Flask(__name__, static_folder=None)



def db():
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db(); cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        os   TEXT NOT NULL,
        cpu  REAL,
        mem  REAL,
        disk REAL,
        net_up   REAL,
        net_down REAL,
        ts   DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host    TEXT,
        level   TEXT,
        message TEXT,
        ts      DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    # state to dont repeating same alerts
    # status "high" or "normal"
    # last percentage sent for alert
    cur.execute("""
    CREATE TABLE IF NOT EXISTS metric_state(
        host TEXT NOT NULL,
        kind TEXT NOT NULL,         -- cpu/mem/disk
        status TEXT NOT NULL,       -- high/normal
        last_value REAL,            -- last sent value
        updated_ts DATETIME NOT NULL,
        PRIMARY KEY(host, kind)
    )
    """)

    
    try:
        cur.execute("ALTER TABLE metrics ADD COLUMN ip TEXT")
    except sqlite3.OperationalError:
        pass

    con.commit(); con.close()


init_db()


def since_minutes(con, mins=10):
    cur = con.cursor()
    cur.execute("SELECT DATETIME('now','-%d minutes')" % mins)
    return cur.fetchone()[0]


def _f(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return float(default)


def _get_metric_state(cur, host: str, kind: str):
    cur.execute("SELECT status, last_value FROM metric_state WHERE host=? AND kind=?", (host, kind))
    r = cur.fetchone()
    if not r:
        return ("normal", None)
    return (r["status"], r["last_value"])


def _set_metric_state(cur, host: str, kind: str, status: str, last_value):
    now_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT INTO metric_state(host,kind,status,last_value,updated_ts)
        VALUES(?,?,?,?,?)
        ON CONFLICT(host,kind) DO UPDATE SET
          status=excluded.status,
          last_value=excluded.last_value,
          updated_ts=excluded.updated_ts
    """, (host, kind, status, last_value, now_utc))


def handle_metric(cur, host: str, host_ip: str, kind: str, value: float, threshold: float):
    """
    Emits:
    - critical alert once when crossing into HIGH
    - optional critical update if still HIGH but changed enough
    - info recovery once when back to NORMAL
    Avoids repeating identical alerts.
    """
    prev_status, prev_value = _get_metric_state(cur, host, kind)

    is_high = value >= threshold

   
    if is_high and prev_status != "high":
        msg = f"{kind.upper()} high on {host} ({host_ip}): {value:.1f}%"
        cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)", (host, "critical", msg))
        _set_metric_state(cur, host, kind, "high", float(value))
        return

    
    if is_high and prev_status == "high":
        if prev_value is None or abs(float(value) - float(prev_value)) >= METRIC_DELTA_RESEND:
            msg = f"{kind.upper()} still high on {host} ({host_ip}): {value:.1f}%"
            cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)", (host, "critical", msg))
            _set_metric_state(cur, host, kind, "high", float(value))
        
        return

    
    if (not is_high) and prev_status == "high":
        msg = f"{kind.upper()} back to normal on {host} ({host_ip}): {value:.1f}%"
        cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)", (host, "info", msg))
        _set_metric_state(cur, host, kind, "normal", float(value))
        return

   
    _set_metric_state(cur, host, kind, "normal", float(value))


# recive data from agent
@app.post("/ingest")
def ingest():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(force=True, silent=True) or {}

    
    if "meta" in payload or "resources" in payload:
        meta      = payload.get("meta", {}) or {}
        resources = payload.get("resources", {}) or {}
        network   = payload.get("network", {}) or {}

        host     = meta.get("hostname") or payload.get("host", "unknown")
        osname   = meta.get("os") or payload.get("os", "unknown")
        host_ip  = meta.get("ip") or payload.get("src_ip") or request.remote_addr or "unknown"

        cpu  = _f(resources.get("cpu_percent", 0))
        mem  = _f(resources.get("ram_percent", 0))
        disk = _f(resources.get("disk_percent", 0))

        total = network.get("total", {}) or {}
        net_up   = _f(total.get("bytes_sent", 0))
        net_down = _f(total.get("bytes_recv", 0))

        con = db(); cur = con.cursor()

        # store 
        cur.execute(
            "INSERT INTO metrics(host,os,cpu,mem,disk,net_up,net_down,ip) VALUES(?,?,?,?,?,?,?,?)",
            (host, osname, cpu, mem, disk, net_up, net_down, host_ip)
        )

        #alerts (no duplicates)
        handle_metric(cur, host, host_ip, "cpu",  cpu,  CPU_TH)
        handle_metric(cur, host, host_ip, "mem",  mem,  MEM_TH)
        handle_metric(cur, host, host_ip, "disk", disk, DISK_TH)

        
        auth_events = payload.get("auth_events", []) or []
        for evt in auth_events:
            etype = (evt.get("type") or "").lower().strip()
            if not etype:
                continue

            attacker_ip = (evt.get("src_ip") or "unknown").strip()
            status_tag = "(Local)" if attacker_ip in LOCAL_TI else "(TI)"
            event_time = datetime.now(OMAN_TZ).strftime("%Y-%m-%d %H:%M:%S")

            if etype == "successful_login":
                level = "critical"
                verb  = "Successful SSH login"
            elif etype == "failed_login":
                level = "warning"
                verb  = "Failed SSH login"
            elif etype == "logout":
                level = "warning"
                verb  = "SSH logout"
            else:
                level = "info"
                verb  = f"Auth event ({etype})"

            level_tag = level.upper()
            msg = (
                f"[{level_tag}] {status_tag} {verb} "
                f"from {attacker_ip} (attacker_user) "
                f"at {event_time} "
                f"to ip {host_ip} (target_user)"
            )

            cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)", (host, level, msg))

        con.commit(); con.close()
        return jsonify({"status": "ok", "mode": "meta"})

   
    host    = payload.get("host", "unknown")
    osname  = payload.get("os", "unknown")
    cpu     = _f(payload.get("cpu", 0))
    mem     = _f(payload.get("mem", 0))
    disk    = _f(payload.get("disk", 0))
    net_up  = _f(payload.get("net_up", 0))
    net_down= _f(payload.get("net_down", 0))
    evt_msg = payload.get("event_msg")
    evt_lvl = payload.get("event_level", "info")

    host_ip = payload.get("src_ip") or request.remote_addr or "unknown"

    con = db(); cur = con.cursor()
    cur.execute(
        "INSERT INTO metrics(host,os,cpu,mem,disk,net_up,net_down,ip) VALUES(?,?,?,?,?,?,?,?)",
        (host, osname, cpu, mem, disk, net_up, net_down, host_ip)
    )

    #alerts
    handle_metric(cur, host, host_ip, "cpu",  cpu,  CPU_TH)
    handle_metric(cur, host, host_ip, "mem",  mem,  MEM_TH)
    handle_metric(cur, host, host_ip, "disk", disk, DISK_TH)

    if evt_msg:
        cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)", (host, evt_lvl, evt_msg))

    con.commit(); con.close()
    return jsonify({"status": "ok", "mode": "flat"})


@app.get("/api/hosts")
def api_hosts():
    con = db(); cur = con.cursor()

    cur.execute("""
        SELECT m1.host, m1.os, m1.cpu, m1.mem, m1.disk,
               m1.net_up, m1.net_down, m1.ip, m1.ts
        FROM metrics m1
        JOIN (
            SELECT host, MAX(id) AS max_id
            FROM metrics
            GROUP BY host
        ) m2
        ON m1.host = m2.host AND m1.id = m2.max_id
        ORDER BY m1.host
    """)
    rows = cur.fetchall()
    con.close()

    hosts = []
    now_utc = datetime.utcnow().replace(tzinfo=timezone.utc)

    for r in rows:
        ts_str = r["ts"]
        try:
            dt_utc = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            dt_utc = now_utc

        delta = (now_utc - dt_utc).total_seconds()
        status = "online" if delta <= 20 else "offline"

        last_seen_oman = dt_utc.astimezone(OMAN_TZ).strftime("%Y-%m-%d %H:%M:%S")

        hosts.append({
            "host": r["host"],
            "os": r["os"],
            "ip": r["ip"],
            "cpu": round(r["cpu"] or 0, 1),
            "mem": round(r["mem"] or 0, 1),
            "disk": round(r["disk"] or 0, 1),
            "net_up": round(r["net_up"] or 0, 1),
            "net_down": round(r["net_down"] or 0, 1),
            "last_seen": last_seen_oman,
            "status": status
        })

    return jsonify(hosts)


@app.get("/api/kpis")
def api_kpis():
    con = db(); cur = con.cursor()
    t0 = since_minutes(con, 10)
    cur.execute("SELECT AVG(cpu),AVG(mem),AVG(disk) FROM metrics WHERE ts >= ?", (t0,))
    a = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM events WHERE ts >= ? AND level IN ('warning','critical')", (t0,))
    alerts = cur.fetchone()[0]
    con.close()
    return jsonify({
        "cpu": round((a[0] or 0),1),
        "memory": round((a[1] or 0),1),
        "disk": round((a[2] or 0),1),
        "activeAlerts": alerts
    })


@app.get("/api/alerts")
def api_alerts():
    con = db(); cur = con.cursor()
    cur.execute("""
        SELECT id, host, level, message, ts
        FROM events
        WHERE ts >= DATETIME('now','-30 minutes')
        ORDER BY id DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    con.close()

    out = []
    for r in rows:
        ts_str = r["ts"]
        try:
            dt_utc = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            dt_utc = datetime.utcnow().replace(tzinfo=timezone.utc)
        time_oman = dt_utc.astimezone(OMAN_TZ).strftime("%Y-%m-%d %H:%M:%S")

        out.append({
            "id": r["id"],
            "level": r["level"],
            "message": r["message"],
            "time": time_oman,
            "source": r["host"]
        })
    return jsonify(out)



@app.get("/")
def index():
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>FYP Monitoring Dashboard</title>
        <style>
            * { box-sizing:border-box; margin:0; padding:0; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
            body { background:#0f172a; color:#e5e7eb; min-height:100vh; display:flex; align-items:flex-start; justify-content:center; }
            .container { width:100%; max-width:1100px; padding:24px; }
            h1 { font-size:28px; margin-bottom:8px; }
            .subtitle { font-size:14px; color:#9ca3af; margin-bottom:24px; }
            .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }
            .card { background:#020617; border-radius:16px; padding:16px 18px; box-shadow:0 10px 25px rgba(0,0,0,0.35); border:1px solid #1f2937; }
            .card-title { font-size:14px; color:#9ca3af; margin-bottom:8px; }
            .card-value { font-size:24px; font-weight:600; margin-bottom:10px; }
            .bar-track { height:8px; border-radius:999px; background:#1f2937; overflow:hidden; }
            .bar-fill { height:100%; width:0%; border-radius:999px; background:linear-gradient(90deg,#22c55e,#ef4444); transition:width 0.4s ease-out; }
            .status-ok { color:#22c55e; font-weight:500; }
            .status-bad { color:#ef4444; font-weight:500; }
            .footer { margin-top:20px; font-size:12px; color:#6b7280; display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }
            .pill { padding:4px 10px; border-radius:999px; border:1px solid #1f2937; background:#020617; font-size:11px; }
            .section-title { font-size:18px; margin-bottom:8px; margin-top:8px; }
            .hosts-table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
            .hosts-table th,.hosts-table td { padding:8px 10px; border-bottom:1px solid #1f2937; text-align:left; }
            .hosts-table th { color:#9ca3af; background:#020617; }
            .hosts-table tbody tr:hover { background:#020617; }
            .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; }
            .badge-online { background:rgba(34,197,94,0.15); color:#4ade80; }
            .badge-offline { background:rgba(239,68,68,0.15); color:#fca5a5; }

            .level-warning { background: rgba(234,179,8,0.10); }
            .level-warning td { color:#facc15; }

            .level-critical { background: rgba(239,68,68,0.12); }
            .level-critical td { color:#fecaca; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>FYP Local Monitoring Dashboard</h1>
            <div class="subtitle">Live KPIs and host status from your agents.</div>

            <div class="grid">
                <div class="card">
                    <div class="card-title">CPU Usage (avg)</div>
                    <div class="card-value" id="cpuValue">-- %</div>
                    <div class="bar-track"><div class="bar-fill" id="cpuBar"></div></div>
                </div>
                <div class="card">
                    <div class="card-title">Memory Usage (avg)</div>
                    <div class="card-value" id="memValue">-- %</div>
                    <div class="bar-track"><div class="bar-fill" id="memBar"></div></div>
                </div>
                <div class="card">
                    <div class="card-title">Disk Usage (avg)</div>
                    <div class="card-value" id="diskValue">-- %</div>
                    <div class="bar-track"><div class="bar-fill" id="diskBar"></div></div>
                </div>
                <div class="card">
                    <div class="card-title">Active Alerts (last 10 min)</div>
                    <div class="card-value" id="alertsValue">--</div>
                    <div id="alertsStatus" class="status-ok">Waiting for data...</div>
                </div>
            </div>

            <h2 class="section-title">Monitored Hosts</h2>
            <table class="hosts-table">
                <thead>
                    <tr>
                        <th>Host</th><th>IP</th><th>OS</th><th>Status</th>
                        <th>CPU</th><th>Memory</th><th>Disk</th><th>Last seen</th>
                    </tr>
                </thead>
                <tbody id="hostsBody"><tr><td colspan="8">Loading...</td></tr></tbody>
            </table>

            <h2 class="section-title">Recent Alerts</h2>
            <table class="hosts-table">
                <thead>
                    <tr><th>Time (Oman / UTC+4)</th><th>Host</th><th>Level</th><th>Message</th></tr>
                </thead>
                <tbody id="alertsBody"><tr><td colspan="4">Loading...</td></tr></tbody>
            </table>

            <div class="footer">
                <div id="lastUpdated">Last updated: --</div>
                <div class="pill">FYP Monitoring · 10.10.1.10:8000</div>
            </div>
        </div>

        <script>
            async function fetchKpis() {
                const res = await fetch('/api/kpis');
                const data = await res.json();
                const cpu  = Number(data.cpu ?? 0);
                const mem  = Number(data.memory ?? 0);
                const disk = Number(data.disk ?? 0);
                const alerts = Number(data.activeAlerts ?? 0);

                document.getElementById('cpuValue').textContent  = cpu.toFixed(1)  + ' %';
                document.getElementById('memValue').textContent  = mem.toFixed(1)  + ' %';
                document.getElementById('diskValue').textContent = disk.toFixed(1) + ' %';
                document.getElementById('alertsValue').textContent = alerts;

                document.getElementById('cpuBar').style.width  = Math.max(0, Math.min(cpu, 100))  + '%';
                document.getElementById('memBar').style.width  = Math.max(0, Math.min(mem, 100))  + '%';
                document.getElementById('diskBar').style.width = Math.max(0, Math.min(disk, 100)) + '%';

                const statusEl = document.getElementById('alertsStatus');
                statusEl.textContent = (alerts > 0) ? (alerts + ' alerts in last 10 minutes') : 'No active alerts';
                statusEl.className = (alerts > 0) ? 'status-bad' : 'status-ok';

                document.getElementById('lastUpdated').textContent =
                    'Last updated: ' + new Date().toLocaleTimeString();
            }

            async function fetchHosts() {
                const res = await fetch('/api/hosts');
                const hosts = await res.json();
                const tbody = document.getElementById('hostsBody');
                tbody.innerHTML = '';
                if (!hosts.length) {
                    tbody.innerHTML = '<tr><td colspan="8">No hosts reported yet.</td></tr>';
                    return;
                }
                hosts.forEach(h => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${h.host}</td>
                        <td>${h.ip || '-'}</td>
                        <td>${h.os}</td>
                        <td><span class="badge ${h.status === 'online' ? 'badge-online' : 'badge-offline'}">${h.status}</span></td>
                        <td>${Number(h.cpu).toFixed(1)} %</td>
                        <td>${Number(h.mem).toFixed(1)} %</td>
                        <td>${Number(h.disk).toFixed(1)} %</td>
                        <td>${h.last_seen}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            async function fetchAlerts() {
                const res = await fetch('/api/alerts');
                const alerts = await res.json();
                const tbody = document.getElementById('alertsBody');
                tbody.innerHTML = '';
                if (!alerts.length) {
                    tbody.innerHTML = '<tr><td colspan="4">No alerts yet.</td></tr>';
                    return;
                }
                alerts.forEach(a => {
                    const tr = document.createElement('tr');
                    tr.classList.add('level-' + (a.level || 'info').toLowerCase());
                    tr.innerHTML = `
                        <td>${a.time}</td>
                        <td>${a.source || '-'}</td>
                        <td>${a.level}</td>
                        <td>${a.message}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            function refreshAll() { fetchKpis(); fetchHosts(); fetchAlerts(); }
            refreshAll();
            setInterval(refreshAll, 3000);
        </script>
    </body>
    </html>
    """
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
