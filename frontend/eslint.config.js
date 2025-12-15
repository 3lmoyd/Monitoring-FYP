#!/usr/bin/env python3
# monitoringAgent.py — central server (Flask + SQLite + dashboard)

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, Response, redirect

# ---- CONFIG ----
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "telemetry.db"
API_KEY = "CHANGE_ME_SUPER_SECRET"  # must match agents' X-API-Key

# Oman timezone (UTC+4)
OMAN_TZ = timezone(timedelta(hours=4))

app = Flask(__name__, static_folder=None)


# =========================
#       DATABASE
# =========================

def db():
    """Return a SQLite connection with row factory."""
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    cur = con.cursor()

    # Metrics table (simple)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            os   TEXT NOT NULL,
            cpu  REAL,
            mem  REAL,
            disk REAL,
            ts   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Alerts table (Linux + Windows, normalized)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host      TEXT NOT NULL,
            os        TEXT NOT NULL,
            source    TEXT,       -- 'auth_log', 'security', 'sysmon', 'threshold', etc.
            category  TEXT,       -- 'auth', 'process', 'network', 'resource', ...
            event_id  INTEGER,
            event_name TEXT,
            severity   TEXT,      -- 'high','medium','low','info'
            username   TEXT,
            ip         TEXT,
            process    TEXT,
            message    TEXT,
            extra_json TEXT,
            ts   DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    con.commit()
    con.close()


init_db()


# =========================
#      SECURITY / AUTH
# =========================

def check_api_key(req):
    key = req.headers.get("X-API-Key")
    return key == API_KEY


# =========================
#          ROUTES
# =========================

@app.route("/", methods=["GET"])
def index():
    """Dashboard page."""
    return Response(DASHBOARD_HTML, mimetype="text/html")


@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Endpoint for agents.

    Expected JSON payload:
    {
      "meta": {...},
      "resources": {...},
      "network": {...},   # optional
      "alerts": [ {...}, {...} ]   # optional, from Linux or Windows
    }
    """
    if not check_api_key(request):
        return Response("Forbidden", status=403)

    try:
        data = request.get_json(force=True)
    except Exception:
        return Response("Invalid JSON", status=400)

    if not isinstance(data, dict):
        return Response("JSON must be object", status=400)

    meta = data.get("meta", {})
    resources = data.get("resources", {})

    host = meta.get("hostname", "unknown")
    os_name = meta.get("os", "unknown")
    cpu = resources.get("cpu_percent")
    mem = resources.get("ram_percent")
    disk = resources.get("disk_percent")

    # store server-side ts in Oman timezone
    now_ts = datetime.now(OMAN_TZ).isoformat()

    con = db()
    cur = con.cursor()

    # ---- Insert metrics row ----
    cur.execute(
        """
        INSERT INTO metrics(host, os, cpu, mem, disk, ts)
        VALUES(?,?,?,?,?,?)
        """,
        [host, os_name, cpu, mem, disk, now_ts],
    )

    # ---- Insert alerts if present ----
    alerts = data.get("alerts", [])
    alerts_inserted = 0

    if isinstance(alerts, list) and alerts:
        for a in alerts:
            if not isinstance(a, dict):
                continue

            # ---- compatibility & defaults ----
            event_id = a.get("event_id")
            source = a.get("source")
            username = a.get("username")
            ip_val = a.get("ip")
            process = a.get("process")
            message = a.get("message") or a.get("msg")

            # accept both "severity" and old "level"
            raw_sev = a.get("severity") or a.get("level") or "info"
            severity = str(raw_sev).lower()

            # auto-detect category if missing
            category = a.get("category")
            if not category:
                if event_id in (4624, 4625, 4634):
                    # login / failed login / logout
                    category = "auth"
                elif source in ("security", "auth_log"):
                    category = "auth"
                elif source in ("sysmon", "process"):
                    category = "process"
                elif source in ("network", "net"):
                    category = "network"
                else:
                    category = "resource"

            # --- make alert timestamp Oman time (UTC+4) ---
            raw_ts = a.get("timestamp")
            if raw_ts:
                try:
                    # handle ISO strings like "2025-12-10T06:53:24Z" or with offset
                    s = str(raw_ts)
                    if s.endswith("Z"):
                        s = s.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(s)

                    # if agent sent naive time (no tz), assume UTC then convert
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)

                    dt_oman = dt.astimezone(OMAN_TZ)
                    ts_value = dt_oman.isoformat()
                except Exception:
                    # if parsing fails, fall back to server Oman time
                    ts_value = now_ts
            else:
                # no timestamp from agent → use server Oman time
                ts_value = now_ts

            cur.execute(
                """
                INSERT INTO alerts(
                    host, os, source, category,
                    event_id, event_name, severity,
                    username, ip, process, message,
                    extra_json, ts
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                [
                    a.get("host", host),
                    a.get("os", os_name),
                    source,
                    category,
                    event_id,
                    a.get("event_name"),
                    severity,
                    username,
                    ip_val,
                    process,
                    message,
                    json.dumps(a, ensure_ascii=False),
                    ts_value,
                ],
            )
            alerts_inserted += 1

    con.commit()
    con.close()

    print(
        f"[INGEST] host={host} os={os_name} "
        f"cpu={cpu} mem={mem} disk={disk} alerts={alerts_inserted}"
    )

    return jsonify({"status": "ok", "alerts_ingested": alerts_inserted})


@app.route("/api/hosts", methods=["GET"])
def api_hosts():
    """
    Return list of known hosts with last seen timestamp and OS.
    """
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT host,
               os,
               MAX(ts) AS last_ts
        FROM metrics
        GROUP BY host, os
        ORDER BY host ASC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify(rows)


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    """
    Return metrics for charts.

    Query params:
      host  (optional) : filter by host
      limit (optional) : default 100
    """
    host = request.args.get("host")
    limit = request.args.get("limit", default=100, type=int)

    con = db()
    cur = con.cursor()

    if host:
        cur.execute(
            """
            SELECT id, host, os, cpu, mem, disk, ts
            FROM metrics
            WHERE host = ?
            ORDER BY ts DESC
            LIMIT ?
            """,
            (host, limit),
        )
    else:
        cur.execute(
            """
            SELECT id, host, os, cpu, mem, disk, ts
            FROM metrics
            ORDER BY ts DESC
            LIMIT ?
            """,
            (limit,),
        )

    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify(rows)


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    Return recent alerts (Linux + Windows).

    Query params:
      host     (optional)
      os       (optional)
      category (optional)
      severity (optional)
      limit    (optional) default 200
    """
    host = request.args.get("host")
    os_filter = request.args.get("os")
    category = request.args.get("category")
    severity = request.args.get("severity")
    limit = request.args.get("limit", default=200, type=int)

    con = db()
    cur = con.cursor()

    where_clauses = []
    params = []

    if host:
        where_clauses.append("host = ?")
        params.append(host)
    if os_filter:
        where_clauses.append("os LIKE ?")
        params.append(f"%{os_filter}%")
    if category:
        where_clauses.append("category = ?")
        params.append(category)
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT id, host, os, source, category,
               event_id, event_name, severity,
               username, ip, process, message, ts
        FROM alerts
        {where_sql}
        ORDER BY ts DESC
        LIMIT ?
    """
    params.append(limit)

    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify(rows)


# =========================
#     DASHBOARD HTML
# =========================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FYP Monitoring Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <!-- Chart.js CDN -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #0b1120;
      --bg-alt: #020617;
      --card: #111827;
      --card-alt: #020617;
      --accent: #38bdf8;
      --accent-soft: rgba(56,189,248,0.1);
      --text: #e5e7eb;
      --text-muted: #9ca3af;
      --danger: #f97373;
      --warning: #facc15;
      --success: #4ade80;
      --border: #1f2937;
      --danger-soft: rgba(248, 113, 113, 0.15);
      --warning-soft: rgba(234, 179, 8, 0.15);
      --success-soft: rgba(34,197,94,0.12);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, #0f172a 0, #020617 50%, #000 100%);
      color: var(--text);
      display: flex;
      height: 100vh;
      overflow: hidden;
    }

    .sidebar {
      width: 260px;
      background: linear-gradient(to bottom, #020617, #020617);
      border-right: 1px solid var(--border);
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .main {
      flex: 1;
      display: flex;
      flex-direction: column;
      padding: 1rem 1.5rem;
      gap: 1rem;
      overflow: hidden;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
    }

    .title {
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--accent);
    }

    .subtitle {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .badge {
      border-radius: 999px;
      padding: 0.25rem 0.75rem;
      font-size: 0.75rem;
      border: 1px solid var(--accent-soft);
      background: rgba(15,23,42,0.8);
    }

    .section-title {
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.08em;
      margin-bottom: 0.4rem;
    }

    .card {
      background: radial-gradient(circle at top left, rgba(56,189,248,0.08), #020617 40%);
      border-radius: 0.9rem;
      border: 1px solid var(--border);
      padding: 0.75rem 0.9rem;
    }

    .card-solid {
      background: var(--card);
      border-radius: 0.9rem;
      border: 1px solid var(--border);
      padding: 0.75rem 0.9rem;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-bottom: 0.2rem;
    }

    .host-list {
      list-style: none;
      margin: 0;
      padding: 0;
      max-height: calc(100vh - 200px);
      overflow-y: auto;
      scrollbar-width: thin;
    }

    .host-item {
      padding: 0.45rem 0.5rem;
      border-radius: 0.6rem;
      cursor: pointer;
      margin-bottom: 0.25rem;
      border: 1px solid transparent;
      display: flex;
      flex-direction: column;
      gap: 0.05rem;
    }

    .host-item:hover {
      border-color: var(--accent-soft);
      background: rgba(15,23,42,0.8);
    }

    .host-item.active {
      border-color: var(--accent);
      background: rgba(56,189,248,0.12);
    }

    .host-name {
      font-size: 0.88rem;
      font-weight: 600;
    }

    .host-meta {
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    .badge-os {
      font-size: 0.7rem;
      padding: 0.05rem 0.45rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(15,23,42,0.85);
      margin-left: 0.25rem;
    }

    .badge-status {
      font-size: 0.7rem;
      padding: 0.05rem 0.45rem;
      border-radius: 999px;
      margin-left: auto;
    }

    .badge-status.online {
      background: var(--success-soft);
      color: var(--success);
    }

    .badge-status.offline {
      background: var(--danger-soft);
      color: var(--danger);
    }

    .top-grid {
      display: grid;
      grid-template-columns: 2.2fr 1.4fr;
      gap: 1rem;
      height: 48%;
      min-height: 250px;
    }

    .bottom-grid {
      height: 50%;
      min-height: 250px;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 0.6rem;
      margin-bottom: 0.4rem;
    }

    .metric-value {
      font-size: 1.1rem;
      font-weight: 600;
    }

    .metric-label {
      font-size: 0.78rem;
      color: var(--text-muted);
    }

    .metric-chip {
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      background: rgba(15,23,42,0.9);
      border: 1px solid rgba(148,163,184,0.3);
      margin-top: 0.18rem;
    }

    .chart-wrapper {
      height: calc(100% - 1.4rem);
    }

    .chart-canvas {
      width: 100%;
      height: 100%;
    }

    .bottom-grid .card-solid {
      height: 100%;
      display: flex;
      flex-direction: column;
    }

    .alerts-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.4rem;
    }

    .alerts-filters {
      display: flex;
      gap: 0.4rem;
      align-items: center;
      flex-wrap: wrap;
    }

    .select, .input {
      background: var(--bg-alt);
      border-radius: 999px;
      border: 1px solid var(--border);
      padding: 0.25rem 0.7rem;
      color: var(--text);
      font-size: 0.75rem;
      outline: none;
    }

    .input {
      border-radius: 0.5rem;
    }

    .alerts-table-wrap {
      flex: 1;
      overflow: auto;
      border-radius: 0.6rem;
      border: 1px solid var(--border);
      background: #020617;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.78rem;
    }

    thead {
      position: sticky;
      top: 0;
      background: #020617;
      z-index: 1;
    }

    th, td {
      padding: 0.3rem 0.5rem;
      border-bottom: 1px solid #111827;
      text-align: left;
      white-space: nowrap;
    }

    th {
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    tbody tr:hover {
      background: rgba(15,23,42,0.8);
    }

    .severity-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.1rem 0.4rem;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 500;
    }

    .severity-pill.high {
      background: var(--danger-soft);
      color: var(--danger);
    }

    .severity-pill.medium {
      background: var(--warning-soft);
      color: var(--warning);
    }

    .severity-pill.low, .severity-pill.info {
      background: var(--success-soft);
      color: var(--success);
    }

    .tag-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.08rem 0.4rem;
      border-radius: 999px;
      font-size: 0.7rem;
      background: rgba(15,23,42,1);
      border: 1px solid rgba(148,163,184,0.4);
      color: var(--text-muted);
    }

    .text-faded {
      color: var(--text-muted);
    }

    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 999px;
      margin-right: 4px;
    }
  </style>
</head>
<body>
  <!-- Sidebar (hosts) -->
  <aside class="sidebar">
    <div>
      <div class="title">FYP Monitor</div>
      <div class="subtitle">Central dashboard for Kali + Windows agents</div>
    </div>

    <div class="card-solid">
      <div class="section-title">Hosts</div>
      <ul id="hostList" class="host-list"></ul>
    </div>

    <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: auto;">
      <div>🔐 API protected with X-API-Key</div>
      <div>📡 Endpoints: /ingest, /api/metrics, /api/alerts, /api/hosts</div>
    </div>
  </aside>

  <!-- Main content -->
  <main class="main">
    <header class="header">
      <div>
        <div style="display:flex;align-items:center;gap:0.4rem;">
          <span style="font-weight:600;">Host:</span>
          <span id="currentHostLabel" style="font-weight:600;">All hosts</span>
        </div>
        <div class="subtitle">Real-time CPU / RAM trends and normalized security alerts.</div>
      </div>
      <div>
        <span class="badge">Last refresh: <span id="lastRefresh">—</span></span>
      </div>
    </header>

    <section class="top-grid">
      <div class="card">
        <div class="card-header">
          <span class="section-title" style="margin:0;">Resource Overview</span>
          <span style="font-size:0.75rem;color:var(--text-muted);">CPU / RAM / Disk</span>
        </div>
        <div class="metrics-grid" id="metricsSummary">
          <div class="card-solid">
            <div class="metric-label">CPU</div>
            <div class="metric-value" id="cpuValue">—</div>
            <div class="metric-chip" id="cpuChip">No data</div>
          </div>
          <div class="card-solid">
            <div class="metric-label">RAM</div>
            <div class="metric-value" id="memValue">—</div>
            <div class="metric-chip" id="memChip">No data</div>
          </div>
          <div class="card-solid">
            <div class="metric-label">Disk</div>
            <div class="metric-value" id="diskValue">—</div>
            <div class="metric-chip" id="diskChip">No data</div>
          </div>
        </div>
        <div class="chart-wrapper">
          <canvas id="metricsChart" class="chart-canvas"></canvas>
        </div>
      </div>

      <div class="card-solid">
        <div class="card-header">
          <span class="section-title" style="margin:0;">Alert Summary</span>
          <span style="font-size:0.75rem;color:var(--text-muted);">Last 50 alerts</span>
        </div>
        <div id="alertSummary" style="display:flex;flex-direction:column;gap:0.4rem;font-size:0.8rem;">
          <div>No alerts loaded yet.</div>
        </div>
      </div>
    </section>

    <section class="bottom-grid">
      <div class="card-solid">
        <div class="alerts-header">
          <div class="section-title" style="margin:0;">Security Alerts</div>
          <div class="alerts-filters">
            <select id="severityFilter" class="select">
              <option value="">Severity: All</option>
              <option value="high">High only</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select id="categoryFilter" class="select">
              <option value="">Category: All</option>
              <option value="auth">Authentication</option>
              <option value="process">Process</option>
              <option value="network">Network</option>
              <option value="resource">Resource</option>
            </select>
          </div>
        </div>
        <div class="alerts-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time (Oman / UTC+4)</th>
                <th>Host</th>
                <th>OS</th>
                <th>Source</th>
                <th>Category</th>
                <th>Event</th>
                <th>User</th>
                <th>IP</th>
                <th>Process</th>
                <th>Severity</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody id="alertsBody"></tbody>
          </table>
        </div>
      </div>
    </section>
  </main>

  <script>
    let currentHost = "";
    let metricsChart = null;

    async function fetchJSON(url) {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      return resp.json();
    }

    function formatTime(ts) {
      const d = new Date(ts);
      const options = {
        timeZone: "Asia/Muscat",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
      };
      return new Intl.DateTimeFormat("en-GB", options)
        .format(d)
        .replace(",", "");
    }

    function isRecently(tsStr, minutes = 2) {
      try {
        const ts = new Date(tsStr).getTime();
        const now = Date.now();
        return (now - ts) <= minutes * 60 * 1000;
      } catch {
        return false;
      }
    }

    function severityClass(sev) {
      if (!sev) return "";
      const s = sev.toLowerCase();
      if (s === "high" || s === "critical") return "high";
      if (s === "medium") return "medium";
      if (s === "low") return "low";
      if (s === "info") return "info";
      return "";
    }

    async function loadHosts() {
      try {
        const hosts = await fetchJSON("/api/hosts");
        const ul = document.getElementById("hostList");
        ul.innerHTML = "";

        const makeItem = (hostObj) => {
          const li = document.createElement("li");
          li.className = "host-item";
          li.dataset.host = hostObj.host;
          if (currentHost === hostObj.host) li.classList.add("active");

          li.onclick = () => {
            currentHost = hostObj.host;
            document.getElementById("currentHostLabel").textContent = hostObj.host;
            document.querySelectorAll(".host-item").forEach(e => e.classList.remove("active"));
            li.classList.add("active");
            refreshData();
          };

          const topRow = document.createElement("div");
          topRow.style.display = "flex";
          topRow.style.alignItems = "center";
          topRow.style.gap = "0.35rem";

          const nameSpan = document.createElement("span");
          nameSpan.className = "host-name";
          nameSpan.textContent = hostObj.host;
          topRow.appendChild(nameSpan);

          const osSpan = document.createElement("span");
          osSpan.className = "badge-os";
          osSpan.textContent = hostObj.os.startsWith("Windows") ? "Windows" : "Linux";
          topRow.appendChild(osSpan);

          const statusSpan = document.createElement("span");
          statusSpan.className = "badge-status";
          const dot = document.createElement("span");
          dot.className = "status-dot";
          if (isRecently(hostObj.last_ts, 2)) {
            statusSpan.classList.add("online");
            dot.style.background = "#4ade80";
            statusSpan.textContent = "Online";
          } else {
            statusSpan.classList.add("offline");
            dot.style.background = "#f97373";
            statusSpan.textContent = "Offline";
          }
          statusSpan.prepend(dot);
          topRow.appendChild(statusSpan);

          const metaDiv = document.createElement("div");
          metaDiv.className = "host-meta";
          metaDiv.textContent = "Last seen: " + formatTime(hostObj.last_ts);

          li.appendChild(topRow);
          li.appendChild(metaDiv);
          return li;
        };

        const allItem = document.createElement("li");
        allItem.className = "host-item";
        allItem.onclick = () => {
          currentHost = "";
          document.getElementById("currentHostLabel").textContent = "All hosts";
          document.querySelectorAll(".host-item").forEach(e => e.classList.remove("active"));
          allItem.classList.add("active");
          refreshData();
        };
        if (!currentHost) allItem.classList.add("active");

        const topRowAll = document.createElement("div");
        topRowAll.style.display = "flex";
        topRowAll.style.alignItems = "center";
        topRowAll.style.gap = "0.35rem";
        const allName = document.createElement("span");
        allName.className = "host-name";
        allName.textContent = "All hosts";
        topRowAll.appendChild(allName);
        const metaAll = document.createElement("div");
        metaAll.className = "host-meta";
        metaAll.textContent = "Aggregate view";
        allItem.appendChild(topRowAll);
        allItem.appendChild(metaAll);
        ul.appendChild(allItem);

        hosts.forEach(h => ul.appendChild(makeItem(h)));
      } catch (err) {
        console.error("Error loading hosts:", err);
      }
    }

    async function loadMetrics() {
      const limit = 100;
      const url = currentHost
        ? `/api/metrics?host=${encodeURIComponent(currentHost)}&limit=${limit}`
        : `/api/metrics?limit=${limit}`;
      const data = await fetchJSON(url);
      updateMetricsUI(data);
    }

    async function loadAlerts() {
      const limit = 200;
      const severity = document.getElementById("severityFilter").value;
      const category = document.getElementById("categoryFilter").value;

      let url = `/api/alerts?limit=${limit}`;
      if (currentHost) url += `&host=${encodeURIComponent(currentHost)}`;
      if (severity) url += `&severity=${encodeURIComponent(severity)}`;
      if (category) url += `&category=${encodeURIComponent(category)}`;

      const data = await fetchJSON(url);
      updateAlertsUI(data);
      updateAlertSummary(data);
    }

    function updateMetricsUI(data) {
      if (!Array.isArray(data) || data.length === 0) {
        document.getElementById("cpuValue").textContent = "—";
        document.getElementById("memValue").textContent = "—";
        document.getElementById("diskValue").textContent = "—";
        document.getElementById("cpuChip").textContent = "No data";
        document.getElementById("memChip").textContent = "No data";
        document.getElementById("diskChip").textContent = "No data";
        if (metricsChart) metricsChart.destroy();
        metricsChart = null;
        return;
      }

      const sorted = [...data].reverse();
      const labels = sorted.map(r => r.ts);
      const cpuValues = sorted.map(r => r.cpu ?? null);
      const memValues = sorted.map(r => r.mem ?? null);

      const latest = sorted[sorted.length - 1];
      const cpu = latest.cpu ?? 0;
      const mem = latest.mem ?? 0;
      const disk = latest.disk ?? 0;

      document.getElementById("cpuValue").textContent = cpu.toFixed(1) + "%";
      document.getElementById("memValue").textContent = mem.toFixed(1) + "%";
      document.getElementById("diskValue").textContent = disk.toFixed(1) + "%";

      const cpuChip = document.getElementById("cpuChip");
      const memChip = document.getElementById("memChip");
      const diskChip = document.getElementById("diskChip");

      cpuChip.textContent = cpu < 50 ? "Healthy" : cpu < 80 ? "Elevated load" : "High load";
      memChip.textContent = mem < 60 ? "Healthy" : mem < 85 ? "Elevated usage" : "High usage";
      diskChip.textContent = disk < 70 ? "Plenty of space" : disk < 90 ? "Getting full" : "Critical";

      const ctx = document.getElementById("metricsChart").getContext("2d");
      if (metricsChart) metricsChart.destroy();

      metricsChart = new Chart(ctx, {
        type: "line",
        data: {
          labels: labels.map(t => new Date(t).toLocaleTimeString("en-GB", { timeZone: "Asia/Muscat" })),
          datasets: [
            {
              label: "CPU %",
              data: cpuValues,
              borderWidth: 2,
              tension: 0.3,
              pointRadius: 0,
            },
            {
              label: "RAM %",
              data: memValues,
              borderWidth: 2,
              borderDash: [4, 4],
              tension: 0.3,
              pointRadius: 0,
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              labels: { color: "#e5e7eb", font: { size: 11 } }
            }
          },
          scales: {
            x: {
              ticks: { color: "#9ca3af", maxTicksLimit: 8, font: { size: 10 } },
              grid: { display: false }
            },
            y: {
              ticks: { color: "#9ca3af", stepSize: 20, font: { size: 10 } },
              grid: { color: "rgba(55,65,81,0.4)" },
              min: 0,
              max: 100
            }
          }
        }
      });
    }

    function updateAlertsUI(data) {
      const tbody = document.getElementById("alertsBody");
      tbody.innerHTML = "";

      if (!Array.isArray(data) || data.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 11;
        td.className = "text-faded";
        td.textContent = "No alerts for this selection.";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      data.forEach(alert => {
        const tr = document.createElement("tr");

        const addCell = (text, className) => {
          const td = document.createElement("td");
          td.textContent = text ?? "";
          if (className) td.className = className;
          tr.appendChild(td);
        };

        addCell(formatTime(alert.ts), "text-faded");
        addCell(alert.host);
        addCell(alert.os.startsWith("Windows") ? "Windows" : "Linux", "text-faded");
        addCell(alert.source || "", "text-faded");

        const catTd = document.createElement("td");
        const catSpan = document.createElement("span");
        catSpan.className = "tag-pill";
        catSpan.textContent = alert.category || "—";
        catTd.appendChild(catSpan);
        tr.appendChild(catTd);

        const ev = alert.event_id ? `${alert.event_id} ${alert.event_name || ""}` : (alert.event_name || "—");
        addCell(ev.trim());

        addCell(alert.username || "", "text-faded");
        addCell(alert.ip || "", "text-faded");
        addCell(alert.process || "", "text-faded");

        const sevTd = document.createElement("td");
        const sevSpan = document.createElement("span");
        const sev = (alert.severity || "").toLowerCase();
        sevSpan.className = "severity-pill " + severityClass(sev);
        sevSpan.textContent = sev || "—";
        sevTd.appendChild(sevSpan);
        tr.appendChild(sevTd);

        addCell(alert.message || "");
        tbody.appendChild(tr);
      });
    }

    function updateAlertSummary(data) {
      const container = document.getElementById("alertSummary");
      container.innerHTML = "";

      if (!Array.isArray(data) || data.length === 0) {
        const div = document.createElement("div");
        div.textContent = "No alerts in the current view.";
        container.appendChild(div);
        return;
      }

      const total = data.length;
      const counts = { high: 0, medium: 0, low: 0, info: 0 };
      const categories = {};

      data.forEach(a => {
        const s = (a.severity || "").toLowerCase();
        if (counts[s] !== undefined) counts[s]++;

        const c = a.category || "other";
        categories[c] = (categories[c] || 0) + 1;
      });

      const row1 = document.createElement("div");
      row1.textContent = `Total alerts: ${total}`;
      container.appendChild(row1);

      const row2 = document.createElement("div");
      row2.innerHTML =
        `<span class="severity-pill high">High: ${counts.high}</span> ` +
        `<span class="severity-pill medium">Medium: ${counts.medium}</span> ` +
        `<span class="severity-pill low">Low: ${counts.low}</span> ` +
        `<span class="severity-pill info">Info: ${counts.info}</span>`;
      container.appendChild(row2);

      const row3 = document.createElement("div");
      row3.style.marginTop = "0.2rem";
      row3.className = "text-faded";
      row3.textContent = "By category: " + Object.entries(categories)
        .map(([k, v]) => `${k} (${v})`)
        .join(", ");
      container.appendChild(row3);
    }

    async function refreshData() {
      try {
        await Promise.all([loadMetrics(), loadAlerts()]);
        document.getElementById("lastRefresh").textContent =
          new Date().toLocaleTimeString("en-GB", { timeZone: "Asia/Muscat" });
      } catch (err) {
        console.error("Error refreshing data:", err);
      }
    }

    function setupFilters() {
      document.getElementById("severityFilter").addEventListener("change", loadAlerts);
      document.getElementById("categoryFilter").addEventListener("change", loadAlerts);
    }

    async function init() {
      setupFilters();
      await loadHosts();
      await refreshData();
      setInterval(refreshData, 10000);
      setInterval(loadHosts, 30000);
    }

    window.addEventListener("DOMContentLoaded", init);
  </script>
</body>
</html>
"""

# =========================
#        MAIN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
