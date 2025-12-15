from pathlib import Path
from datetime import datetime
import json, sqlite3, time
from flask import Flask, request, jsonify, send_from_directory, Response

# ---------------- Config ----------------
BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"       # Vite build goes here
DB_PATH = BASE_DIR / "telemetry.db"
API_KEY = "CHANGE_ME_SUPER_SECRET"     # set a strong key

app = Flask(__name__, static_folder=None)

# ---------------- DB helpers ----------------
def db():
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        os TEXT NOT NULL,
        cpu REAL,
        mem REAL,
        disk REAL,
        net_up REAL,
        net_down REAL,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT,
        level TEXT,
        message TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    con.commit()
    con.close()

init_db()

# ---------------- Ingest endpoint (agents will use later) ----------------
@app.post("/ingest")
def ingest():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    host    = payload.get("host", "unknown")
    osname  = payload.get("os", "unknown")
    cpu     = float(payload.get("cpu", 0))
    mem     = float(payload.get("mem", 0))
    disk    = float(payload.get("disk", 0))
    net_up  = float(payload.get("net_up", 0))
    net_down= float(payload.get("net_down", 0))
    evt_msg = payload.get("event_msg")
    evt_lvl = payload.get("event_level", "info")

    con = db()
    cur = con.cursor()
    cur.execute("INSERT INTO metrics(host,os,cpu,mem,disk,net_up,net_down) VALUES(?,?,?,?,?,?,?)",
                (host, osname, cpu, mem, disk, net_up, net_down))
    if evt_msg:
        cur.execute("INSERT INTO events(host,level,message) VALUES(?,?,?)",
                    (host, evt_lvl, evt_msg))
    con.commit()
    con.close()
    return jsonify({"status":"ok"})

# ---------------- API for dashboard ----------------
def since_minutes(con, mins=10):
    cur = con.cursor()
    cur.execute("SELECT DATETIME('now','-%d minutes')" % mins)
    return cur.fetchone()[0]

@app.get("/api/kpis")
def api_kpis():
    con = db(); cur = con.cursor()
    t0 = since_minutes(con, 10)
    cur.execute("SELECT AVG(cpu), AVG(mem), AVG(disk) FROM metrics WHERE ts >= ?", (t0,))
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

@app.get("/api/cpu_series")
def api_cpu_series():
    con = db(); cur = con.cursor()
    t0 = since_minutes(con, 10)
    cur.execute("""
      SELECT STRFTIME('%H:%M:%S', ts) AS t, AVG(cpu) AS v
      FROM metrics WHERE ts >= ?
      GROUP BY STRFTIME('%Y-%m-%d %H:%M', ts), STRFTIME('%S', ts)
      ORDER BY ts ASC
    """, (t0,))
    data = [{"time": r["t"], "value": round(r["v"] or 0,1)} for r in cur.fetchall()]
    con.close()
    return jsonify(data[-30:])

@app.get("/api/network_series")
def api_network_series():
    con = db(); cur = con.cursor()
    t0 = since_minutes(con, 10)
    cur.execute("""
      SELECT STRFTIME('%H:%M:%S', ts) AS t, AVG(net_down) AS down, AVG(net_up) AS up
      FROM metrics WHERE ts >= ?
      GROUP BY STRFTIME('%Y-%m-%d %H:%M', ts), STRFTIME('%S', ts)
      ORDER BY ts ASC
    """, (t0,))
    data = [{"time": r["t"], "down": round(r["down"] or 0,1), "up": round(r["up"] or 0,1)} for r in cur.fetchall()]
    con.close()
    return jsonify(data[-30:])

@app.get("/api/alerts")
def api_alerts():
    con = db(); cur = con.cursor()
    cur.execute("SELECT id, host, level, message, ts FROM events ORDER BY id DESC LIMIT 20")
    rows = cur.fetchall(); con.close()
    return jsonify([{
        "id": r["id"], "level": r["level"], "message": r["message"], "time": r["ts"], "source": r["host"]
    } for r in rows])

@app.get("/api/events")
def api_events():
    con = db(); cur = con.cursor()
    cur.execute("SELECT id, host, level, message, ts FROM events ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall(); con.close()
    return jsonify([{"id": r["id"], "msg": f"{r['host']} | {r['level']} | {r['message']} @ {r['ts']}"} for r in rows])

# ---------------- SSE stream (optional for realtime event list) ----------------
@app.get("/stream")
def stream():
    def event_stream():
        last_id = 0
        while True:
            con = db(); cur = con.cursor()
            cur.execute("SELECT id, host, level, message, ts FROM events WHERE id > ? ORDER BY id ASC", (last_id,))
            rows = cur.fetchall(); con.close()
            for r in rows:
                evt = {"id": r["id"], "msg": f"{r['host']} | {r['level']} | {r['message']} @ {r['ts']}"}
                yield f"data: {json.dumps(evt)}\n\n"
                last_id = r["id"]
            time.sleep(2)
    return Response(event_stream(), mimetype="text/event-stream")

# ---------------- Static file serving (React build) ----------------
@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")

@app.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(STATIC_DIR / "assets", filename)

# SPA fallback (so client-side routes don't 404). Keep API/ingest/stream excluded.
@app.get("/<path:path>")
def spa_fallback(path):
    if path.startswith(("api", "ingest", "stream", "assets")):
        return ("Not found", 404)
    return send_from_directory(STATIC_DIR, "index.html")

# No __main__ here; waitress will run this app from run_all.py
