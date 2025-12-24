

import os, re, json, time, socket, platform, subprocess
from datetime import datetime, timezone, timedelta

import psutil
import requests

CENTRAL_URL  = "http://10.10.1.10:8000/ingest"
API_KEY      = "CHANGE_ME_SUPER_SECRET"
INTERVAL_SEC = 8

OMAN_TZ = timezone(timedelta(hours=4))
LAST_CHECKED_UTC = datetime.now(timezone.utc) - timedelta(seconds=10)

SEEN_OPENSSH_RECORDS = set()

IP_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
USER_IP_RE = re.compile(r"for\s+(\S+)\s+from\s+((\d{1,3}\.){3}\d{1,3})", re.IGNORECASE)


def get_ip():
    try:
        addrs = psutil.net_if_addrs()
        for _, lst in addrs.items():
            for a in lst:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    return a.address
    except Exception:
        pass
    return "unknown"


def collect_metrics():
    hostname = socket.gethostname()
    ip = get_ip()
    oman_now = datetime.now(timezone.utc).astimezone(OMAN_TZ)

    meta = {
        "hostname": hostname,
        "ip": ip,
        "os": platform.platform(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "timestamp": oman_now.isoformat(),
    }

    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("C:\\")

    resources = {
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "disk_percent": disk.percent,
    }

    net_io = psutil.net_io_counters()
    network = {
        "total": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
        }
    }
    return meta, resources, network


def run_ps_text(script: str) -> str:
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12
        )
        return (proc.stdout or "").strip()
    except Exception:
        return ""


def run_ps_json(script: str):
    out = run_ps_text(script)
    if not out:
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except Exception:
        return []
    return []


def openssh_channel_exists() -> bool:
    out = run_ps_text(r'wevtutil el | findstr /i openssh')
    return "OpenSSH/Operational" in out


def parse_openssh_message(msg: str):
    lower = msg.lower()
    etype = None
    if "failed password" in lower or "invalid user" in lower:
        etype = "failed_login"
    elif "accepted password" in lower or "accepted publickey" in lower:
        etype = "successful_login"
    elif "disconnected from" in lower or "connection closed" in lower or "session closed" in lower:
        etype = "logout"
    else:
        return None

    username = None
    src_ip = None

    m = USER_IP_RE.search(msg)
    if m:
        username = m.group(1)
        src_ip = m.group(2)
    else:
        ipm = IP_RE.search(msg)
        if ipm:
            src_ip = ipm.group(0)

    return etype, username, src_ip


def collect_from_openssh_operational(since_utc: datetime):
    since_iso = since_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    ps = rf"""
$since = Get-Date "{since_iso}"
Get-WinEvent -FilterHashtable @{{LogName='OpenSSH/Operational'; StartTime=$since}} |
  Select-Object RecordId, TimeCreated, Id, Message |
  ConvertTo-Json -Compress
"""
    rows = run_ps_json(ps)
    events = []

    for r in rows:
        rid = r.get("RecordId")
        if rid is None or rid in SEEN_OPENSSH_RECORDS:
            continue
        SEEN_OPENSSH_RECORDS.add(rid)

        msg = (r.get("Message") or "").strip()
        if not msg:
            continue

        parsed = parse_openssh_message(msg)
        if not parsed:
            continue

        etype, username, src_ip = parsed
       
        if not src_ip or src_ip in ("127.0.0.1", "::1"):
            continue

        try:
            tc = r.get("TimeCreated")
            dt = datetime.fromisoformat(str(tc)[:19]).replace(tzinfo=timezone.utc)
            ts_oman = dt.astimezone(OMAN_TZ).isoformat()
        except Exception:
            ts_oman = datetime.now(timezone.utc).astimezone(OMAN_TZ).isoformat()

        events.append({
            "type": etype,
            "src_ip": src_ip,
            "username": username,
            "timestamp": ts_oman,
            "raw": msg, 
        })

    return events


LOG_PATHS = [
    r"C:\ProgramData\ssh\logs\sshd.log",
    r"C:\ProgramData\ssh\sshd.log",
]

STATE_FILE = os.path.join(os.path.dirname(__file__), "win11_sshd_offset.state")


def read_file_new_lines(path: str):
    if not os.path.exists(path):
        return []

    try:
        offset = 0
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                offset = int((f.read() or "0").strip() or "0")

        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read()
            new_offset = f.tell()

        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(str(new_offset))

        text = chunk.decode("utf-8", errors="ignore")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return lines
    except Exception:
        return []


def collect_from_sshd_logfile():
    for p in LOG_PATHS:
        if os.path.exists(p):
            lines = read_file_new_lines(p)
            events = []
            now_oman = datetime.now(timezone.utc).astimezone(OMAN_TZ).isoformat()

            for ln in lines:
                parsed = parse_openssh_message(ln)
                if not parsed:
                    continue
                etype, username, src_ip = parsed
                if not src_ip or src_ip in ("127.0.0.1", "::1"):
                    continue
                events.append({
                    "type": etype,
                    "src_ip": src_ip,
                    "username": username,
                    "timestamp": now_oman,
                    "raw": ln,
                })
            return events
    return []


def main():
    global LAST_CHECKED_UTC

    print("Windows agent started (OpenSSH auth mode)")
    print(f"Sending to: {CENTRAL_URL}")

    session = requests.Session()
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    while True:
        poll_start = datetime.now(timezone.utc)
        try:
            meta, resources, network = collect_metrics()

            auth_events = []
            if openssh_channel_exists():
                auth_events = collect_from_openssh_operational(LAST_CHECKED_UTC)
            else:
                auth_events = collect_from_sshd_logfile()

            payload = {
                "meta": meta,
                "resources": resources,
                "network": network,
                "auth_events": auth_events,
                "os": "windows",
            }

            resp = session.post(CENTRAL_URL, headers=headers, data=json.dumps(payload), timeout=8)
            if resp.status_code == 200:
                print(f"[{meta['timestamp']}] sent ok | auth_events={len(auth_events)}")
            else:
                print(f"[ERROR] {resp.status_code}: {resp.text}")

            LAST_CHECKED_UTC = poll_start

        except Exception as e:
            print("[ERROR]", e)

        time.sleep(INTERVAL_SEC)


if __name__ == "__main__":
    main()
