

import psutil
import socket
import platform
import time
import json
from datetime import datetime
import subprocess
import requests
import re


CENTRAL_URL  = "http://10.10.1.10:8000/ingest"
API_KEY      = "CHANGE_ME_SUPER_SECRET"
INTERVAL_SEC = 5

DEBUG_EVENTS  = False
DEBUG_JOURNAL = False


IP_RE = re.compile(r'(\d{1,3}\.){3}\d{1,3}')

LAST_AUTH_USERNAME = None
LAST_AUTH_IP = None


def get_ip():
    try:
        addrs = psutil.net_if_addrs()
        for iface, lst in addrs.items():
            for a in lst:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    return a.address
    except Exception:
        pass
    return "unknown"


def collect_metrics():
    hostname = socket.gethostname()
    ip = get_ip()
    os_full = platform.platform()
    kernel = platform.release()
    arch = platform.machine()
    meta_ts = datetime.now().isoformat()

    cpu_percent = psutil.cpu_percent(interval=1)
    vmem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    meta = {
        "hostname": hostname,
        "ip": ip,
        "os": os_full,
        "kernel": kernel,
        "arch": arch,
        "timestamp": meta_ts,
    }

    resources = {
        "cpu_percent": cpu_percent,
        "ram_percent": vmem.percent,
        "ram_used_mb": round(vmem.used / (1024 * 1024), 2),
        "ram_total_mb": round(vmem.total / (1024 * 1024), 2),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / (1024 * 1024 * 1024), 2),
        "disk_total_gb": round(disk.total / (1024 * 1024 * 1024), 2),
    }

    net_io = psutil.net_io_counters()
    network = {
        "total": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
        }
    }

    return meta, resources, network


def extract_ip(line: str):
    m = IP_RE.search(line)
    return m.group(0) if m else None


def extract_username(line: str):
    patterns = [
        r"Failed password for invalid user (\S+)",
        r"Failed password for (\S+)\s+from",
        r"Accepted password for (\S+)\s+from",
        r"session opened for user (\S+)",
        r"session closed for user (\S+)",
        r"for user (\S+)",
    ]
    for pat in patterns:
        m = re.search(pat, line)
        if m:
            return m.group(1)
    return None


def parse_journalctl_events(since_time_str):
    global LAST_AUTH_USERNAME, LAST_AUTH_IP

    events = []
    seen_raw = set()

    # Collect ssh/sshd lines
    ssh_lines = []
    for unit in ["ssh", "sshd"]:
        try:
            cmd = ["journalctl", "-u", unit, "--since", since_time_str, "--no-pager"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            ssh_lines += [ln for ln in out.strip().splitlines() if ln.strip()]
        except Exception:
            continue

    # Collect logind lines
    try:
        cmd_logind = ["journalctl", "-t", "systemd-logind", "--since", since_time_str, "--no-pager"]
        out_logind = subprocess.check_output(cmd_logind, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
        logind_lines = [ln for ln in out_logind.strip().splitlines() if ln.strip()]
    except Exception:
        logind_lines = []

    if DEBUG_JOURNAL:
        print(f"[DEBUG] journalctl since={since_time_str}: {len(ssh_lines)} ssh lines, {len(logind_lines)} logind lines")

    saw_sshd_logout = False

    # ---- sshd events ----
    for line in ssh_lines:
        if line in seen_raw:
            continue
        seen_raw.add(line)

        lower = line.lower()
        ev_type = None

        if "failed password" in lower or "invalid user" in lower:
            ev_type = "failed_login"
        elif "accepted password" in lower or "accepted publickey" in lower:
            ev_type = "successful_login"
        elif ("session closed for user" in lower or
              "disconnected from" in lower or
              "received disconnect" in lower or
              "session closed" in lower):
            ev_type = "logout"

        if not ev_type:
            continue

        username = extract_username(line)
        src_ip = extract_ip(line)

        if ev_type in ("successful_login", "failed_login"):
            if username:
                LAST_AUTH_USERNAME = username
            if src_ip:
                LAST_AUTH_IP = src_ip

        if ev_type == "logout":
            saw_sshd_logout = True
            if not username and LAST_AUTH_USERNAME:
                username = LAST_AUTH_USERNAME
            if not src_ip and LAST_AUTH_IP:
                src_ip = LAST_AUTH_IP

        events.append({
            "type": ev_type,
            "username": username,
            "src_ip": src_ip,
            "raw": line
        })

        if DEBUG_EVENTS:
            print(f"[DEBUG] ssh event: {ev_type} user={username} ip={src_ip}")

    # ---- logind logout (only if sshd did NOT already emit logout) ----
    # Also dedup per session-id because logind often prints:
    #   "Session 329 logged out..." and "Removed session 329."
    if not saw_sshd_logout:
        seen_sessions = set()

        for line in logind_lines:
            if line in seen_raw:
                continue
            seen_raw.add(line)

            lower = line.lower()
            if "session" in lower and ("logged out" in lower or "removed" in lower or "closed" in lower):
                m = re.search(r"\bsession\s+(\d+)\b", lower)
                sess_id = m.group(1) if m else None

                if sess_id and sess_id in seen_sessions:
                    continue
                if sess_id:
                    seen_sessions.add(sess_id)

                events.append({
                    "type": "logout",
                    "username": LAST_AUTH_USERNAME,
                    "src_ip": LAST_AUTH_IP,
                    "raw": line
                })

                if DEBUG_EVENTS:
                    print(f"[DEBUG] logind logout: session={sess_id} user={LAST_AUTH_USERNAME} ip={LAST_AUTH_IP}")

    return events


def main():
    print("Linux Monitoring Agent (metrics + SSH events via journalctl) started...\n")
    print(f"Sending to: {CENTRAL_URL}")
    print(f"API key: {API_KEY}\n")

    session = requests.Session()
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    last_checked_time = datetime.now()

    while True:
        try:
            meta, resources, network = collect_metrics()
            since_str = last_checked_time.strftime('%Y-%m-%d %H:%M:%S')

            auth_events = parse_journalctl_events(since_str)

            payload = {
                "meta": meta,
                "resources": resources,
                "network": network,
                "auth_events": auth_events,
            }

            resp = session.post(CENTRAL_URL, headers=headers, data=json.dumps(payload), timeout=6)

            if resp.status_code == 200:
                print(f"[{meta['timestamp']}] sent ok | auth_events={len(auth_events)}")
            else:
                print(f"[ERROR] server returned {resp.status_code}: {resp.text}")

            last_checked_time = datetime.now()

        except Exception as e:
            print(f"[ERROR] Failed to send data: {e}")

        time.sleep(INTERVAL_SEC)


if __name__ == "__main__":
    main()
