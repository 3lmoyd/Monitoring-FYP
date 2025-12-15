import requests, json

# You pasted your keys here, so just set them directly:
ABUSE_KEY = "566933eef1a4edf8315ce60e293c377f73421159c1eabf6c7994d467043681217250cdc287843fcb"
VT_KEY = "d1c8112e3c70cdf412a041b8d3ee18f2b62cc272e620ff1c77a8c4de86a7b772"

def check_ip(ip):
    result = {"ip": ip, "abuse_score": None, "vt_malicious": None}

    # ---- Check AbuseIPDB ----
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Accept": "application/json", "Key": ABUSE_KEY},
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()["data"]
            result["abuse_score"] = data["abuseConfidenceScore"]
    except Exception as e:
        print("AbuseIPDB error:", e)

    # ---- Check VirusTotal ----
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            result["vt_malicious"] = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except Exception as e:
        print("VirusTotal error:", e)

    return result
