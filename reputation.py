"""Check 1: is this URL (or a file it tries to download) already known to be malicious?"""
import base64
import os
import time

import requests

VT = "https://www.virustotal.com/api/v3"


def check_virustotal(url: str, wait_for_new: bool = True) -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"service": "VirusTotal", "available": False, "note": "no API key"}
    h = {"x-apikey": key}
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"{VT}/urls/{uid}", headers=h, timeout=15)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        elif r.status_code == 404:
            # Never seen before: submit it and wait briefly (free tier = 4 req/min)
            s = requests.post(f"{VT}/urls", headers=h, data={"url": url}, timeout=15)
            s.raise_for_status()
            if not wait_for_new:
                return {"service": "VirusTotal", "available": True, "malicious": 0, "suspicious": 0,
                        "note": "new URL submitted, no verdict yet"}
            aid = s.json()["data"]["id"]
            stats = None
            for _ in range(3):
                time.sleep(10)
                a = requests.get(f"{VT}/analyses/{aid}", headers=h, timeout=15).json()
                if a["data"]["attributes"]["status"] == "completed":
                    stats = a["data"]["attributes"]["stats"]
                    break
            if stats is None:
                return {"service": "VirusTotal", "available": True, "malicious": 0, "suspicious": 0,
                        "note": "analysis still running"}
        else:
            return {"service": "VirusTotal", "available": False, "note": f"HTTP {r.status_code}"}
        return {
            "service": "VirusTotal", "available": True,
            "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
        }
    except Exception as e:
        return {"service": "VirusTotal", "available": False, "note": f"error: {e}"[:200]}


def check_safe_browsing(url: str) -> dict:
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key:
        return {"service": "Google Safe Browsing", "available": False, "note": "no API key"}
    body = {
        "client": {"clientId": "phish-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=15)
        if r.status_code != 200:
            return {"service": "Google Safe Browsing", "available": False, "note": f"HTTP {r.status_code}"}
        matches = r.json().get("matches", [])
        return {"service": "Google Safe Browsing", "available": True, "flagged": bool(matches),
                "threats": sorted({m.get("threatType") for m in matches})}
    except Exception as e:
        return {"service": "Google Safe Browsing", "available": False, "note": f"error: {e}"[:200]}


def reputation_check(url: str) -> dict:
    return {"virustotal": check_virustotal(url), "safe_browsing": check_safe_browsing(url)}


def reputation_points(rep: dict) -> tuple[int, list]:
    """Turn reputation results into risk points + human-readable reasons."""
    pts, why = 0, []
    sb = rep.get("safe_browsing", {})
    if sb.get("flagged"):
        pts += 50
        why.append("Google Safe Browsing flags it: " + ", ".join(sb.get("threats", [])))
    vt = rep.get("virustotal", {})
    mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
    if mal >= 3:
        pts += 50
        why.append(f"VirusTotal: {mal} security vendors say malicious")
    elif mal >= 1:
        pts += 30
        why.append(f"VirusTotal: {mal} vendor(s) say malicious")
    elif sus >= 1:
        pts += 10
        why.append(f"VirusTotal: {sus} vendor(s) say suspicious")
    for d in rep.get("downloads", []):
        dv = d.get("virustotal", {})
        if dv.get("malicious", 0) >= 1:
            pts += 40
            why.append(f"Download '{d.get('filename')}' is flagged malicious by {dv['malicious']} VirusTotal vendor(s)")
    return pts, why
