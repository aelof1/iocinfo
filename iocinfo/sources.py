"""API clients for VirusTotal and AbuseIPDB (free accounts are enough)."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

HttpFunc = Callable[[str, dict], tuple[int, dict]]


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env reader: KEY=value lines. Existing environment variables win."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def default_http(url: str, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "iocinfo", **headers})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        try:
            body = json.loads(err.read().decode())
        except Exception:
            body = {}
        return err.code, body


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"
    PATHS = {"ip": "ip_addresses", "domain": "domains", "url": "urls",
             "md5": "files", "sha1": "files", "sha256": "files"}

    def __init__(self, api_key: str, http: HttpFunc = default_http):
        self.key = api_key
        self.http = http

    def lookup(self, ioc_type: str, value: str) -> dict:
        if ioc_type not in self.PATHS:
            return {"error": "type not supported"}
        ident = value
        if ioc_type == "url":  # VT identifies URLs by their base64url form without padding
            ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        status, body = self.http(f"{self.BASE}/{self.PATHS[ioc_type]}/{urllib.parse.quote(ident, safe='')}",
                                 {"x-apikey": self.key})
        if status == 404:
            return {"found": False}
        if status == 429:
            return {"error": "rate limit reached (free API: 4 requests/minute)"}
        if status == 401:
            return {"error": "invalid VirusTotal API key"}
        if status != 200:
            return {"error": f"HTTP {status}"}
        attr = body.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "engines": sum(stats.values()) if stats else 0,
            "reputation": attr.get("reputation"),
            "country": attr.get("country"),
            "owner": attr.get("as_owner") or attr.get("registrar"),
            "name": attr.get("meaningful_name"),
            "file_type": attr.get("type_description"),
            "tags": attr.get("tags", [])[:8],
            "link": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(value, safe='')}",
        }


class AbuseIPDB:
    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, http: HttpFunc = default_http):
        self.key = api_key
        self.http = http

    def lookup(self, ip: str, max_age_days: int = 90) -> dict:
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
        status, body = self.http(f"{self.BASE}?{query}", {"Key": self.key, "Accept": "application/json"})
        if status == 401:
            return {"error": "invalid AbuseIPDB API key"}
        if status == 429:
            return {"error": "daily rate limit reached"}
        if status != 200:
            return {"error": f"HTTP {status}"}
        d = body.get("data", {})
        return {
            "confidence": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "usage": d.get("usageType"),
            "tor": d.get("isTor", False),
            "last_reported": d.get("lastReportedAt"),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        }


def verdict(vt: dict | None, abuse: dict | None) -> str:
    malicious = (vt or {}).get("malicious", 0)
    suspicious = (vt or {}).get("suspicious", 0)
    confidence = (abuse or {}).get("confidence", 0)
    if malicious >= 5 or confidence >= 75:
        return "MALICIOUS"
    if malicious >= 1 or suspicious >= 2 or confidence >= 25:
        return "SUSPICIOUS"
    if (vt or {}).get("found") is False and abuse is None:
        return "UNKNOWN"
    if vt is None and abuse is None:
        return "NOT CHECKED"
    return "CLEAN"
