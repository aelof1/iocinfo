"""Recognise what kind of indicator (IOC) a string is."""

from __future__ import annotations

import ipaddress
import re

HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def refang(value: str) -> str:
    """Analysts 'defang' IOCs so nobody clicks them: hxxp://evil[.]com -> http://evil.com"""
    v = value.strip().strip("'\"")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    return v


def defang(value: str) -> str:
    return value.replace("http", "hxxp", 1).replace(".", "[.]")


def detect(value: str) -> tuple[str, str]:
    """Return (type, normalised_value). Type is ip, domain, url, md5, sha1, sha256 or unknown."""
    v = refang(value)
    if re.match(r"^https?://", v, re.I):
        return "url", v
    try:
        ip = ipaddress.ip_address(v)
        return "ip", str(ip)
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]+", v) and len(v) in HASH_TYPES:
        return HASH_TYPES[len(v)], v.lower()
    if DOMAIN_RE.match(v):
        return "domain", v.lower().rstrip(".")
    return "unknown", v


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global
