"""iocinfo command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__
from .ioc import defang, detect, is_public_ip
from .sources import AbuseIPDB, VirusTotal, load_dotenv, verdict

VERDICT_COLOR = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "CLEAN": "\033[92m"}


def enrich(value: str, vt: VirusTotal | None, abuse: AbuseIPDB | None) -> dict:
    kind, norm = detect(value)
    result = {"input": value, "type": kind, "value": norm}
    if kind == "unknown":
        result["verdict"] = "INVALID"
        return result
    if kind == "ip" and not is_public_ip(norm):
        result["verdict"] = "PRIVATE"
        result["note"] = "private/reserved address - nothing to look up"
        return result
    vt_res = vt.lookup(kind, norm) if vt else None
    abuse_res = abuse.lookup(norm) if (abuse and kind == "ip") else None
    if vt_res is not None:
        result["virustotal"] = vt_res
    if abuse_res is not None:
        result["abuseipdb"] = abuse_res
    result["verdict"] = verdict(vt_res if vt_res and "error" not in vt_res else None,
                                abuse_res if abuse_res and "error" not in abuse_res else None)
    return result


def print_result(r: dict, color: bool) -> None:
    c, reset = (VERDICT_COLOR.get(r["verdict"], ""), "\033[0m") if color else ("", "")
    print(f"\n{defang(r['value'])}  [{r['type']}]  ->  {c}{r['verdict']}{reset}")
    if "note" in r:
        print(f"   {r['note']}")
    vt = r.get("virustotal")
    if vt:
        if "error" in vt:
            print(f"   VirusTotal : error - {vt['error']}")
        elif not vt["found"]:
            print("   VirusTotal : never seen")
        else:
            print(f"   VirusTotal : {vt['malicious']}/{vt['engines']} engines say malicious, "
                  f"{vt['suspicious']} suspicious (reputation {vt['reputation']})")
            extra = [f"{k}: {vt[k]}" for k in ("country", "owner", "name", "file_type") if vt.get(k)]
            if extra:
                print("                " + " | ".join(extra))
            if vt["tags"]:
                print("                tags: " + ", ".join(vt["tags"]))
    ab = r.get("abuseipdb")
    if ab:
        if "error" in ab:
            print(f"   AbuseIPDB  : error - {ab['error']}")
        else:
            tor = " | TOR exit node" if ab["tor"] else ""
            print(f"   AbuseIPDB  : confidence {ab['confidence']}%, {ab['reports']} reports, "
                  f"{ab['country']} | {ab['isp']} | {ab['usage']}{tor}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="iocinfo",
                                description="Check the reputation of IPs, domains, URLs and file hashes.")
    p.add_argument("iocs", nargs="*", help="IP, domain, URL or hash (defanged values like evil[.]com are OK)")
    p.add_argument("-f", "--file", help="read IOCs from a file (one per line)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--delay", type=float, default=15.0,
                   help="seconds between VirusTotal requests (free API = 4/min, default 15)")
    p.add_argument("--env", default=".env", help="path of the .env file with API keys")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    load_dotenv(args.env)
    vt_key, abuse_key = os.environ.get("VT_API_KEY"), os.environ.get("ABUSEIPDB_API_KEY")
    if not vt_key and not abuse_key:
        print("error: no API key found. Copy .env.example to .env and add your keys.", file=sys.stderr)
        return 2
    vt = VirusTotal(vt_key) if vt_key else None
    abuse = AbuseIPDB(abuse_key) if abuse_key else None

    values = list(args.iocs)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            values += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not values:
        p.error("give at least one IOC or use --file")

    results = []
    for i, v in enumerate(values):
        if i and vt:
            time.sleep(args.delay)
        r = enrich(v, vt, abuse)
        results.append(r)
        if not args.json:
            print_result(r, color=not args.no_color and sys.stdout.isatty())
    if args.json:
        print(json.dumps(results, indent=2))
    return 1 if any(r["verdict"] in ("MALICIOUS", "SUSPICIOUS") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
