"""All API calls are faked: tests run without keys or Internet."""

import base64

from iocinfo.cli import enrich
from iocinfo.ioc import defang, detect, refang
from iocinfo.sources import AbuseIPDB, VirusTotal, load_dotenv, verdict


def test_detect_types():
    assert detect("8.8.8.8") == ("ip", "8.8.8.8")
    assert detect("2001:4860:4860::8888")[0] == "ip"
    assert detect("Example.COM") == ("domain", "example.com")
    assert detect("hxxps://evil[.]com/a") == ("url", "https://evil.com/a")
    assert detect("44d88612fea8a8f36de82e1278abb02f")[0] == "md5"
    assert detect("a" * 40)[0] == "sha1"
    assert detect("A" * 64) == ("sha256", "a" * 64)
    assert detect("not an ioc!")[0] == "unknown"


def test_fang_roundtrip():
    assert refang(defang("http://evil.com")) == "http://evil.com"


def test_private_ip_not_looked_up():
    r = enrich("10.0.0.5", vt=None, abuse=None)
    assert r["verdict"] == "PRIVATE"


def test_virustotal_parsing_and_url_id():
    calls = []

    def fake(url, headers):
        calls.append(url)
        assert headers["x-apikey"] == "KEY"
        return 200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 10},
            "reputation": -40, "tags": ["phishing"]}}}

    vt = VirusTotal("KEY", http=fake)
    res = vt.lookup("url", "http://evil.com/")
    expected_id = base64.urlsafe_b64encode(b"http://evil.com/").decode().rstrip("=")
    assert calls[0].endswith("/urls/" + expected_id)
    assert res["malicious"] == 12 and res["engines"] == 73
    assert verdict(res, None) == "MALICIOUS"


def test_virustotal_errors():
    assert VirusTotal("k", http=lambda u, h: (404, {})).lookup("domain", "x.com") == {"found": False}
    assert "rate limit" in VirusTotal("k", http=lambda u, h: (429, {})).lookup("domain", "x.com")["error"]


def test_abuseipdb_and_full_enrich():
    abuse = AbuseIPDB("K", http=lambda u, h: (200, {"data": {
        "abuseConfidenceScore": 100, "totalReports": 900, "countryCode": "NL",
        "isp": "Bad Hosting", "usageType": "Data Center", "isTor": True}}))
    r = enrich("203.0.113.7", vt=None, abuse=abuse)
    # 203.0.113.0/24 is a documentation range, so it is not "global"
    assert r["verdict"] == "PRIVATE"
    r = enrich("185.220.101.4", vt=None, abuse=abuse)
    assert r["abuseipdb"]["tor"] and r["verdict"] == "MALICIOUS"


def test_verdicts():
    assert verdict({"found": True, "malicious": 0, "suspicious": 0}, {"confidence": 0}) == "CLEAN"
    assert verdict({"found": True, "malicious": 2, "suspicious": 0}, None) == "SUSPICIOUS"
    assert verdict(None, None) == "NOT CHECKED"


def test_load_dotenv(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    f = tmp_path / ".env"
    f.write_text("# comment\nVT_API_KEY='abc123'\n")
    load_dotenv(str(f))
    import os
    assert os.environ["VT_API_KEY"] == "abc123"
