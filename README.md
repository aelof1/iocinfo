# iocinfo

**IOC** (*Indicators of Compromise*) enrichment tool. Give it an IP address, a domain, a URL or a file hash, and it queries **VirusTotal** and **AbuseIPDB** to tell you whether it's known to be malicious.

## Why I built this

In a SOC, when an alert fires, the first question is almost always: "this IP / this file, do we know it?". Opening three websites and copy-pasting every time is slow. This tool runs the lookups in one go, accepts a whole list and gives a clear verdict. It's also a good exercise in using REST APIs and handling API keys properly.

## What it does

| IOC type | Example | Sources queried |
|---|---|---|
| IP address (v4 / v6) | `185.220.101.4` | VirusTotal + AbuseIPDB |
| Domain | `example.com` | VirusTotal |
| URL | `https://example.com/login` | VirusTotal |
| File hash | MD5, SHA-1, SHA-256 | VirusTotal |

- The type is **detected automatically**.
- **Defanged** IOCs are accepted: `hxxp://evil[.]com` is understood as `http://evil.com`. That's the usual way to share dangerous links without anyone clicking them by mistake, and the tool shows its results defanged too.
- Private IPs (`192.168.x.x`, `10.x.x.x`…) are never sent to the APIs.

Verdict:

| Verdict | Rule |
|---|---|
| MALICIOUS | 5 or more antivirus engines on VirusTotal, or AbuseIPDB score ≥ 75% |
| SUSPICIOUS | at least 1 detection, or AbuseIPDB score ≥ 25% |
| CLEAN | known, with no detections |
| UNKNOWN | never seen by VirusTotal |

## Compatibility

| System | Works? |
|---|---|
| Linux (all distributions) | Yes |
| macOS | Yes |
| Windows 10 / 11 | Yes |

## Requirements

- **Python 3.9 or newer**
- An Internet connection
- **At least one free API key**:
  - VirusTotal: create an account on [virustotal.com](https://www.virustotal.com), then go to your profile → *API Key*
  - AbuseIPDB: create an account on [abuseipdb.com](https://www.abuseipdb.com), then go to *Account* → *API*
- No external Python libraries

| Free account limits | |
|---|---|
| VirusTotal | 4 requests per minute, 500 per day |
| AbuseIPDB | 1000 checks per day |

The tool waits 15 seconds between two VirusTotal requests to stay under the limit (configurable with `--delay`).

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git
git clone https://github.com/aelof1/iocinfo.git
cd iocinfo
pipx install .
```

### Fedora

```bash
sudo dnf install -y python3 pipx git
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

## Setting up the API keys

```bash
cp .env.example .env
nano .env          # paste your keys
```

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

> The `.env` file is in `.gitignore`: it will **never** be pushed to GitHub. Never put your keys directly in the code.

You can also use environment variables (`export VT_API_KEY=...`). By default `.env` is read from the current folder; otherwise give its path with `--env`.

## Usage

```bash
iocinfo 185.220.101.4
iocinfo example.com "hxxp://evil[.]com/login" 44d88612fea8a8f36de82e1278abb02f
iocinfo -f samples/iocs.txt            # list in a file
iocinfo 8.8.8.8 --json                 # JSON (for a ticket or a SOAR)
```

Exit code: `1` if at least one IOC is malicious or suspicious, `0` otherwise.

### Example output

```
185[.]220[.]101[.]4  [ip]  ->  MALICIOUS
   VirusTotal : 14/94 engines say malicious, 2 suspicious (reputation -21)
                country: DE | owner: ...
   AbuseIPDB  : confidence 100%, 2500 reports, DE | ... | Data Center/Web Hosting/Transit | TOR exit node

192[.]168[.]1[.]1  [ip]  ->  PRIVATE
   private/reserved address - nothing to look up
```

(The numbers change from day to day: this is live data.)

The hash `44d88612fea8a8f36de82e1278abb02f` is the one of the **EICAR** test file: harmless, but detected by every antivirus. Handy to check everything works.

## Project layout

```
iocinfo/
├── iocinfo/
│   ├── ioc.py       # IOC type detection, fang/defang
│   ├── sources.py   # VirusTotal and AbuseIPDB clients, .env loading, verdict
│   └── cli.py
├── samples/iocs.txt
├── .env.example
└── tests/           # APIs are faked, no key needed for the tests
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

## Good practice

- **Don't submit files or confidential information** to VirusTotal: whatever is submitted there can be seen by others. This tool only sends hashes, IPs, domains and URLs, never files.
- Internal URLs (intranet, links containing a token) shouldn't be submitted.

## Ideas for later

- More sources: AlienVault OTX, URLhaus, GreyNoise, Shodan
- Local cache so the same IOC doesn't use up the quota twice
- CSV export

## License

MIT
