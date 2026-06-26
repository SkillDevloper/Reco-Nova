# ⚡ Reco-Nova — Reconnaissance Intelligence Framework

```
 ██████╗ ███████╗ ██████╗ ██████╗       ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗      ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║█████╗██╔██╗ ██║██║   ██║██║   ██║███████║
 ██╔══██╗██╔══╝  ██║     ██║   ██║╚════╝██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝      ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/Version-1.2-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/For-Bug%20Bounty-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Man%20Page-Available-blueviolet?style=for-the-badge"/>
</p>

<p align="center">
  <b>Automated Reconnaissance Intelligence Framework for Bug Bounty Hunters & Security Researchers</b><br/>
  <sub>Developer: Daniyal Shahid &nbsp;|&nbsp; Tested on: Kali Linux + Python 3.13</sub>
</p>

---

## 📌 Table of Contents

- [What is Reco-Nova?](#-what-is-reco-nova)
- [What's New in v1.1?](#-whats-new-in-v11)
- [Features](#-features)
- [Folder Structure](#-folder-structure)
- [Installation](#-installation)
- [Man Page](#-man-page)
- [Usage](#-usage)
- [All Commands](#-all-commands)
- [Output Files](#-output-files)
- [Scan Phases](#-scan-phases)
- [Intelligence Engine](#-intelligence-engine)
- [Dependencies](#-dependencies)
- [Troubleshooting](#-troubleshooting)
- [Legal Disclaimer](#-legal-disclaimer)

---

## What's New in v1.2?

### Pro-Level Logic & Resilience

#### Phase 6 — Deep Fingerprinting Database (50+ Signatures)
- Comprehensive technology signatures: 50+ entries across servers, frameworks, CMS, cloud/CDN, WAF, and databases
- Multi-source detection: Checks Server headers, X-Powered-By, Set-Cookie, HTML body tags, and meta generators
- Favicon Fingerprinting: MurmurHash3 hash calculation for `/favicon.ico` with 50+ known hashes
  - Detects Jenkins, Jira, Confluence, Spring Boot, phpMyAdmin, WordPress, Grafana, Kubernetes, and more
  - Shodan-compatible hash algorithm for known technology identification

#### Phase 2 & 3 — URL Intelligence & Priority Filtering
- High-interest URL detection: Automatically identifies sensitive URLs by extensions (`.php`, `.env`, `.config`, etc.) and keywords (`admin`, `api`, `login`, etc.)
- Smart Grouping: Groups 10+ URLs with same high-interest tag under "Show More" toggle to reduce UI noise
- Priority badges: HIGH/NORMAL badges with visual highlighting (red glow) for high-priority targets
- Indicator tags: Shows technology indicators (PHP, Admin Panel, API v1, etc.)
- DataTables filtering: Filter buttons for "High Priority Only" and "Show All"

#### Forensic Audit Logging
- scan_log.txt: Professional audit trail in output directory
- Phase/module tracking: Logs start/end times, result counts, status, and duration for all 7 phases
- Findings summary: Comprehensive summary with all discovered assets
- Proof of work: Audit-ready format for professional security assessments

#### Stealth & WAF Resilience
- Global header rotation: `get_random_ua()` with 15+ modern User-Agents (Chrome, Firefox, Safari, Edge)
- Fake Referer headers: Randomized legitimate referers (Google, Bing, Reddit, GitHub, etc.)
- httpx screenshot fallback: Tertiary fallback with stealth User-Agent rotation for each request
- WAF detection: Automatic WAF detection (Cloudflare, Akamai, ModSecurity, etc.) with adaptive rate limiting

#### Execution Jitter (Rate Limiting Bypass)
- `--delay` flag: Enables 0.5-2s random sleep between requests
- Rate limiting protection: Random delays minimize WAF detection and prevent blocking
- Module coverage: Applied to all passive sources (crt.sh, HackerTarget, AlienVault, RapidDNS, ThreatCrowd)

#### Advanced Error Tracing
- Detailed error logging: Captures HTTP status codes (403, 401, 404, 429, 500, etc.) and exception types
- Error categorization: Maps status codes to human-readable categories (e.g., "Forbidden (WAF/Access Control)")
- Error summaries: Per-phase breakdowns by error type for audit trails

### Phase 7 — Screenshots (Major Overhaul)
- Primary: Firefox Headless with `--headless --screenshot` flags
- Secondary fallback: `gowitness scan single --no-sandbox --disable-gpu --timeout 20`
- Tertiary fallback: `httpx -screenshot` with stealth User-Agent rotation
- Force Logic: Extracts unique domains from discovered URLs when `live_hosts = 0`

### Phase 4 & 6 — Native Fingerprinting Stability
- `beautifulsoup4` import is validated as `bs4` (correct runtime import name)
- Legacy `python-wappalyzer` dependency removed from runtime and setup checks
- Native fingerprinting dependencies now include `mmh3` and `lxml`
- Environment Debugging: setup import checks expose missing native deps quickly

### Phase 2 & 3 — URL Intelligence & Priority Filtering
- High-interest URL detection: Automatically identifies sensitive URLs by extensions (`.php`, `.env`, `.config`, etc.) and keywords (`admin`, `api`, `login`, etc.)
- Smart Grouping: Groups 10+ URLs with same high-interest tag under "Show More" toggle to reduce UI noise
- Priority badges: HIGH/NORMAL badges with visual highlighting (red glow) for high-priority targets
- Indicator tags: Shows technology indicators (PHP, Admin Panel, API v1, etc.)
- DataTables filtering: Filter buttons for "High Priority Only" and "Show All"

---

## What is Reco-Nova?

**Reco-Nova** is an automated reconnaissance intelligence framework designed for bug bounty hunters, penetration testers, and security researchers.

Unlike simple recon scripts, Reco-Nova:

- Collects data from multiple passive and active sources simultaneously
- Analyzes JavaScript files for hidden endpoints and leaked secrets
- Correlates all findings into unified per-host intelligence profiles
- Prioritizes high-value attack targets using a 0–100 risk scoring engine
- Visualizes the entire attack surface as an interactive HTML graph
- Monitors assets over time and alerts on newly exposed infrastructure

> Raw data → Structured Security Intelligence

---

## Features

| Feature | Description |
|---|---|
| Subdomain Discovery | crt.sh, HackerTarget, AlienVault OTX, RapidDNS, ThreatCrowd, subfinder, assetfinder, amass, DNS brute-force |
| HTTP Probing | Live host detection, status codes, login/admin panel detection, API discovery, WAF-aware throttling |
| URL Discovery | Wayback Machine (10k URLs), CommonCrawl, live web crawler (depth 2) |
| JS Intelligence | Endpoint extraction from fetch/axios/XHR, async JS worker queue, multi-line secret detection |
| Sensitive Files | 30+ paths checked — .env, .git, backup, config, credentials with smart baseline false-positive filtering |
| Fingerprinting | Native `TECH_PATTERNS` engine: headers + HTML meta + script tags + body regexes + favicon MurmurHash3 |
| Vulnerability Scanning | Optional Nuclei integration (`--nuclei`) with JSON output and severity-aware summary stats |
| Screenshots | Firefox Headless (primary) → gowitness (fallback) → httpx with stealth UA (tertiary) |
| Parameter Intel | 50+ parameter → vulnerability class mapping (IDOR, SQLi, SSRF, LFI, Open Redirect...) |
| Risk Scoring | Context-aware 0–100 scoring (admin/API context, parameters, tech stack), sorted into CRITICAL / HIGH / MEDIUM / LOW |
| Attack Surface Graph | Interactive HTML graph — domain → subdomain → endpoint → parameter |
| Monitoring | Continuous scan with diff-based change detection and JSON diff reports |
| HTML Report | Full dark-themed intelligence report with all findings |
| Man Page | Full Linux manual page — `man reco-nova` |

---

## Folder Structure

```
Reco-Nova v-1.2/
│
├── Reco_nova.py              ← MAIN ENTRY POINT — run this file
├── install.sh                ← Run first on fresh install
├── requirements.txt          ← Python pip dependencies
├── README.md                 ← This documentation file
├── reco-nova.1               ← Man page (raw troff format)
├── reco-nova.1.gz            ← Man page (compressed — install this)
├── Images/                   ← Documentation images and screenshots
│
├── config/
│   ├── __init__.py
│   └── settings.py           ← All settings, vuln maps, secret patterns
│
├── core/
│   ├── __init__.py
│   ├── banner.py             ← ASCII art banner on startup
│   ├── logger.py             ← File-based logging + forensic audit logger
│   ├── display.py            ← Rich terminal UI (colors, tables, summary box)
│   ├── setup_checker.py      ← Dependency verifier + auto-installer
│   ├── input_handler.py      ← All input modes (-d, -l, stdin, interactive)
│   ├── scan_engine.py        ← Master orchestrator — runs all 7 phases
│   ├── reporter.py           ← Classic HTML report generator
│   ├── reporter_modern.py    ← Bootstrap dark theme with URL intelligence
│   ├── utils.py              ← Stealth headers, User-Agent rotation
│   └── monitor.py            ← Continuous monitoring + diff detection
│
├── modules/
│   ├── __init__.py
│   ├── subdomain_discovery.py  ← Phase 1: crt.sh, APIs, subfinder, DNS brute-force
│   ├── http_probe.py           ← Phase 2: HTTP probing, WAF detection, stealth headers
│   ├── url_discovery.py        ← Phase 3: Wayback, CommonCrawl, live crawler
│   ├── js_intelligence.py      ← Phase 4: JS download, beautify, endpoint + secret extraction
│   ├── sensitive_assets.py     ← Phase 5: .env/.git/backup/config detection + cloud assets
│   ├── fingerprinting.py       ← Phase 6: Native TECH_PATTERNS + favicon MurmurHash3 fingerprinting
│   ├── vulnerability_scanner.py← Optional Nuclei vulnerability scanning (`--nuclei`)
│   └── screenshots.py          ← Phase 7: Firefox → gowitness → httpx with stealth UA
│
├── intelligence/
│   ├── __init__.py
│   ├── analysis.py             ← Parameter vuln mapping + endpoint risk scoring
│   └── correlation.py          ← Data correlation + JSON/HTML graph builder
│
├── output/                   ← Auto-created when scan runs
│   └── example.com/
│       ├── subdomains.txt
│       ├── live_hosts.txt
│       ├── apis.txt
│       ├── urls.txt
│       ├── parameters.txt
│       ├── js_analysis.txt
│       ├── secrets.txt
│       ├── sensitive_files.txt
│       ├── cloud_assets.txt
│       ├── fingerprints.txt
│       ├── probe_results.txt
│       ├── correlation.txt
│       ├── prioritized_targets.txt
│       ├── scan_log.txt        ← Forensic audit log
│       └── screenshots/
│
├── graphs/                   ← Auto-created
│   ├── example.com_graph.json
│   └── example.com_graph.html
│
├── reports/                  ← Auto-created
│   └── example.com_report.html
│
├── database/                 ← Auto-created (monitor mode only)
│   └── example.com_baseline.json
│
└── logs/                     ← Auto-created
    └── reco-nova-20260312-143022.log
```

> **Note:** `output/`, `graphs/`, `reports/`, `database/`, and `logs/` are created automatically. You do not need to create them manually.

---

## Installation

### Requirements

- Python 3.9+ (tested on Python 3.13 on Kali Linux)
- Linux — Kali Linux or Ubuntu recommended
- Go 1.21+ (optional — for subfinder, httpx, amass, gowitness)
- **Chromium browser** (required for httpx screenshot capture)

### Step 1 — Navigate to project folder

```bash
cd ~/Desktop/Reconova-v1.0
```

### Step 2 — Install system-level screenshot dependencies

The screenshot engine (`httpx -screenshot` and `gowitness`) requires a Chromium browser and shared system libraries. **Install these first or screenshots will silently fail.**

**Kali Linux / Ubuntu / Debian:**
```bash
sudo apt-get update && sudo apt-get install -y \
  chromium-browser libnss3 libgconf-2-4 libxi6 libxrandr2 \
  libxss1 libxcursor1 libxcomposite1 libasound2 libxtst6 \
  libatk-bridge2.0-0 libgtk-3-0 libgbm1 fonts-liberation
```

**Arch Linux / BlackArch:**
```bash
sudo pacman -S chromium nss libxi libxrandr
```

**Fedora / RHEL:**
```bash
sudo dnf install chromium nss libXrandr libXi
```

> **Note:** The `install.sh` script handles this automatically for apt/pacman/dnf systems.

### Step 3 — Run installer

```bash
bash install.sh
```

This will:
- Check Python version (3.9+ required)
- Install system-level chromium + libnss3 dependencies (auto-detects apt/pacman/dnf)
- Install all pip dependencies (`--break-system-packages` handled automatically)
- Force-reinstall `beautifulsoup4` to prevent import conflicts
- Create `reco-nova` alias in `~/.bashrc` and `~/.zshrc`
- Make `reco_nova.py` executable

### Step 4 — Load alias

Kali Linux uses **Zsh** by default:
```bash
source ~/.zshrc
```

Or if using Bash:
```bash
source ~/.bashrc
```

### Step 5 — Fix file names (IMPORTANT on Linux)

Linux is case-sensitive. Run this once:

```bash
cd ~/Desktop/Reconova-v1.0
mv config/Settings.py config/settings.py
mv core/Banner.py core/banner.py
mv core/Display.py core/display.py
mv core/Input_handler.py core/input_handler.py
mv core/Logger.py core/logger.py
mv core/Setup_checker.py core/setup_checker.py
```

> Windows treats `Settings.py` and `settings.py` as the same file. Linux does not. The code imports lowercase names so files must match exactly.

### Step 6 — Verify environment

```bash
reco-nova setup
```

Expected output:

```
  [OK]  Python 3.13.x
  Python Libraries
    [OK]  requests
    [OK]  aiohttp
    [OK]  bs4
    [OK]  rich
    [OK]  typer
    [OK]  tldextract
    [OK]  dnspython
    [OK]  jsbeautifier
    [OK]  jinja2
    [OK]  aiofiles
  External Tools
    [OK]  subfinder
    [OK]  httpx
    [OK]  assetfinder
    [OK]  gowitness
    [OK]  amass
```

### Step 7 — Install Man Page (optional)

```bash
sudo cp reco-nova.1.gz /usr/share/man/man1/
sudo mandb
man reco-nova
```

---

## Man Page

Reco-Nova ships with a full Linux manual page — just like `man nmap`.

```bash
# Install
sudo cp reco-nova.1.gz /usr/share/man/man1/
sudo mandb

# Read
man reco-nova
```

| Key | Action |
|---|---|
| `Space` / `f` | Next page |
| `b` | Previous page |
| `/keyword` | Search |
| `n` | Next search result |
| `q` | Quit |

---

## Usage

### Basic scan

```bash
reco-nova -d example.com
```

### Full scan — all modules

```bash
reco-nova -d example.com --full
```

### Full scan + attack surface graph

```bash
reco-nova -d example.com --full --graph
```

### Passive only — stealth mode (recommended for first run)

```bash
reco-nova -d example.com --passive-only --no-screenshots
```

### Batch scan from file

```bash
reco-nova -l domains.txt
```

`domains.txt` format:
```
# comments are ignored
example.com
test.com
demo.org
```

### Stdin pipeline

```bash
cat domains.txt | reco-nova
```

### Custom threads and timeout

```bash
reco-nova -d example.com --threads 30 --timeout 15
```

> On rate-limited or WAF-protected targets use: `--threads 5`

### Skip screenshots

```bash
reco-nova -d example.com --no-screenshots
```

### Verbose output

```bash
reco-nova -d example.com -v
```

---

## All Commands

```
usage: reco-nova [-h] [-d DOMAIN] [-l LIST] [--full] [--graph]
                 [--threads N] [--timeout N] [--output DIR]
                 [--no-screenshots] [--passive-only] [-v]
                 {setup,monitor,report} ...

SUBCOMMANDS:
  setup                    Verify and auto-install all dependencies
  monitor <domain>         Continuous monitoring mode
    --interval SECONDS       Time between scans (default: 3600)
  report <domain>          Generate HTML report from existing scan data

SCAN OPTIONS:
  -d, --domain DOMAIN      Single target domain
  -l, --list FILE          File with list of domains (one per line)
  --full                   Enable all modules (full recon mode)
  --graph                  Generate interactive attack surface graph
  --threads N              Concurrent threads (default: 20)
  --timeout N              HTTP timeout in seconds (default: 10)
  --output DIR             Output directory (default: output/)
  --no-screenshots         Skip screenshot capture
  --passive-only           Passive sources only — no active probing
  -v, --verbose            Verbose output
  -h, --help               Show help and exit
```

### Quick Reference

```bash
reco-nova -d example.com                           # basic scan
reco-nova -d example.com --full --graph            # full scan + graph
reco-nova -d example.com --passive-only            # stealth mode
reco-nova -l domains.txt --threads 30              # batch scan
reco-nova monitor example.com --interval 1800      # monitor every 30min
reco-nova report example.com                       # generate report
reco-nova setup                                    # check dependencies
man reco-nova                                      # read manual
```

---

## Output Files

All results saved in `output/<domain>/`:

| File | Contents |
|---|---|
| `subdomains.txt` | All discovered and DNS-validated subdomains |
| `live_hosts.txt` | Live hosts with HTTP status codes |
| `apis.txt` | API endpoints with status codes |
| `urls.txt` | All collected URLs |
| `parameters.txt` | URL parameters grouped by name |
| `js_analysis.txt` | Endpoints and secrets from JS files |
| `secrets.txt` | Credentials, API keys, tokens (masked) |
| `sensitive_files.txt` | Exposed sensitive files with severity |
| `cloud_assets.txt` | S3, Azure, GCP, Cloudflare R2 assets |
| `fingerprints.txt` | Technology stack per host with favicon hashes |
| `probe_results.txt` | Full HTTP probe — status, title, server |
| `correlation.txt` | Unified intelligence profile per host |
| `prioritized_targets.txt` | Risk-scored ranked target list |
| `scan_log.txt` | **Forensic audit log** with phase tracking |
| `screenshots/` | PNG screenshots of live hosts |

**Additional:**

| Path | Contents |
|---|---|
| `graphs/<domain>_graph.html` | Interactive attack surface graph |
| `graphs/<domain>_graph.json` | Machine-readable graph data |
| `reports/<domain>_report.html` | Full HTML intelligence report |
| `database/<domain>_baseline.json` | Monitoring baseline |
| `logs/reco-nova-<timestamp>.log` | Full execution log |

---

## Scan Phases

### Phase 1 — Subdomain Discovery

| Source | Type |
|---|---|
| crt.sh | Certificate transparency |
| HackerTarget | Passive DNS |
| AlienVault OTX | Threat intelligence |
| RapidDNS | DNS records |
| ThreatCrowd | Threat data |
| subfinder | Multi-source enumeration |
| assetfinder | Fast passive finder |
| amass | Advanced graph enumeration |
| DNS brute-force | 60+ common prefixes |

### Phase 2 — HTTP Probing
- Tests HTTP + HTTPS on every subdomain across ports 80, 443, 8080, 8443, 8888, 9000
- Detects live status, page title, server header
- Flags login panels, admin pages, API endpoints
- **`403 Forbidden` and `401 Unauthorized` are treated as LIVE hosts** (authentication-gated)
- Automatically enables WAF-aware rate limiting (reduced threads + jitter) when a WAF (Cloudflare, Akamai, ModSecurity, etc.) is detected

### Phase 3 — URL & Parameter Discovery
- Wayback Machine — up to 10,000 historical URLs
- CommonCrawl — crawl index
- Live Crawler — internal links depth 2
- Extracts all `?param=` from every URL

### Phase 4 — JavaScript Intelligence

Downloads and beautifies JavaScript files using an asynchronous worker queue, then extracts endpoints, parameters, and detects 20+ secret types (multi-line aware).

If `beautifulsoup4` is not available, an **aggressive regex fallback** kicks in automatically:
```
(?:src|href)=(["'])([^"']+\.js[^"']*)\1
```
This catches `src=` and `href=` attributes, CDN scripts, and query-string variants without any library dependency.

| Secret Type | Example Pattern |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` |
| JWT Token | `eyJ...` |
| Stripe Key | `sk_live_...` |
| Firebase Key | `AIza[0-9A-Za-z]{35}` |
| Slack Token | `xox[baprs]-...` |
| Private Key | `-----BEGIN PRIVATE KEY-----` |
| Database URL | `database_url = "postgres://..."` |

### Phase 5 — Sensitive Asset Detection

Checks 30+ paths including (with smart baseline comparison to remove ghost/custom-404 hits):
```
.env  .git/config  backup.zip  database.sql
config.php  wp-config.php  id_rsa  credentials.json
Dockerfile  docker-compose.yml  phpinfo.php  .htaccess
python3 Reco_nova.py --help
```

### Phase 6 — Intelligence & Correlation

**Parameter → Vulnerability Mapping:**

| Parameter | Vulnerability | Severity |
|---|---|---|
| `id`, `user_id` | IDOR | High |
| `redirect`, `next`, `url` | Open Redirect | Medium |
| `file`, `path`, `load` | LFI / Path Traversal | High |
| `query`, `search`, `q` | SQLi / XSS | High |
| `host`, `domain`, `uri` | SSRF | High |
| `callback`, `jsonp` | JSONP Injection | Medium |
| `token`, `key`, `secret` | Secret Exposure | Critical |
| `password`, `passwd` | Credential Exposure | Critical |

**Risk Scoring (Context-Aware):**

| Condition | Points |
|---|---|
| Admin panel | +40 |
| Login panel | +30 |
| API endpoint | +20 |
| Admin keyword in URL | +15 |
| 401 Unauthorized | +15 |
| 403 Forbidden | +10 |
| Sensitive parameter (e.g. `id`, `user_id`, `account_id`) on `/admin` or `/api/v2` path | +25 |

Risk is also slightly reduced for obviously public content (e.g. `/blog`, `/news`, `/static/`). Technologies identified during fingerprinting are mapped to recommended sensitive file checks (e.g. PHP/WordPress → `config.php`, `.php.bak`, `wp-config.php`).

Priority: **CRITICAL** (80–100) · **HIGH** (60–79) · **MEDIUM** (35–59) · **LOW** (0–34)

### Phase 7 — Screenshots & Report
- **Primary**: `httpx -screenshot -system-chrome -args "--no-sandbox,--disable-gpu,--headless" -screenshot-wait 10` (uses system-installed Chrome with proper args parameter)
- **Root detection**: Automatically detects root user and makes Chrome sandbox args mandatory
- **Path validation**: Checks `shutil.which('httpx')` before execution
- **Aggressive fallback**: `gowitness single <url> --no-sandbox --disable-gpu --timeout 20` (individual URL processing)
- **Force Logic**: if `live_hosts = 0` but URLs were discovered, unique domains are extracted and screenshotted automatically
- Full dark-themed HTML report at `reports/<domain>_report.html`

---

## 🧠 Intelligence Engine

The intelligence engine correlates all collected data into actionable security insights:

### Data Correlation
- **Per-host profiles**: All findings (subdomains, URLs, parameters, technologies, secrets) unified by host
- **Cross-referencing**: Parameters mapped to discovered endpoints, technologies to sensitive files
- **Context scoring**: Admin/API endpoints weighted higher than public content

### Risk Assessment
- **Automated scoring**: 0–100 scale based on context, parameters, and technology stack
- **Vulnerability mapping**: 50+ parameters → specific vulnerability classes
- **Prioritization**: CRITICAL/HIGH/MEDIUM/LOW ranking with detailed reasoning

### Reporting
- **Interactive graphs**: Domain → subdomain → endpoint → parameter relationships
- **HTML intelligence reports**: Dark-themed, comprehensive findings
- **Machine-readable output**: JSON for automation and integration

### Screenshots not working / 0 screenshots captured

```bash
# Verify Chrome is installed
chromium-browser --version
# OR
google-chrome --version

# Install if missing (Kali / Ubuntu)
sudo apt-get install -y chromium-browser libnss3 libgtk-3-0 libgbm1

# Verify httpx supports screenshots
httpx -version   # should be recent build

# Check if httpx is in PATH
which httpx

# If httpx still fails, gowitness fallback kicks in automatically.
# Check logs/ folder for the full stderr:
cat logs/reco-nova-*.log | grep -i screenshot
```

**Common Issues:**
- **Root user**: Chrome sandbox args are automatically added when running as root
- **httpx not found**: Ensure `httpx` is in your PATH (`shutil.which('httpx')` check)
- **Permission denied**: Install Chromium system libraries as shown above

### `reco-nova: command not found`
```bash
source ~/.zshrc        # Kali Linux (Zsh)
source ~/.bashrc       # Bash
# Or run directly:
python3 Reco_nova.py --help
```

### `[!] Some dependencies missing` on scan start
```bash
reco-nova setup    # auto-installs missing libs
```

### Fingerprinting dependency issues (bs4/mmh3/lxml)
If setup shows dependencies as installed but scan still reports missing libs:

```bash
# Check actual import status
python3 -c "import bs4; print('bs4 OK')"
python3 -c "import mmh3; print('mmh3 OK')"
python3 -c "import lxml; print('lxml OK')"

# If imports fail, check environment
python3 -c "import sys; print('Python executable:', sys.executable)"
python3 -c "import sys; print('sys.path:'); [print(p) for p in sys.path]"

# Force reinstall with environment flags
python3 -m pip install beautifulsoup4 mmh3 lxml --break-system-packages --force-reinstall

# In virtual environment, ensure venv is activated
source venv/bin/activate
pip install beautifulsoup4 mmh3 lxml --force-reinstall
```

**Bypass Behavior**: If core native deps (`mmh3`/`lxml`) fail import checks, Phase 6 is disabled and scan continues with other phases.

### `sudo` password prompt during scan
```bash
reco-nova -d example.com --passive-only    # skips amass (which needs sudo)
```

### Scan too slow or getting rate-limited
```bash
reco-nova -d example.com --threads 5 --timeout 20
```

### Running inside virtual environment
```bash
source venv/bin/activate
pip install -r requirements.txt
reco-nova -d example.com
```

---

## ⚠️ Legal Disclaimer

╔══════════════════════════════════════════════════════════════╗
║                    LEGAL DISCLAIMER                          ║
║                                                              ║
║  Reco-Nova is designed EXCLUSIVELY for authorized security   ║
║  testing and educational purposes.                           ║
║                                                              ║
║  Use of this tool against systems WITHOUT explicit written   ║
║  authorization from the system owner is ILLEGAL and          ║
║  UNETHICAL under applicable computer crime laws.             ║
║                                                              ║
║  The developer (Daniyal Shahid) assumes NO liability for     ║
║  unauthorized, unethical, or illegal use of this tool.       ║
║                                                              ║
║  Always:                                                     ║
║  • Obtain written authorization before scanning              ║
║  • Follow responsible disclosure practices                   ║
║  • Comply with bug bounty program scope and rules            ║
╚══════════════════════════════════════════════════════════════╝

## 👤 Developer

**Daniyal Shahid**

| | |
|---|---|
| Tool | Reco-Nova |
| Version | **1.2** |
| Platform | Kali Linux / Ubuntu |
| Language | Python 3.9+ |
| Tested On | Kali Linux, Python 3.13 |

---

<p align="center">
  <b>⚡ Reco-Nova — Hunt Smarter, Not Harder</b><br/>
  <sub>Made for Bug Bounty Hunters. Built for Intelligence.</sub>
</p>