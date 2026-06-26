# ⚡ Reco-Nova — Premium Reconnaissance Intelligence Framework

```
 ██████╗ ███████╗ ██████╗ ██████╗       ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗      ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██████╔╝█████╗  ██║     ██║   ██║█████╗██╔██╗ ██║██║   ██║██║   ██║██║   ██
 ██╔══██╗██╔══╝  ██║     ██║   ██║╚════╝██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║  ██║███████╗╚██████╗╚██████╔╝      ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝       ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red?style=for-the-badge&logo=linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/Version-1.4-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/For-Bug%20Bounty-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Man%20Page-Available-blueviolet?style=for-the-badge"/>
</p>

<p align="center">
  <b>Professional Automated Reconnaissance Intelligence Framework</b><br/>
  <sub>Lead Auditor: Daniyal Shahid (CEH v13) &nbsp;|&nbsp; Version: 1.4 &nbsp;|&nbsp; Tested on: Kali Linux + Python 3.13</sub>
</p>

---

## 📋 Table of Contents

- [About Reco-Nova](#-about-reco-nova)
- [✨ Key Features](#-key-features)
- [🚀 Installation](#-installation)
- [📖 Usage](#-usage)
- [📊 Output Files](#-output-files)
- [🔧 Scan Phases](#-scan-phases)
- [⚙️ Configuration](#️-configuration)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [📄 Credits](#-credits)

---

## 🌟 About Reco-Nova

**Reco-Nova** is a premium, enterprise-grade reconnaissance intelligence framework designed for professional security researchers, bug bounty hunters, and penetration testers. Built with modern Python 3.9+ and cutting-edge web technologies, it transforms raw reconnaissance data into actionable security intelligence.

### 🎯 Mission Statement
> _"From scattered data points to unified attack surface intelligence"_

Reco-Nova automates the entire reconnaissance lifecycle, from subdomain enumeration to vulnerability analysis, delivering client-ready reports that rival commercial security tools. Engineered by **Daniyal Shahid (CEH v13)**, it is built with an aggressive "Bug Hunter" mindset.

---

## ✨ Key Features

### 🔍 **Comprehensive Reconnaissance Engine**
- **Multi-Source Subdomain Discovery**: crt.sh, HackerTarget, AlienVault OTX, RapidDNS, ThreatCrowd, subfinder, assetfinder, amass, DNS brute-force
- **Intelligent HTTP Probing**: Live host detection with 403/401 handling, **TCP fallback**, **WAF-aware throttling**, **execution jitter**
- **Advanced URL Discovery**: Wayback Machine (10k URLs), CommonCrawl, live web crawling with depth control
- **Aggressive JS Intelligence**: 2-pass Deep JS Crawler, inline `<script>` extraction, and multi-line secret detection for AWS, Firebase, Twilio, etc.
- **Sensitive Asset Detection**: 30+ file paths with smart baseline false-positive filtering
- **Technology Fingerprinting**: Native `TECH_PATTERNS` engine (headers/meta/scripts/body regex) + favicon MurmurHash3 (`mmh3`)
- **Bulletproof Screenshots (3-Tier)**: `httpx` (-system-chrome) → `gowitness` → Firefox Headless fallbacks
- **Intelligence Correlation**: Cross-referenced findings with **forensic audit logging**

### 🧠 **Advanced Intelligence Engine**
- **Parameter Vulnerability Mapping**: 50+ parameters → specific vulnerability classes (IDOR, SQLi, SSRF, LFI, etc.)
- **Context-Aware Risk Scoring**: 0–100 scale based on admin/API context, parameters, and technology stack
- **URL Intelligence**: **High-interest URL detection**, **smart grouping**, **priority badges** with visual highlighting
- **Attack Surface Visualization**: Interactive D3.js network graphs with zoom, drag, and click functionality
- **Automated Prioritization**: CRITICAL/HIGH/MEDIUM/LOW ranking with detailed reasoning
- **Forensic Audit Logging**: **scan_log.txt** with phase tracking, findings summary, and proof of work

### 🎨 **Premium User Experience**
- **Self-Healing Update Engine**: Run `reco-nova --update` to automatically apply aliases, update Go tools, Python dependencies, and system packages (`apt`).
- **Cybersec HTML Report**: Premium styling featuring neon Glassmorphism cards, animated count-ups, sticky nav, zoom-on-click Masonry screenshots, and DataTables.
- **Cinematic Attack Graph**: Full-screen interactive graph with floating filter controls, right-side node inspector, gradient edges, and pulsing critical nodes.
- **Modern Terminal UI**: Rich library with professional icons (`[*]`, `[+]`, `[!]`, `[-]`), boxed layouts, and detailed progress bars.

### 🛡️ **Enterprise-Grade Reliability**
- **Version Resilience**: Automatically strips deprecated flags from underlying tools if they fail during a scan.
- **Crash-Protected Architecture**: Every phase wrapped in exception handling — scans always complete.
- **Graceful Degradation**: Continues operation even when optional dependencies fail.
- **Stealth Mode**: **15+ User-Agent rotation**, **fake referers**, **execution jitter** for WAF evasion.

---

## 🚀 Installation

### 📋 System Requirements

- **Python**: 3.9+ (tested on Python 3.13)
- **Platform**: Linux (Kali/Ubuntu/Arch), macOS, Windows
- **Browser**: Firefox Headless (auto-installed) or gowitness fallback
- **Memory**: 4GB+ RAM recommended for large-scale scans
- **Storage**: 2GB+ free disk space for reports and screenshots

### ⚡ Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/skilldevloper/reco-nova.git
cd reco-nova

# Run the automated installer or the Self-Healing engine
python3 reco_nova.py --update

# You can now use the global alias from anywhere:
reco-nova -d target.com
```

### 📦 Manual Installation

#### 1. Python Dependencies
```bash
pip install -r requirements.txt
```

#### 2. Firefox Headless (Screenshots)
**Kali/Ubuntu:**
```bash
sudo apt-get install firefox-esr firefox libnss3 libgconf-2-4
```

**Arch Linux:**
```bash
sudo pacman -S firefox
```

**macOS:**
```bash
brew install firefox
```

#### 3. External Tools (Optional but Recommended)
```bash
# Go tools (subfinder, httpx, amass, gowitness)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/sensepost/gowitness@latest

# Verify installation
which subfinder httpx amass gowitness
```

### 🔧 Configuration

Reco-Nova is designed to work out-of-the-box with minimal configuration. All settings are in `config/settings.py`:

```python
# Custom timeout (default: 15s)
reco-nova -d example.com --timeout 30

# Custom threads (default: 20)
reco-nova -d example.com --threads 50

# Disable screenshots
reco-nova -d example.com --no-screenshots

# Passive-only mode (no active probing)
reco-nova -d example.com --passive-only

# Generate interactive graph
reco-nova -d example.com --graph

# Run the Self-Healing Update Engine
reco-nova --update

# Custom threading & timeout
reco-nova -d example.com --threads 50 --timeout 30
```

---

## 📖 Usage

### 🔰 Basic Scanning

```bash
# Standard reconnaissance scan
reco-nova -d example.com

# Full scan with screenshots and graph
reco-nova -d example.com --full --graph

# Multiple targets from file
reco-nova -l targets.txt --threads 30
```

### 📊 Advanced Usage

```bash
# Custom output directory
reco-nova -d example.com --output /custom/path

# Verbose mode with detailed logging
reco-nova -d example.com -v

# Passive reconnaissance only (no active probing)
reco-nova -d example.com --passive-only

# Skip screenshots for faster scanning
reco-nova -d example.com --no-screenshots
```

### 🎯 Bug Bounty Workflow

```bash
# 1. Quick recon to identify attack surface
reco-nova -d target.com --passive-only

# 2. Full scan with intelligence analysis
reco-nova -d target.com --full

# Stealth mode with execution jitter (rate limiting protection)
reco-nova -d target.com --passive-only --delay

# Generate comprehensive report with graph
reco-nova -d target.com --graph --output client-report/
```

### 📈 Monitoring Mode

```bash
# Continuous monitoring with change detection
reco-nova monitor example.com --interval 3600

# Monitor multiple targets
reco-nova monitor -l targets.txt --interval 1800
```

---

## 📊 Output Files

Reco-Nova creates comprehensive output in structured directories:

### 📁 Primary Output (`output/<domain>/`)

| File | Description |
|------|-------------|
| `subdomains.txt` | All discovered and validated subdomains |
| `live_hosts.txt` | Live hosts with HTTP status codes and titles |
| `apis.txt` | Discovered API endpoints with status codes |
| `urls.txt` | Complete URL collection from all sources |
| `parameters.txt` | Extracted URL parameters grouped by name |
| `js_analysis.txt` | JavaScript endpoints and secrets found |
| `secrets.txt` | Potential credentials, API keys, tokens |
| `sensitive_files.txt` | Exposed sensitive files with severity |
| `cloud_assets.txt` | Cloud storage assets (S3, Azure, GCP) |
| `fingerprints.txt` | Technology stack per host **with favicon hashes** |
| `probe_results.txt` | Full HTTP probe results **with WAF detection** |
| `correlation.txt` | Unified intelligence profiles |
| `prioritized_targets.txt` | Risk-scored target rankings |
| `scan_log.txt` | **Forensic audit trail** with phase tracking |

### 📸 Screenshots (`output/<domain>/screenshots/`)

- High-quality PNG screenshots using Firefox Headless
- Automatic gallery generation with lightbox viewer
- Individual files named: `subdomain_example_com.png`

### 📈 Reports (`reports/`)

| File | Description |
|------|-------------|
| `<domain>_report.html` | Modern Bootstrap dark theme report with all findings |
| `<domain>_graph.html` | Interactive D3.js network visualization |
| `<domain>_graph.json` | Machine-readable graph data for automation |

### 📊 Intelligence (`graphs/`)

- **Interactive Network Graph**: Zoom, pan, drag nodes
- **Color-Coded Visualization**: Different colors for asset types
- **Detailed Tooltips**: Hover over nodes for detailed information
- **Export Options**: JSON data for further analysis

---

## 🔧 Scan Phases

### **Phase 1: Subdomain Discovery**
Multi-source enumeration using passive DNS data, certificate transparency, and active brute-force.

### **Phase 2: HTTP Probing** 
Intelligent host validation with 403/401 handling and WAF-aware throttling.

### **Phase 3: URL & Parameter Discovery**
Historical and live crawling with parameter extraction for vulnerability analysis.

### **Phase 4: JavaScript Intelligence**
Deep 2-pass aggressive crawling of JavaScript files and inline `<script>` tags for endpoints, secrets, and API keys.

### **Phase 5: Sensitive Asset Detection**
Comprehensive file enumeration with smart false-positive filtering.

### **Phase 6: Intelligence & Correlation**
Advanced correlation engine with risk scoring and target prioritization.

### **Phase 7: Screenshots & Reporting**
3-Tier screenshot strategy (`httpx`, `gowitness`, `firefox`) with Premium Cybersec HTML report generation and Cinematic Attack Surface Graph.

---

## ⚙️ Configuration

### 📄 Settings File (`config/settings.py`)

```python
# Scan Configuration
DEFAULT_TIMEOUT = 15          # HTTP request timeout in seconds
DEFAULT_THREADS = 20          # Concurrent threads
MAX_URLS_PER_HOST = 10000   # Wayback Machine limit
MAX_CRAWL_DEPTH = 2          # Live crawler depth

# Screenshot Configuration
SCREENSHOT_TIMEOUT = 60         # Firefox screenshot timeout
SCREENSHOT_DELAY = 5           # Delay between screenshots
MAX_SCREENSHOTS = 30          # Maximum screenshots per domain

# Risk Scoring
CRITICAL_THRESHOLD = 80         # Minimum score for CRITICAL priority
HIGH_THRESHOLD = 60             # Minimum score for HIGH priority
```

### 🎨 Customization

```python
# Add custom vulnerability patterns
VULN_PATTERNS = {
    "custom_param": {
        "pattern": r"user_id|account_id",
        "vulnerability": "IDOR",
        "severity": "High"
    }
}

# Custom sensitive file paths
CUSTOM_PATHS = [
    "/api/docs",
    "/backup/config",
    "/.env.production"
]
```

---

## 🛠️ Troubleshooting

### 🔧 Common Issues

#### **Screenshot Failures**
```bash
# Verify httpx and gowitness are installed
which httpx
which gowitness

# Run the Update Engine to automatically install them
reco-nova --update
```

#### **Permission Denied Errors**
```bash
# Use --passive-only to avoid active probing
reco-nova -d target.com --passive-only

# Reduce threads to avoid rate limiting
reco-nova -d target.com --threads 5

# Increase timeout for slow targets
reco-nova -d target.com --timeout 30
```

#### **Memory Issues on Large Scans**
```bash
# Limit concurrent operations
reco-nova -d target.com --threads 10

# Process targets in batches
reco-nova -l targets.txt --threads 5

# Use monitoring mode for gradual scanning
reco-nova monitor target.com --interval 7200
```

#### **Dependency Issues**
```bash
# Complete environment check
reco-nova setup

# Force reinstall problematic packages
pip install beautifulsoup4 mmh3 lxml --force-reinstall --break-system-packages

# Check Python environment
python3 -c "import sys; print(sys.executable); print(sys.version)"
```

### 📝 Debug Mode

```bash
# Enable verbose logging
reco-nova -d target.com -v

# Check logs for detailed errors
tail -f logs/reco-nova-*.log

# Test individual modules
python3 -m modules.subdomain_discovery -d example.com
python3 -m modules.http_probe -l hosts.txt
```

---

## 📄 Credits

### 👨‍💻 **Lead Auditor**

**Daniyal Shahid (CEH v13)**
- *Security Researcher* | *Bug Bounty Hunter* | *Penetration Tester*
- GitHub: [@daniyalshahid](https://github.com/skilldevloper)
- Twitter: [@daniyal_shahid](https://twitter.com/Daniyal02570180)

### 🙏 **Acknowledgments**

Reco-Nova incorporates and builds upon several open-source projects:

- **[D3.js](https://d3js.org/)** - Interactive data visualizations
- **[Bootstrap](https://getbootstrap.com/)** - Modern responsive UI framework  
- **[Rich](https://rich.readthedocs.io/)** - Beautiful terminal output
- **[BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)** - HTML parsing
- **[aiohttp](https://aiohttp.readthedocs.io/)** - Async HTTP operations

### 📜 **License**

```
MIT License

Copyright (c) 2024 Daniyal Shahid

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🚀 Getting Started

### 🎯 **First Scan**
```bash
# Basic reconnaissance
reco-nova -d example.com

# View results
ls output/example.com/
cat output/example.com/report.html
```

### 📈 **Advanced Workflow**
```bash
# 1. Passive reconnaissance
reco-nova -d target.com --passive-only

# 2. Active scanning with intelligence
reco-nova -d target.com --full

# 3. Generate comprehensive report
reco-nova -d target.com --graph --output client-report/

# 4. Monitor for changes
reco-nova monitor target.com --interval 3600
```

---

<p align="center">
  <b>⚡ Reco-Nova — Hunt Smarter, Not Harder</b><br/>
  <sub>Enterprise-Grade Reconnaissance Intelligence for Professional Security Research</sub>
</p>
