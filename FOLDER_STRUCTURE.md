# Reco-Nova Project Structure

Complete directory and file organization for the Reco-Nova Framework v1.2.

## Overview

```
reco-nova/
├── reco_nova.py              # Main entry point & CLI
├── install.sh                # Automated setup script
├── requirements.txt          # Python dependencies
├── README.md                 # Professional documentation
├── FOLDER_STRUCTURE.md       # This file
├── man/
│   └── reco-nova.1          # Manual page
│
├── config/                   # Configuration module
│   ├── __init__.py
│   └── settings.py          # Global settings & constants
│
├── core/                     # Core framework modules
│   ├── __init__.py
│   ├── banner.py            # ASCII art banner
│   ├── display.py           # Rich-based terminal UI
│   ├── input_handler.py     # Target input processing
│   ├── logger.py            # Logging infrastructure + forensic audit logger
│   ├── reporter.py          # Classic HTML report generator
│   ├── reporter_modern.py   # Bootstrap dark theme reports with URL intelligence
│   ├── scan_engine.py       # Main scan orchestration
│   ├── setup_checker.py     # Dependency verification
│   └── utils.py             # Stealth headers, User-Agent rotation
│
├── modules/                  # Reconnaissance modules
│   ├── __init__.py
│   ├── subdomain_discovery.py    # Phase 1: Subdomain enumeration
│   ├── http_probe.py            # Phase 2: HTTP probing
│   ├── url_discovery.py         # Phase 3: URL & parameter discovery
│   ├── js_intelligence.py      # Phase 4: JavaScript analysis
│   ├── sensitive_assets.py     # Phase 5: Sensitive file detection
│   ├── fingerprinting.py       # Phase 6: Technology fingerprinting
│   └── screenshots.py          # Phase 7: Screenshot capture
│
├── intelligence/             # Intelligence & analysis
│   ├── __init__.py
│   ├── analysis.py          # Parameter & endpoint analysis
│   ├── correlation.py       # Classic correlation engine
│   └── correlation_modern.py # D3.js graph generator
│
├── output/                   # Scan outputs (created at runtime)
│   └── <domain>/
│       ├── subdomains.txt
│       ├── live_hosts.txt
│       ├── urls.txt
│       ├── parameters.txt
│       ├── apis.txt
│       ├── js_analysis.txt
│       ├── secrets.txt
│       ├── sensitive_files.txt
│       ├── cloud_assets.txt
│       ├── fingerprints.txt
│       ├── probe_results.txt
│       ├── correlation.txt
│       ├── prioritized_targets.txt
│       ├── scan_log.txt        # Forensic audit log
│       └── screenshots/
│           └── *.png
│
├── reports/                  # Generated HTML reports
│   ├── <domain>_modern.html  # Modern Bootstrap report (default)
│   └── <domain>_report.html  # Classic simple report (with --simple)
│
├── graphs/                   # Interactive attack surface graphs
│   ├── <domain>_graph.html   # D3.js visualization
│   └── <domain>_graph.json  # Graph data
│
└── logs/                     # Execution logs
    └── reco-nova-*.log
```

## Module Descriptions

### Core Modules (`core/`)

| File | Purpose |
|------|---------|
| `banner.py` | ASCII art logo and version info |
| `display.py` | Rich-based terminal UI with icons, panels, progress bars |
| `input_handler.py` | Parse domain lists, files, CLI arguments |
| `logger.py` | Structured logging with rotation + forensic audit logger |
| `reporter.py` | Classic simple HTML report generator |
| `reporter_modern.py` | Modern Bootstrap dark theme report generator with URL intelligence |
| `scan_engine.py` | Main orchestrator for all 7 scan phases |
| `setup_checker.py` | Verify/install dependencies |
| `utils.py` | Stealth headers, User-Agent rotation, execution jitter |

### Reconnaissance Modules (`modules/`)

| File | Phase | Description |
|------|-------|-------------|
| `subdomain_discovery.py` | 1 | Multi-source subdomain enumeration |
| `http_probe.py` | 2 | HTTP probing with WAF detection |
| `url_discovery.py` | 3 | Wayback, CommonCrawl, live crawling |
| `js_intelligence.py` | 4 | JavaScript analysis & secret extraction |
| `sensitive_assets.py` | 5 | Sensitive file detection |
| `fingerprinting.py` | Phase 6 | Native TECH_PATTERNS fingerprinting (headers/meta/scripts/body regex) + favicon MurmurHash3 |
| `vulnerability_scanner.py` | Bonus | Optional Nuclei vulnerability scan (`--nuclei`) with JSON output |
| `screenshots.py` | Phase 7 | Firefox → gowitness → httpx with stealth UA rotation |

### Intelligence Modules (`intelligence/`)

| File | Purpose |
|------|---------|
| `analysis.py` | Parameter vulnerability mapping, risk scoring |
| `correlation.py` | Classic graph data generation |
| `correlation_modern.py` | D3.js interactive graph generator |

## New in v1.2

### Advanced Features Added

| Feature | Module | Description |
|---------|--------|-------------|
| Native Fingerprinting | `fingerprinting.py` | TECH_PATTERNS engine + MurmurHash3 favicon mapping |
| Nuclei Integration | `vulnerability_scanner.py` | Optional vulnerability scan and severity tracking |
| URL Intelligence | `reporter_modern.py` | High-interest URL detection, priority badges, smart grouping |
| Execution Jitter | `subdomain_discovery.py` | 0.5-2s random delays for rate limiting protection |
| Stealth Headers | `utils.py`, `http_probe.py`, `screenshots.py` | 15+ User-Agent rotation, fake referers |
| Forensic Audit Logging | `logger.py` | scan_log.txt with phase tracking and findings summary |
| Smart Grouping | `reporter_modern.py` | Collapsible "Show More" toggle for grouped URLs |
| Error Tracing | `logger.py` | HTTP status code and exception type capture |

## Output Structure

### Per-Domain Output (`output/<domain>/`)

Generated during scan execution:

| File | Content |
|------|---------|
| `subdomains.txt` | All discovered subdomains |
| `live_hosts.txt` | Responsive HTTP hosts |
| `urls.txt` | Discovered URLs from all sources |
| `parameters.txt` | URL parameters with example URLs |
| `apis.txt` | API endpoints with status codes |
| `js_analysis.txt` | JS endpoints and secrets |
| `secrets.txt` | Potential credentials/tokens |
| `sensitive_files.txt` | Exposed sensitive files |
| `cloud_assets.txt` | S3 buckets, Azure blobs, etc. |
| `fingerprints.txt` | Technology per host |
| `nuclei_results.json` | Raw Nuclei JSON findings (when `--nuclei` is used) |
| `prioritized_targets.txt` | Risk-scored target rankings |
| `scan_log.txt` | Forensic audit log with phase tracking |
| `screenshots/*.png` | Webpage screenshots |

### Reports (`reports/`)

| File | Generated By | Description |
|------|--------------|-------------|
| `<domain>_modern.html` | `reporter_modern.py` | Bootstrap dark theme (default) |
| `<domain>_report.html` | `reporter.py` | Classic simple HTML (`--simple`) |

### Graphs (`graphs/`)

| File | Description |
|------|---------------|
| `<domain>_graph.html` | Interactive D3.js visualization |
| `<domain>_graph.json` | Machine-readable graph data |

## Configuration

### Settings (`config/settings.py`)

Key configuration options:

```python
DEFAULT_TIMEOUT = 15          # HTTP timeout (seconds)
DEFAULT_THREADS = 20          # Concurrent threads
MAX_URLS_PER_HOST = 10000   # Wayback Machine limit
MAX_CRAWL_DEPTH = 2          # Live crawler depth
SCREENSHOT_TIMEOUT = 60         # Firefox screenshot timeout
CRITICAL_THRESHOLD = 80         # Risk score for CRITICAL priority
HIGH_THRESHOLD = 60             # Risk score for HIGH priority
```

## Runtime Flow

```
reco_nova.py
    ├── Parse CLI args (--simple, --debug, etc.)
    ├── Load targets (single domain or file)
    └── For each domain:
        └── scan_engine.py::_scan_domain()
            ├── Phase 1: subdomain_discovery.py
            ├── Phase 2: http_probe.py
            ├── Phase 3: url_discovery.py
            ├── Phase 4: js_intelligence.py
            ├── Phase 5: sensitive_assets.py
            ├── Phase 6: fingerprinting.py (if available)
            ├── Phase 7: screenshots.py
            └── Report: reporter_modern.py (or reporter.py with --simple)
                └── Graph: correlation_modern.py (if --graph)
```

## Extension Points

### Adding New Modules

1. Create module in `modules/` following async pattern
2. Import in `core/scan_engine.py`
3. Add phase call in `_scan_domain()`
4. Update this documentation

### Custom Reporting

- Modify `core/reporter_modern.py` for modern reports
- Modify `core/reporter.py` for classic reports
- Both receive identical data dictionaries

## File Sizes (Typical)

| Output | Small Site | Medium Site | Large Site |
|--------|-----------|-------------|------------|
| subdomains.txt | ~50 KB | ~500 KB | ~5 MB |
| urls.txt | ~100 KB | ~2 MB | ~20 MB |
| screenshots/ | ~5 MB | ~50 MB | ~200 MB |
| report.html | ~100 KB | ~500 KB | ~2 MB |
| graph.html | ~50 KB | ~200 KB | ~1 MB |

---

**Version**: 1.2  
**Last Updated**: March 2026  
**Maintainer**: Daniyal Shahid
