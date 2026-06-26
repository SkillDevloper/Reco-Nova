"""
Modern HTML Report Generator with Bootstrap Dark Theme.
Generates a responsive, professional HTML report with Bootstrap 5.
"""

import json
from pathlib import Path
from datetime import datetime
from core.logger import get_logger

logger = get_logger("reporter")


class Reporter:
    def __init__(self, domain: str, output_dir: str = "output"):
        self.domain = domain
        self.output_dir = Path(output_dir) / domain
        self.report_dir = Path("reports")
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, subdomains=None, live_hosts=None, api_endpoints=None,
                 urls=None, parameters=None, js_results=None,
                 sensitive_findings=None, cloud_assets=None, fingerprints=None,
                 param_findings=None, prioritized=None, correlated=None):
        """Generate modern Bootstrap HTML report."""
        
        # Load from files if not passed directly
        subdomains = subdomains or self._read_list("subdomains.txt")
        live_hosts = live_hosts or self._read_list("live_hosts.txt")
        api_endpoints = api_endpoints or self._read_list("apis.txt")
        urls = urls or self._read_list("urls.txt")
        sensitive_findings = sensitive_findings or []
        cloud_assets = cloud_assets or self._read_list("cloud_assets.txt")
        param_findings = param_findings or []
        prioritized = prioritized or []
        js_results = js_results or []
        correlated = correlated or {}

        critical_targets = [t for t in prioritized if t.priority == "CRITICAL"]
        high_targets = [t for t in prioritized if t.priority == "HIGH"]
        total_secrets = sum(len(r.secrets) for r in js_results) if js_results else 0

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = self._build_modern_html(
            domain=self.domain,
            timestamp=timestamp,
            subdomains=subdomains,
            live_hosts=live_hosts,
            api_endpoints=api_endpoints,
            urls=urls,
            sensitive_findings=sensitive_findings,
            cloud_assets=cloud_assets,
            param_findings=param_findings,
            critical_targets=critical_targets,
            high_targets=high_targets,
            total_secrets=total_secrets,
            correlated=correlated,
        )

        out_file = self.report_dir / f"{self.domain}_modern.html"
        out_file.write_text(html)
        logger.info(f"Modern report saved: {out_file}")
        print(f"\n  [+] Modern Report: {out_file}")

    def _read_list(self, filename: str) -> list:
        """Read list from file."""
        f = self.output_dir / filename
        if f.exists():
            return [l for l in f.read_text().splitlines() if l.strip()]
        return []

    def _build_modern_html(self, domain, timestamp, subdomains, live_hosts,
                           api_endpoints, urls, sensitive_findings, cloud_assets,
                           param_findings, critical_targets, high_targets,
                           total_secrets, correlated):
        """Build premium cybersec HTML report — Bug Hunter Edition."""

        parameters = []
        secrets = total_secrets
        vulnerabilities = len(param_findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RECO-NOVA | {domain} — Offensive Intelligence Report</title>

    <!-- Google Fonts: Rajdhani + JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <!-- DataTables -->
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css">

    <style>
        /* ── Base ──────────────────────────────────────────────── */
        :root {{
            --bg:       #0a0a0a;
            --bg2:      #0f0f13;
            --bg3:      #14141a;
            --border:   #1e1e2a;
            --neon:     #39FF14;
            --orange:   #FF8C00;
            --red:      #FF2D55;
            --cyan:     #00D4FF;
            --gold:     #FFD60A;
            --text:     #d4d4d8;
            --text-dim: #52525b;
            --card-bg:  rgba(20,20,26,0.85);
        }}
        *, *::before, *::after {{ box-sizing: border-box; }}

        html {{ scroll-behavior: smooth; }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Rajdhani', system-ui, sans-serif;
            font-size: 15px;
            margin: 0;
            min-height: 100vh;
        }}

        /* ── Scanline overlay on hero ──────────────────────────── */
        @keyframes scanline {{
            0%   {{ transform: translateY(-100%); }}
            100% {{ transform: translateY(100vh); }}
        }}
        .scanline {{
            pointer-events: none;
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(to bottom, transparent, rgba(57,255,20,.12), transparent);
            animation: scanline 6s linear infinite;
            z-index: 9999;
        }}

        /* ── Sidebar ───────────────────────────────────────────── */
        .sidebar {{
            position: fixed;
            left: 0; top: 0; bottom: 0;
            width: 220px;
            background: var(--bg2);
            border-right: 1px solid var(--border);
            padding: 80px 0 20px;
            z-index: 100;
            overflow-y: auto;
        }}
        .sidebar-brand {{
            position: absolute;
            top: 0; left: 0; right: 0;
            padding: 14px 16px;
            background: var(--bg);
            border-bottom: 2px solid var(--neon);
            font-size: 1rem;
            font-weight: 700;
            letter-spacing: 2px;
            color: var(--neon);
        }}
        .sidebar-brand span {{ color: var(--orange); }}
        .sidebar-nav {{ list-style: none; padding: 8px 0; margin: 0; }}
        .sidebar-nav li a {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 18px;
            color: var(--text-dim);
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all .2s;
            border-left: 3px solid transparent;
        }}
        .sidebar-nav li a:hover,
        .sidebar-nav li a.active {{
            color: var(--neon);
            border-left-color: var(--neon);
            background: rgba(57,255,20,.06);
        }}
        .sidebar-nav li a i {{ font-size: 1rem; }}
        .sidebar-section {{
            padding: 14px 18px 4px;
            font-size: 0.65rem;
            letter-spacing: 2px;
            color: var(--text-dim);
            text-transform: uppercase;
        }}

        /* ── Main Wrapper ──────────────────────────────────────── */
        .main-wrapper {{
            margin-left: 220px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}

        /* ── Top Navbar ────────────────────────────────────────── */
        .top-nav {{
            position: sticky;
            top: 0;
            z-index: 90;
            background: rgba(10,10,10,.95);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 10px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .top-nav-brand {{
            font-size: 1.15rem;
            font-weight: 700;
            letter-spacing: 3px;
            color: var(--neon);
        }}
        .top-nav-brand span {{ color: var(--orange); }}
        .top-nav-meta {{
            font-size: 0.75rem;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
            display: flex;
            gap: 20px;
        }}
        .top-nav-meta b {{ color: var(--text); }}

        /* ── Hero Banner ───────────────────────────────────────── */
        .hero-banner {{
            position: relative;
            background: linear-gradient(135deg, #0a0e0f 0%, #0a0a0a 50%, #0d0a00 100%);
            border-bottom: 1px solid var(--border);
            padding: 32px 28px;
            overflow: hidden;
        }}
        .hero-banner::before {{
            content: '';
            position: absolute;
            inset: 0;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(57,255,20,.04) 40px),
                repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(57,255,20,.04) 40px);
        }}
        .hero-title {{
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: 4px;
            color: var(--neon);
            text-shadow: 0 0 20px rgba(57,255,20,.4);
            margin: 0;
        }}
        .hero-title span {{ color: var(--orange); }}
        .hero-subtitle {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: var(--text-dim);
            margin-top: 6px;
        }}
        .hero-subtitle b {{ color: var(--orange); }}
        .hero-badges {{ margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }}
        .hbadge {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            padding: 3px 10px;
            border-radius: 3px;
            border: 1px solid;
            font-weight: 600;
        }}
        .hbadge-green  {{ color: var(--neon);   border-color: var(--neon);   background: rgba(57,255,20,.08); }}
        .hbadge-orange {{ color: var(--orange);  border-color: var(--orange); background: rgba(255,140,0,.08); }}
        .hbadge-red    {{ color: var(--red);     border-color: var(--red);    background: rgba(255,45,85,.08); }}
        .hbadge-cyan   {{ color: var(--cyan);    border-color: var(--cyan);   background: rgba(0,212,255,.08); }}

        /* ── Content area ──────────────────────────────────────── */
        .content-area {{ padding: 24px 28px; flex: 1; }}

        /* ── Section headings ──────────────────────────────────── */
        .section-heading {{
            font-size: 0.65rem;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--text-dim);
            margin: 28px 0 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section-heading::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: var(--border);
        }}

        /* ── Cards ─────────────────────────────────────────────── */
        .rn-card {{
            background: var(--card-bg);
            backdrop-filter: blur(8px);
            border: 1px solid var(--border);
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: border-color .2s, box-shadow .2s;
        }}
        .rn-card:hover {{
            border-color: rgba(57,255,20,.25);
            box-shadow: 0 0 18px rgba(57,255,20,.06);
        }}
        .rn-card-header {{
            background: rgba(255,255,255,.025);
            border-bottom: 1px solid var(--border);
            padding: 12px 16px;
            font-weight: 700;
            font-size: 0.8rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--neon);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .rn-card-header.orange {{ color: var(--orange); }}
        .rn-card-header.red    {{ color: var(--red);    }}
        .rn-card-header.cyan   {{ color: var(--cyan);   }}
        .rn-card-body {{ padding: 16px; }}

        /* ── Stat cards ────────────────────────────────────────── */
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 18px 20px;
            position: relative;
            overflow: hidden;
            transition: transform .2s, border-color .2s;
        }}
        .stat-card::before {{
            content: '';
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 3px;
        }}
        .stat-card.green::before  {{ background: var(--neon);   }}
        .stat-card.orange::before {{ background: var(--orange); }}
        .stat-card.cyan::before   {{ background: var(--cyan);   }}
        .stat-card.red::before    {{ background: var(--red);    }}
        .stat-card:hover {{
            transform: translateY(-3px);
            border-color: rgba(57,255,20,.3);
        }}
        .stat-number {{
            font-size: 2rem;
            font-weight: 700;
            line-height: 1;
            font-family: 'Rajdhani', sans-serif;
        }}
        .stat-number.green  {{ color: var(--neon);   text-shadow: 0 0 12px rgba(57,255,20,.4); }}
        .stat-number.orange {{ color: var(--orange); text-shadow: 0 0 12px rgba(255,140,0,.4); }}
        .stat-number.cyan   {{ color: var(--cyan);   text-shadow: 0 0 12px rgba(0,212,255,.4); }}
        .stat-number.red    {{ color: var(--red);    text-shadow: 0 0 12px rgba(255,45,85,.4);  }}
        .stat-label {{
            font-size: 0.68rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-top: 4px;
        }}
        .stat-icon {{
            position: absolute;
            top: 14px; right: 16px;
            font-size: 1.6rem;
            opacity: .12;
        }}

        /* ── Tables ────────────────────────────────────────────── */
        .rn-table {{ width: 100%; border-collapse: collapse; }}
        .rn-table th {{
            background: rgba(255,255,255,.04);
            color: var(--text-dim);
            font-size: 0.65rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            padding: 9px 14px;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }}
        .rn-table td {{
            padding: 9px 14px;
            border-bottom: 1px solid rgba(30,30,42,.8);
            vertical-align: middle;
            font-size: 0.82rem;
        }}
        .rn-table tr:hover td {{
            background: rgba(57,255,20,.04);
        }}
        .rn-table td a {{
            color: var(--cyan);
            text-decoration: none;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
        }}
        .rn-table td a:hover {{ color: var(--neon); }}
        .rn-table td code {{
            background: rgba(255,255,255,.06);
            color: var(--orange);
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ── Severity pills ────────────────────────────────────── */
        .pill {{
            display: inline-block;
            padding: 2px 9px;
            border-radius: 3px;
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid;
        }}
        .pill-critical {{ color: var(--red);    border-color: var(--red);    background: rgba(255,45,85,.12); }}
        .pill-high     {{ color: var(--orange); border-color: var(--orange); background: rgba(255,140,0,.12); }}
        .pill-medium   {{ color: var(--gold);   border-color: var(--gold);   background: rgba(255,214,10,.12); }}
        .pill-low      {{ color: #64748b;       border-color: #334155;       background: rgba(100,116,139,.08); }}
        .pill-normal   {{ color: #475569;       border-color: #334155;       background: rgba(71,85,105,.08); }}

        /* ── Hunter target card (pulsing red) ──────────────────── */
        @keyframes glow-pulse {{
            0%, 100% {{ box-shadow: 0 0 12px rgba(255,45,85,.3); }}
            50%       {{ box-shadow: 0 0 28px rgba(255,45,85,.6); }}
        }}
        .hunter-card {{
            background: rgba(20,5,8,.9);
            border: 1px solid rgba(255,45,85,.4);
            border-radius: 6px;
            animation: glow-pulse 3s ease-in-out infinite;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .hunter-header {{
            background: linear-gradient(135deg, rgba(255,45,85,.18), rgba(10,10,10,0));
            border-bottom: 1px solid rgba(255,45,85,.3);
            padding: 13px 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .hunter-title {{
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--red);
        }}
        .hunter-body {{ padding: 16px 18px; }}
        .hunter-meta {{
            font-size: 0.72rem;
            color: var(--text-dim);
            margin-bottom: 14px;
        }}

        /* ── Screenshot masonry ────────────────────────────────── */
        .ss-masonry {{
            column-count: 3;
            column-gap: 14px;
        }}
        @media (max-width: 1100px) {{ .ss-masonry {{ column-count: 2; }} }}
        @media (max-width: 700px)  {{ .ss-masonry {{ column-count: 1; }} }}
        .ss-item {{
            break-inside: avoid;
            margin-bottom: 14px;
            border-radius: 5px;
            overflow: hidden;
            cursor: pointer;
            border: 1px solid var(--border);
            transition: transform .2s, border-color .2s;
            position: relative;
        }}
        .ss-item:hover {{
            transform: scale(1.025);
            border-color: var(--neon);
        }}
        .ss-item img {{ width: 100%; display: block; }}
        .ss-overlay {{
            position: absolute;
            bottom: 0; left: 0; right: 0;
            background: linear-gradient(transparent, rgba(0,0,0,.85));
            padding: 18px 10px 8px;
            font-size: 0.68rem;
            font-family: 'JetBrains Mono', monospace;
            color: #a3a3a3;
            opacity: 0;
            transition: opacity .2s;
        }}
        .ss-item:hover .ss-overlay {{ opacity: 1; }}

        /* ── Lightbox ──────────────────────────────────────────── */
        .lightbox-backdrop {{
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,.92);
            z-index: 9000;
            justify-content: center;
            align-items: center;
        }}
        .lightbox-backdrop.active {{ display: flex; }}
        .lightbox-img {{
            max-width: 90vw;
            max-height: 88vh;
            border-radius: 4px;
            border: 1px solid var(--neon);
            box-shadow: 0 0 40px rgba(57,255,20,.2);
        }}
        .lightbox-close {{
            position: absolute;
            top: 20px; right: 28px;
            font-size: 2rem;
            color: var(--text);
            cursor: pointer;
            line-height: 1;
        }}
        .lightbox-caption {{
            position: absolute;
            bottom: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
        }}

        /* ── Priority rows ─────────────────────────────────────── */
        .row-high td {{ border-left: 3px solid var(--red); }}
        .row-normal td {{ border-left: 3px solid transparent; }}

        /* ── DataTables overrides ──────────────────────────────── */
        .dataTables_wrapper .dataTables_filter input,
        .dataTables_wrapper .dataTables_length select {{
            background: var(--bg3);
            border: 1px solid var(--border);
            color: var(--text);
            border-radius: 3px;
            padding: 3px 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
        }}
        .dataTables_wrapper .dataTables_info {{ color: var(--text-dim); font-size: 0.75rem; }}
        .dataTables_wrapper .dataTables_paginate .paginate_button {{
            background: var(--bg3) !important;
            border: 1px solid var(--border) !important;
            color: var(--text-dim) !important;
            border-radius: 3px !important;
        }}
        .dataTables_wrapper .dataTables_paginate .paginate_button.current,
        .dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
            background: rgba(57,255,20,.1) !important;
            border-color: var(--neon) !important;
            color: var(--neon) !important;
        }}

        /* ── Footer ────────────────────────────────────────────── */
        .rn-footer {{
            margin-left: 0;
            border-top: 1px solid var(--border);
            padding: 16px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg2);
        }}
        .rn-footer-left {{
            font-size: 0.72rem;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
        }}
        .rn-footer-left b {{ color: var(--neon); }}
        .rn-footer-right {{
            font-size: 0.68rem;
            color: var(--text-dim);
            text-align: right;
        }}
        .rn-footer-right b {{ color: var(--orange); }}

        /* ── Count-up animation ──────────────────────────────── */
        @keyframes count-in {{
            from {{ opacity: 0; transform: translateY(6px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
        .stat-number {{ animation: count-in .5s ease both; }}
    </style>
</head>
<body>
<!-- Scanline FX -->
<div class="scanline"></div>

<!-- Sidebar Navigation -->
<nav class="sidebar">
    <div class="sidebar-brand">RECO<span>-NOVA</span></div>
    <div class="sidebar-section">Navigation</div>
    <ul class="sidebar-nav">
        <li><a href="#section-summary">   <i class="bi bi-speedometer2"></i> Summary</a></li>
        <li><a href="#section-hunter">    <i class="bi bi-crosshair"></i>    Priority Targets</a></li>
        <li><a href="#section-sensitive"> <i class="bi bi-file-lock"></i>    Sensitive Files</a></li>
        <li><a href="#section-params">    <i class="bi bi-code-slash"></i>   Parameters</a></li>
        <li><a href="#section-urls">      <i class="bi bi-link-45deg"></i>   Discovered URLs</a></li>
        <li><a href="#section-screenshots"><i class="bi bi-image"></i>       Screenshots</a></li>
        <li><a href="#section-corr">      <i class="bi bi-diagram-3"></i>    Correlation</a></li>
    </ul>
</nav>

<!-- Main Wrapper -->
<div class="main-wrapper">

    <!-- Top Nav -->
    <div class="top-nav">
        <div class="top-nav-brand">RECO<span>-NOVA</span></div>
        <div class="top-nav-meta">
            <span>TARGET: <b>{domain}</b></span>
            <span>GENERATED: <b>{timestamp}</b></span>
            <span>MODE: <b>OFFENSIVE</b></span>
        </div>
    </div>

    <!-- Hero Banner -->
    <div class="hero-banner" id="section-summary">
        <h1 class="hero-title">RECO-NOVA | <span>Offensive Intelligence Report</span></h1>
        <div class="hero-subtitle">
            Target: <b>{domain}</b> &nbsp;|&nbsp;
            Lead Auditor: <b>Daniyal Shahid (CEH v13)</b> &nbsp;|&nbsp;
            Classification: <b style="color:var(--red)">CONFIDENTIAL</b>
        </div>
        <div class="hero-badges">
            <span class="hbadge hbadge-green">&#x2714; {len(live_hosts)} Live Hosts</span>
            <span class="hbadge hbadge-cyan">&#x25C9; {len(subdomains)} Subdomains</span>
            <span class="hbadge hbadge-orange">&#x26A0; {len(param_findings)} Vuln Params</span>
            <span class="hbadge hbadge-red">&#x1F511; {total_secrets} Secrets Found</span>
            <span class="hbadge hbadge-orange">&#x1F4CE; {len(urls)} URLs Discovered</span>
        </div>
    </div>

    <!-- Content Area -->
    <div class="content-area">

        <!-- Scan Summary Stats -->
        <div class="section-heading"><i class="bi bi-speedometer2"></i> Scan Summary</div>
        <div class="stat-grid">
            <div class="stat-card green">
                <div class="stat-number green" data-count="{len(live_hosts)}">0</div>
                <div class="stat-label">Live Hosts</div>
                <i class="bi bi-hdd-network stat-icon"></i>
            </div>
            <div class="stat-card cyan">
                <div class="stat-number cyan" data-count="{len(subdomains)}">0</div>
                <div class="stat-label">Subdomains</div>
                <i class="bi bi-diagram-3 stat-icon"></i>
            </div>
            <div class="stat-card orange">
                <div class="stat-number orange" data-count="{len(urls)}">0</div>
                <div class="stat-label">URLs Found</div>
                <i class="bi bi-link-45deg stat-icon"></i>
            </div>
            <div class="stat-card red">
                <div class="stat-number red" data-count="{total_secrets}">0</div>
                <div class="stat-label">Secrets / Leaks</div>
                <i class="bi bi-key stat-icon"></i>
            </div>
            <div class="stat-card orange">
                <div class="stat-number orange" data-count="{len(param_findings)}">0</div>
                <div class="stat-label">Vuln Parameters</div>
                <i class="bi bi-code-slash stat-icon"></i>
            </div>
            <div class="stat-card red">
                <div class="stat-number red" data-count="{len(sensitive_findings)}">0</div>
                <div class="stat-label">Sensitive Files</div>
                <i class="bi bi-file-lock stat-icon"></i>
            </div>
        </div>

        <!-- Critical & High Priority Targets -->
        {self._build_priority_section(critical_targets, high_targets)}

        <!-- Bug Hunter: Dangerous Parameter Targets -->
        <div id="section-hunter">
        {self._build_hunter_targets_section(urls)}
        </div>

        <!-- Sensitive Files + Vulnerable Parameters -->
        <div class="section-heading"><i class="bi bi-file-lock"></i> Findings</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;" id="section-sensitive">
            {self._build_sensitive_table(sensitive_findings[:20])}
            <div id="section-params">
            {self._build_parameters_table(param_findings[:30])}
            </div>
        </div>

        <!-- URLs Section -->
        <div id="section-urls">
        {self._build_urls_section(urls)}
        </div>

        <!-- Screenshots Gallery -->
        <div id="section-screenshots">
        {self._build_screenshots_gallery()}
        </div>

        <!-- Correlated Intelligence -->
        <div id="section-corr">
        {self._build_correlation_section(correlated)}
        </div>

    </div><!-- /content-area -->

    <!-- Footer -->
    <footer class="rn-footer">
        <div class="rn-footer-left">
            Generated by <b>Reco-Nova v1.2 Framework</b> &nbsp;|&nbsp;
            Lead Auditor: <b style="color:var(--orange)">Daniyal Shahid (CEH v13)</b>
        </div>
        <div class="rn-footer-right">
            <b>CONFIDENTIAL</b> — For Authorized Use Only<br>
            <span style="color:#27272a;">{timestamp}</span>
        </div>
    </footer>

</div><!-- /main-wrapper -->

<!-- Lightbox -->
<div class="lightbox-backdrop" id="lightbox" onclick="closeLightbox(event)">
    <span class="lightbox-close" onclick="closeLightbox()">&#x2715;</span>
    <img class="lightbox-img" id="lb-img" src="" alt="">
    <div class="lightbox-caption" id="lb-cap"></div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
<script>
// ── Count-up animation ─────────────────────────────────────────────
function animateCountUp(el) {{
    const target = parseInt(el.dataset.count, 10) || 0;
    if (target === 0) {{ el.textContent = '0'; return; }}
    const duration = 900;
    const step = Math.ceil(target / (duration / 20));
    let current = 0;
    const timer = setInterval(() => {{
        current = Math.min(current + step, target);
        el.textContent = current.toLocaleString();
        if (current >= target) clearInterval(timer);
    }}, 20);
}}
document.querySelectorAll('.stat-number[data-count]').forEach(animateCountUp);

// ── Sidebar active link ────────────────────────────────────────────
const sections = document.querySelectorAll('[id^="section-"]');
const navLinks  = document.querySelectorAll('.sidebar-nav a');
const observer  = new IntersectionObserver(entries => {{
    entries.forEach(e => {{
        if (e.isIntersecting) {{
            navLinks.forEach(a => a.classList.remove('active'));
            const link = document.querySelector('.sidebar-nav a[href="#' + e.target.id + '"]');
            if (link) link.classList.add('active');
        }}
    }});
}}, {{ rootMargin: '-20% 0px -60% 0px' }});
sections.forEach(s => observer.observe(s));

// ── Lightbox ───────────────────────────────────────────────────────
function openLightbox(img) {{
    document.getElementById('lb-img').src = img.src;
    document.getElementById('lb-cap').textContent = img.alt || img.title || '';
    document.getElementById('lightbox').classList.add('active');
}}
function closeLightbox(e) {{
    if (!e || e.target === e.currentTarget || e.target.classList.contains('lightbox-close')) {{
        document.getElementById('lightbox').classList.remove('active');
    }}
}}
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeLightbox(); }});

// ── DataTables ─────────────────────────────────────────────────────
$(document).ready(function() {{
    if ($('#urlsTable').length) {{
        var urlsTable = $('#urlsTable').DataTable({{
            "pageLength": 25,
            "order": [[1, "desc"], [0, "asc"]],
            "responsive": true,
        }});
        window.filterHighPriority = function() {{ urlsTable.column(1).search('HIGH').draw(); }};
        window.showAllUrls = function() {{ urlsTable.column(1).search('').draw(); }};
        window.toggleGroup = function(groupId) {{
            var hidden = $('.' + groupId + '-hidden');
            var isHidden = hidden.first().is(':hidden');
            hidden.toggle();
            var btn = event.currentTarget;
            btn.innerHTML = isHidden
                ? '<i class="bi bi-chevron-up"></i> Show less'
                : '<i class="bi bi-chevron-down"></i> Show more';
        }};
    }}
    if ($('#parametersTable').length) {{
        $('#parametersTable').DataTable({{ "pageLength": 50, "order": [[0, "asc"]] }});
    }}
}});
</script>
</body>
</html>"""



    def _build_priority_section(self, critical_targets, high_targets):
        """Build critical and high priority targets section."""
        if not critical_targets and not high_targets:
            return ""
        
        return f"""
        <!-- Critical & High Priority Targets -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <i class="bi bi-exclamation-triangle-fill text-danger"></i>
                        Priority Targets ({len(critical_targets) + len(high_targets)})
                    </div>
                    <div class="card-body">
                        {self._build_priority_table(critical_targets, high_targets)}
                    </div>
                </div>
            </div>
        </div>
        """

    def _build_priority_table(self, critical_targets, high_targets):
        """Build priority targets table."""
        if not critical_targets and not high_targets:
            return ""
        
        rows = ""
        for target in critical_targets[:10]:
            reasons = "; ".join(target.reasons[:2])
            rows += f"""
                <tr>
                    <td><span class="badge bg-danger">CRITICAL</span></td>
                    <td><a href="{target.url}" target="_blank" class="text-decoration-none">{target.url}</a></td>
                    <td>{target.risk_score}/100</td>
                    <td><small>{reasons}</small></td>
                </tr>
            """
        
        for target in high_targets[:10]:
            reasons = "; ".join(target.reasons[:2])
            rows += f"""
                <tr>
                    <td><span class="badge bg-warning">HIGH</span></td>
                    <td><a href="{target.url}" target="_blank" class="text-decoration-none">{target.url}</a></td>
                    <td>{target.risk_score}/100</td>
                    <td><small>{reasons}</small></td>
                </tr>
            """
        
        return f"""
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>Priority</th>
                            <th>Target</th>
                            <th>Risk Score</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        """

    def _build_sensitive_table(self, sensitive_findings):
        """Build sensitive files table."""
        if not sensitive_findings:
            return ""
        
        rows = ""
        for finding in sensitive_findings:
            severity_class = {
                "Critical": "danger",
                "High": "warning", 
                "Medium": "info",
                "Low": "secondary"
            }.get(finding.get("severity", "Medium"), "info")
            
            rows += f"""
                <tr>
                    <td><span class="badge bg-{severity_class}">{finding.get('severity', 'Medium')}</span></td>
                    <td><a href="{finding['url']}" target="_blank" class="text-decoration-none">{finding['url']}</a></td>
                    <td>{finding.get('status', 'Unknown')}</td>
                </tr>
            """
        
        return f"""
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-file-lock"></i>
                    Sensitive Files ({len(sensitive_findings)})
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>URL</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        """

    def _build_parameters_table(self, param_findings):
        """Build parameters table."""
        if not param_findings:
            return """
            <div class="card mb-4">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0"><i class="bi bi-code-slash"></i> Vulnerable Parameters</h5>
                </div>
                <div class="card-body bg-secondary text-center">
                    <p class="text-muted mb-0">
                        <i class="bi bi-info-circle"></i> No vulnerable parameters discovered during scan
                    </p>
                </div>
            </div>
            """
        
        rows = ""
        for param in param_findings:
            severity_class = {
                "Critical": "danger",
                "High": "warning",
                "Medium": "info", 
                "Low": "secondary"
            }.get(param.severity, "info")
            
            rows += f"""
                <tr>
                    <td><code>{param.param}</code></td>
                    <td>{param.vuln_type}</td>
                    <td><span class="badge bg-{severity_class}">{param.severity}</span></td>
                </tr>
            """
        
        return f"""
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-code-slash"></i>
                    Vulnerable Parameters ({len(param_findings)})
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th>Parameter</th>
                                    <th>Vulnerability Type</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        """

    def _build_screenshots_gallery(self):
        """Build masonry screenshot gallery with zoom-on-click lightbox."""
        screenshot_dir = self.output_dir / "screenshots"
        if not screenshot_dir.exists():
            return ""

        screenshots = list(screenshot_dir.glob("*.png"))
        if not screenshots:
            return ""

        items = ""
        for screenshot in screenshots:
            items += f"""
                <div class="ss-item" onclick="openLightbox(this.querySelector('img'))">
                    <img src="{screenshot}" alt="{screenshot.name}" loading="lazy">
                    <div class="ss-overlay">
                        <i class="bi bi-zoom-in"></i> {screenshot.name}
                    </div>
                </div>
            """

        return f"""
            <div class="rn-card">
                <div class="rn-card-header cyan">
                    <i class="bi bi-image"></i>
                    Screenshots Gallery
                    <span style="margin-left:auto;font-weight:400;font-size:0.7rem;color:var(--text-dim);">{len(screenshots)} captures</span>
                </div>
                <div class="rn-card-body">
                    <div class="ss-masonry">
                        {items}
                    </div>
                </div>
            </div>
        """



    def _build_urls_section(self, urls):
        """Build URLs section with DataTables and Intelligence Layer."""
        if not urls:
            return """
            <div class="card mb-4">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0"><i class="bi bi-link-45deg"></i> Discovered URLs</h5>
                </div>
                <div class="card-body bg-secondary text-center">
                    <p class="text-muted mb-0">
                        <i class="bi bi-info-circle"></i> No URLs discovered during scan
                    </p>
                </div>
            </div>
            """
        
        # Categorize URLs by priority
        high_interest_urls = []
        normal_urls = []
        
        for url in urls[:200]:  # Limit to 200 URLs for performance
            if self._is_high_interest_url(url):
                high_interest_urls.append(url)
            else:
                normal_urls.append(url)
        
        # Smart Grouping: Group high-interest URLs by directory
        grouped_urls = self._group_urls_by_directory(high_interest_urls)
        
        # Build rows with smart grouping
        rows = ""
        row_counter = 0
        
        # Process grouped URLs
        for group_key, group_urls in grouped_urls.items():
            if len(group_urls) > 10:
                # Show first 10, collapse the rest
                visible_urls = group_urls[:10]
                hidden_urls = group_urls[10:]
                group_id = f"group_{hash(group_key) % 10000}"
                
                # Visible rows
                for url in visible_urls:
                    row_counter += 1
                    priority_tags = self._get_priority_tags(url)
                    rows += f"""
                        <tr class="high-interest-row">
                            <td>{row_counter}</td>
                            <td><span class="badge bg-danger priority-badge">HIGH</span></td>
                            <td><a href="{url}" target="_blank" class="text-decoration-none text-warning">{url}</a></td>
                            <td><small>{self._extract_domain(url)}</small></td>
                            <td><small class="text-info">{', '.join(priority_tags)}</small></td>
                        </tr>
                    """
                
                # Hidden rows (collapsible)
                hidden_rows = ""
                for url in hidden_urls:
                    row_counter += 1
                    priority_tags = self._get_priority_tags(url)
                    hidden_rows += f"""
                        <tr class="high-interest-row hidden-group-row {group_id}-hidden" style="display:none;">
                            <td>{row_counter}</td>
                            <td><span class="badge bg-danger priority-badge">HIGH</span></td>
                            <td><a href="{url}" target="_blank" class="text-decoration-none text-warning">{url}</a></td>
                            <td><small>{self._extract_domain(url)}</small></td>
                            <td><small class="text-info">{', '.join(priority_tags)}</small></td>
                        </tr>
                    """
                
                rows += hidden_rows
                
                # Show More toggle row
                rows += f"""
                    <tr class="table-secondary">
                        <td colspan="5" class="text-center">
                            <button class="btn btn-sm btn-outline-warning" onclick="toggleGroup('{group_id}')">
                                <i class="bi bi-chevron-down"></i> Show {len(hidden_urls)} more in {group_key}
                            </button>
                        </td>
                    </tr>
                """
            else:
                # Show all URLs in group (10 or less)
                for url in group_urls:
                    row_counter += 1
                    priority_tags = self._get_priority_tags(url)
                    rows += f"""
                        <tr class="high-interest-row">
                            <td>{row_counter}</td>
                            <td><span class="badge bg-danger priority-badge">HIGH</span></td>
                            <td><a href="{url}" target="_blank" class="text-decoration-none text-warning">{url}</a></td>
                            <td><small>{self._extract_domain(url)}</small></td>
                            <td><small class="text-info">{', '.join(priority_tags)}</small></td>
                        </tr>
                    """
        
        # Normal rows
        offset = row_counter
        for i, url in enumerate(normal_urls):
            rows += f"""
                <tr>
                    <td>{offset + i + 1}</td>
                    <td><span class="badge bg-secondary priority-badge">NORMAL</span></td>
                    <td><a href="{url}" target="_blank" class="text-decoration-none">{url}</a></td>
                    <td><small>{self._extract_domain(url)}</small></td>
                    <td><small>-</small></td>
                </tr>
            """
        
        # Calculate stats
        high_count = len(high_interest_urls)
        total_count = len(urls)
        
        return f"""
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <i class="bi bi-link-45deg"></i>
                        Discovered URLs ({total_count})
                        <span class="badge bg-danger ms-2">{high_count} High Priority</span>
                    </div>
                    <div>
                        <button class="btn btn-sm btn-outline-danger me-2" onclick="filterHighPriority()">
                            <i class="bi bi-filter"></i> High Priority Only
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="showAllUrls()">
                            <i class="bi bi-list"></i> Show All
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="urlsTable" class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Priority</th>
                                    <th>URL</th>
                                    <th>Domain</th>
                                    <th>Indicators</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <style>
                .high-interest-row {{
                    background-color: rgba(220, 53, 69, 0.15) !important;
                    border-left: 3px solid #dc3545;
                }}
                .high-interest-row:hover {{
                    background-color: rgba(220, 53, 69, 0.25) !important;
                }}
                .priority-badge {{
                    font-size: 0.75rem;
                }}
            </style>
            <script>
                // DataTable and global functions already initialized in main script section
                // No duplicate initialization needed
            </script>
            <script>
                window.toggleGroup = function(groupId) {{
                    var hiddenRows = $('.' + groupId + '-hidden');
                    var isHidden = hiddenRows.first().is(':hidden');
                    
                    if (isHidden) {{
                        hiddenRows.show();
                        event.target.innerHTML = '<i class="bi bi-chevron-up"></i> Show less';
                    }} else {{
                        hiddenRows.hide();
                        var count = hiddenRows.length;
                        var dirName = groupId.replace('group_', 'directory ');
                        event.target.innerHTML = '<i class="bi bi-chevron-down"></i> Show ' + count + ' more';
                    }}
                }};
            </script>
        """

    def _build_all_parameters_section(self, parameters):
        """Build all parameters section with DataTables."""
        if not parameters:
            return ""
        
        rows = ""
        for i, param in enumerate(parameters[:100]):  # Limit to 100 parameters
            rows += f"""
                <tr>
                    <td>{i+1}</td>
                    <td><code>{param}</code></td>
                    <td><small>Parameter</small></td>
                </tr>
            """
        
        return f"""
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-code-slash"></i>
                    URL Parameters ({len(parameters)})
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="parametersTable" class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>Parameter</th>
                                    <th>Type</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <script>
                $(document).ready(function() {{
                    $('#parametersTable').DataTable({{
                        "pageLength": 50,
                        "order": [[ 0, "asc" ]],
                        "responsive": true,
                        "dark": true
                    }});
                }});
            </script>
        """

    def _extract_domain(self, url):
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return "unknown"

    def _is_high_interest_url(self, url: str) -> bool:
        """Determine if a URL is of high interest for security research."""
        url_lower = url.lower()
        
        # Sensitive extensions
        sensitive_extensions = [
            '.php', '.jsp', '.asp', '.aspx', '.env', '.config',
            '.bak', '.sql', '.log', '.ini', '.conf', '.xml',
            '.json', '.yaml', '.yml', '.properties', '.sh',
            '.py', '.rb', '.pl', '.cgi', '.dll', '.exe'
        ]
        
        # High-value keywords
        keywords = [
            'admin', 'login', 'dashboard', 'api', 'v1', 'v2', 'debug',
            'test', 'upload', 'config', 'wp-admin', 'wp-login',
            'phpmyadmin', 'manager', 'console', 'panel', 'backend',
            'dev', 'development', 'staging', 'beta', 'internal',
            'private', 'secret', 'api-docs', 'swagger', 'graphql',
            'rest', 'oauth', 'auth', 'authenticate', 'authorize',
            'account', 'user', 'users', 'register', 'signup',
            'password', 'reset', 'forgot', 'change', 'update',
            'create', 'delete', 'remove', 'edit', 'modify',
            'database', 'db', 'sql', 'query', 'backup', 'export',
            'import', 'download', 'upload', 'file', 'files',
            'media', 'content', 'cms', 'manage', 'system',
            'server', 'status', 'health', 'ping', 'info',
            'version', 'git', 'svn', 'cvs', 'repository'
        ]
        
        # Check extensions
        for ext in sensitive_extensions:
            if ext in url_lower:
                return True
        
        # Check keywords
        for keyword in keywords:
            if keyword in url_lower:
                return True
        
        return False

    # ─────────────────────────────────────────────────────────────────────
    # Bug Hunter: High Priority Targets section
    # ─────────────────────────────────────────────────────────────────────

    # Dangerous URL parameters that warrant immediate attention
    DANGEROUS_PARAMS = [
        "redirect", "url", "id", "file", "path", "src",
    ]
    # Map param → likely vuln class
    PARAM_VULN_MAP = {
        "redirect": "Open Redirect",
        "url":      "Open Redirect / SSRF",
        "id":       "IDOR",
        "file":     "Path Traversal / LFI",
        "path":     "Path Traversal / LFI",
        "src":      "SSRF / Open Redirect",
    }

    def _build_hunter_targets_section(self, urls: list) -> str:
        """Build a Bug-Hunter focussed 'High Priority Targets' section.

        Scans every URL for query-string parameters that often lead to
        critical vulnerabilities (Open Redirect, IDOR, LFI, SSRF …)
        and renders them in a highly visible, highlighted table.
        """
        import re
        from urllib.parse import urlparse, parse_qs

        # Collect hits: (url, matched_param, vuln_class)
        hits: list[tuple[str, str, str]] = []
        seen: set[str] = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for param in self.DANGEROUS_PARAMS:
                    # Match exact param name OR prefixed/suffixed variant
                    # e.g. next_url=, file_path=, return_url= etc.
                    for key in qs:
                        if re.search(rf"(?:^|[_\-]){re.escape(param)}(?:[_\-]|$)", key, re.I):
                            dedup_key = f"{url}|{param}"
                            if dedup_key not in seen:
                                seen.add(dedup_key)
                                vuln = self.PARAM_VULN_MAP.get(param, "High Risk Parameter")
                                hits.append((url, key, vuln))
                            break
            except Exception:
                continue

        if not hits:
            return ""

        rows = ""
        for url, param, vuln in hits[:50]:  # cap at 50 rows for readability
            rows += f"""
                <tr>
                    <td>
                        <a href="{url}" target="_blank"
                           style="word-break:break-all;color:#ff8c00;font-weight:500;">
                            {url}
                        </a>
                    </td>
                    <td><code style="color:#ff4c4c;">{param}</code></td>
                    <td><span class="badge bg-danger">{vuln}</span></td>
                </tr>
            """

        return f"""
        <!-- Bug Hunter: High Priority Targets -->
        <div class="row mb-4" id="hunter-targets">
            <div class="col-12">
                <div class="card" style="border:2px solid #dc3545;box-shadow:0 0 18px rgba(220,53,69,.45);">
                    <div class="card-header"
                         style="background:linear-gradient(135deg,#6e1010,#1a1a1a);">
                        <span style="color:#ff4c4c;font-size:1.1rem;font-weight:700;">
                            &#x1F3AF; High Priority Targets
                        </span>
                        <span class="badge bg-danger ms-2">{len(hits)} URLs with Dangerous Parameters</span>
                        <small class="text-muted ms-3">
                            Params flagged: redirect=, url=, id=, file=, path=, src=
                        </small>
                    </div>
                    <div class="card-body" style="background:rgba(220,53,69,.06);">
                        <p class="text-muted mb-2" style="font-size:0.85rem;">
                            <i class="bi bi-exclamation-triangle-fill text-warning"></i>
                            These URLs contain parameters commonly exploited for
                            <strong>Open Redirect, IDOR, LFI / Path Traversal, and SSRF</strong>.
                            Test them first.
                        </p>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover"
                                   style="border-left:4px solid #dc3545;">
                                <thead style="background:#2a0808;">
                                    <tr>
                                        <th>&#x1F517; URL</th>
                                        <th>&#x26A0; Dangerous Parameter</th>
                                        <th>Likely Vulnerability</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    def _get_priority_tags(self, url: str) -> list[str]:
        """Get priority indicator tags for a URL."""
        url_lower = url.lower()
        tags = []
        
        # Extension-based tags
        ext_tags = {
            '.php': 'PHP', '.jsp': 'Java', '.asp': 'ASP', '.aspx': '.NET',
            '.env': 'ENV File', '.config': 'Config', '.bak': 'Backup',
            '.sql': 'SQL', '.log': 'Log', '.ini': 'Config',
            '.xml': 'XML', '.json': 'JSON', '.yaml': 'Config',
        }
        
        for ext, tag in ext_tags.items():
            if ext in url_lower:
                tags.append(tag)
                break
        
        # Keyword-based tags
        keyword_tags = {
            'admin': 'Admin Panel', 'login': 'Login', 'dashboard': 'Dashboard',
            'api': 'API', 'v1': 'API v1', 'v2': 'API v2',
            'debug': 'Debug', 'test': 'Test Endpoint', 'upload': 'Upload',
            'config': 'Config', 'wp-admin': 'WordPress', 'phpmyadmin': 'Database',
            'manager': 'Manager', 'console': 'Console', 'panel': 'Panel',
            'backend': 'Backend', 'dev': 'Development', 'staging': 'Staging',
            'internal': 'Internal', 'private': 'Private', 'secret': 'Secret',
            'swagger': 'API Docs', 'graphql': 'GraphQL', 'oauth': 'OAuth',
            'auth': 'Auth', 'password': 'Password', 'reset': 'Password Reset',
            'database': 'Database', 'backup': 'Backup', 'git': 'Git',
        }
        
        for keyword, tag in keyword_tags.items():
            if keyword in url_lower and tag not in tags:
                tags.append(tag)
                if len(tags) >= 3:  # Limit to 3 tags
                    break
        
        return tags

    def _group_urls_by_directory(self, urls: list[str]) -> dict[str, list[str]]:
        """Group URLs by directory for smart collapsing.
        
        Groups URLs that share the same base directory and high-interest tag.
        Returns a dict mapping group keys to lists of URLs.
        """
        from urllib.parse import urlparse
        from collections import defaultdict
        
        groups = defaultdict(list)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path or '/'
                
                # Extract the first significant directory or use the tag as group key
                priority_tags = self._get_priority_tags(url)
                primary_tag = priority_tags[0] if priority_tags else 'Other'
                
                # Get directory path (up to 2 levels deep for grouping)
                path_parts = path.strip('/').split('/')
                if len(path_parts) >= 2:
                    dir_key = f"/{path_parts[0]}/{path_parts[1]}"
                elif len(path_parts) == 1 and path_parts[0]:
                    dir_key = f"/{path_parts[0]}"
                else:
                    dir_key = '/'
                
                # Create group key combining tag and directory
                group_key = f"{primary_tag} → {dir_key}"
                groups[group_key].append(url)
            except Exception:
                # Fallback: group by tag only
                priority_tags = self._get_priority_tags(url)
                primary_tag = priority_tags[0] if priority_tags else 'Other'
                groups[primary_tag].append(url)
        
        # Sort groups by number of URLs (descending) then by key
        sorted_groups = dict(sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])))
        return sorted_groups

    def _build_correlation_section(self, correlated):
        """Build correlated intelligence section."""
        if not correlated:
            return ""
        
        rows = ""
        for url, data in list(correlated.items())[:15]:
            tech = data.get('technology', '—')
            server = data.get('server', '—')
            endpoints = len(data.get('endpoints', []))
            secrets = len(data.get('secrets', []))
            
            rows += f"""
                <tr>
                    <td>{data.get('host', '—')}</td>
                    <td><small>{tech}</small></td>
                    <td><small>{server}</small></td>
                    <td>{endpoints}</td>
                    <td>{secrets}</td>
                </tr>
            """
        
        return f"""
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-diagram-3-fill"></i>
                    Correlated Intelligence ({len(correlated)})
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-dark table-hover">
                            <thead>
                                <tr>
                                    <th>Host</th>
                                    <th>Technology</th>
                                    <th>Server</th>
                                    <th>Endpoints</th>
                                    <th>Secrets</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        """
