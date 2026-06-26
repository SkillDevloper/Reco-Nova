"""
Reporting Engine.
Generates a full HTML report from all scan data.
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
        
        # Initialize parameters at top to prevent NameError
        parameters = parameters or []
        
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

        html = self._build_html(
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

        out_file = self.report_dir / f"{self.domain}_report.html"
        out_file.write_text(html)
        logger.info(f"Report saved: {out_file}")
        print(f"\n  [+] Report: {out_file}")

    def _read_list(self, filename: str) -> list:
        f = self.output_dir / filename
        if f.exists():
            return [l for l in f.read_text().splitlines() if l.strip()]
        return []

    def _build_html(self, domain, timestamp, subdomains, live_hosts,
                    api_endpoints, urls, sensitive_findings, cloud_assets,
                    param_findings, critical_targets, high_targets,
                    total_secrets, correlated):

        def sev_badge(s):
            colors = {"Critical": "#DC2626", "High": "#D97706", "Medium": "#2563EB", "Low": "#6B7280",
                      "CRITICAL": "#DC2626", "HIGH": "#D97706", "MEDIUM": "#2563EB", "LOW": "#6B7280"}
            c = colors.get(s, "#6B7280")
            return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{s}</span>'

        def rows(items, max_items=50):
            return "".join(f"<tr><td>{i+1}</td><td>{item}</td></tr>" for i, item in enumerate(items[:max_items]))

        sensitive_rows = ""
        for f in sensitive_findings[:30]:
            sev = f.get("severity", "MEDIUM")
            sensitive_rows += f"<tr><td>{sev_badge(sev)}</td><td><a href='{f['url']}' target='_blank'>{f['url']}</a></td><td>{f.get('status','')}</td></tr>"

        param_rows = ""
        for p in param_findings[:30]:
            param_rows += f"<tr><td><code>{p.param}</code></td><td>{p.vuln_type}</td><td>{sev_badge(p.severity)}</td></tr>"

        priority_rows = ""
        for t in (critical_targets + high_targets)[:30]:
            reasons = "; ".join(t.reasons[:2])
            priority_rows += f"<tr><td>{sev_badge(t.priority)}</td><td>{t.url}</td><td>{t.risk_score}/100</td><td style='font-size:11px'>{reasons}</td></tr>"

        correlated_rows = ""
        for url, ch in list(correlated.items())[:20]:
            correlated_rows += f"<tr><td>{ch.host}</td><td>{ch.technology or '—'}</td><td>{ch.server or '—'}</td><td>{len(ch.endpoints)}</td><td>{ch.secrets_found}</td><td>{sev_badge(ch.priority)}</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reco-Nova Report — {domain}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0F172A; color: #E2E8F0; }}
  .header {{ background: linear-gradient(135deg, #1E293B, #0F172A); padding: 30px 40px;
             border-bottom: 3px solid #E94560; }}
  .header h1 {{ font-size: 28px; color: #E94560; }}
  .header .meta {{ color: #94A3B8; font-size: 13px; margin-top: 6px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
                 gap: 16px; margin: 24px 0; }}
  .stat-card {{ background: #1E293B; border: 1px solid #334155; border-radius: 10px;
                padding: 18px; text-align: center; }}
  .stat-card .num {{ font-size: 32px; font-weight: bold; color: #E94560; }}
  .stat-card .label {{ font-size: 12px; color: #94A3B8; margin-top: 4px; }}
  .section {{ background: #1E293B; border: 1px solid #334155; border-radius: 10px;
              margin: 20px 0; overflow: hidden; }}
  .section-header {{ padding: 14px 20px; background: #0F172A; border-bottom: 1px solid #334155;
                     display: flex; align-items: center; gap: 10px; }}
  .section-header h2 {{ font-size: 15px; color: #E94560; }}
  .section-body {{ padding: 16px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #0F172A; color: #94A3B8; padding: 8px 12px; text-align: left;
        font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1E293B; color: #CBD5E1; word-break: break-all; }}
  tr:hover td {{ background: #0F172A33; }}
  a {{ color: #60A5FA; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{ background: #0F172A; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #7DD3FC; }}
  .footer {{ text-align: center; padding: 30px; color: #475569; font-size: 12px; }}
  .warning-bar {{ background: #7C2D12; border: 1px solid #DC2626; border-radius: 8px;
                  padding: 12px 16px; margin-bottom: 20px; font-size: 13px; color: #FCA5A5; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ Reco-Nova — Reconnaissance Report</h1>
  <div class="meta">Target: <strong>{domain}</strong> &nbsp;|&nbsp; Generated: {timestamp} &nbsp;|&nbsp; Lead Auditor: Daniyal Shahid (CEH v13)</div>
</div>
<div class="container">

<div class="warning-bar">
  ⚠️ This report contains sensitive security information. Handle with care and share only with authorized parties.
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="num">{len(subdomains)}</div><div class="label">Subdomains</div></div>
  <div class="stat-card"><div class="num">{len(live_hosts)}</div><div class="label">Live Hosts</div></div>
  <div class="stat-card"><div class="num">{len(api_endpoints)}</div><div class="label">API Endpoints</div></div>
  <div class="stat-card"><div class="num">{len(urls)}</div><div class="label">URLs</div></div>
  <div class="stat-card"><div class="num">{len(sensitive_findings)}</div><div class="label">Sensitive Files</div></div>
  <div class="stat-card"><div class="num">{total_secrets}</div><div class="label">Secrets</div></div>
  <div class="stat-card"><div class="num">{len(critical_targets)}</div><div class="label">Critical Targets</div></div>
  <div class="stat-card"><div class="num">{len(cloud_assets)}</div><div class="label">Cloud Assets</div></div>
</div>

<div class="section">
  <div class="section-header"><h2>🎯 High Priority Targets</h2></div>
  <div class="section-body">
  <table><thead><tr><th>Priority</th><th>Target</th><th>Risk Score</th><th>Reasons</th></tr></thead>
  <tbody>{priority_rows}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-header"><h2>⚠️ Sensitive Files Found</h2></div>
  <div class="section-body">
  <table><thead><tr><th>Severity</th><th>URL</th><th>Status</th></tr></thead>
  <tbody>{sensitive_rows}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-header"><h2>🔬 Parameter Analysis</h2></div>
  <div class="section-body">
  <table><thead><tr><th>Parameter</th><th>Vulnerability Type</th><th>Severity</th></tr></thead>
  <tbody>{param_rows}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-header"><h2>🌐 Host Correlation</h2></div>
  <div class="section-body">
  <table><thead><tr><th>Host</th><th>Technology</th><th>Server</th><th>Endpoints</th><th>Secrets</th><th>Risk</th></tr></thead>
  <tbody>{correlated_rows}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-header"><h2>🔗 Subdomains ({len(subdomains)})</h2></div>
  <div class="section-body">
  <table><thead><tr><th>#</th><th>Subdomain</th></tr></thead>
  <tbody>{rows(subdomains)}</tbody></table>
  </div>
</div>

<div class="section">
  <div class="section-header"><h2>☁️ Cloud Assets</h2></div>
  <div class="section-body">
  <table><thead><tr><th>#</th><th>Asset</th></tr></thead>
  <tbody>{rows(cloud_assets)}</tbody></table>
  </div>
</div>

</div>
<div class="footer">
  Reco-Nova v1.2 &nbsp;|&nbsp; Lead Auditor: Daniyal Shahid (CEH v13) &nbsp;|&nbsp;
  Use only against authorized targets. Unauthorized use is illegal.
</div>
</body>
</html>"""