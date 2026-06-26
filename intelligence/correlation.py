"""
Recon Correlation Engine & Attack Surface Graph Builder.
Links all recon data and generates visual asset graphs.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field
from core.display import Display
from core.logger import get_logger

logger = get_logger("correlation")
display = Display()


@dataclass
class CorrelatedHost:
    host: str
    url: str
    endpoints: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    js_files: int = 0
    secrets_found: int = 0
    technology: str = ""
    server: str = ""
    cdn: str = ""
    waf: str = ""
    sensitive_files: list = field(default_factory=list)
    risk_score: int = 0
    priority: str = "LOW"
    # Suggested sensitive file checks based on detected tech stack
    recommended_checks: list = field(default_factory=list)


class CorrelationEngine:
    def __init__(self, domain: str, probe_results, js_results,
                 fingerprints, sensitive_findings, prioritized_targets,
                 output_dir: Path):
        self.domain = domain
        self.probe_results = probe_results
        self.js_results = js_results
        self.fingerprints = fingerprints
        self.sensitive_findings = sensitive_findings
        self.prioritized_targets = prioritized_targets
        self.output_dir = output_dir
        self.correlated: dict[str, CorrelatedHost] = {}

    def run(self) -> dict[str, CorrelatedHost]:
        display.info("Running recon correlation engine...")

        # Build correlation map keyed by host URL
        for result in self.probe_results:
            host_key = result.url
            ch = CorrelatedHost(
                host=result.url.split("//")[-1].split("/")[0],
                url=result.url,
            )

            # Fingerprint data
            fp = self.fingerprints.get(result.url)
            if fp:
                parts = [fp.framework, fp.language, fp.cms]
                ch.technology = " / ".join(p for p in parts if p) or "Unknown"
                ch.server = fp.server
                ch.cdn = fp.cdn
                ch.waf = fp.waf

                # Map technology to recommended sensitive file checks
                tech_blob = " ".join(
                    p for p in [fp.framework, fp.language, fp.cms] if p
                ).lower()
                recommended = []
                if "php" in tech_blob or "wordpress" in tech_blob:
                    recommended.extend(["config.php", ".php.bak", "wp-config.php"])
                if "asp.net" in tech_blob or "iis" in tech_blob:
                    recommended.extend(["web.config", "Web.config.bak"])
                if "django" in tech_blob or "flask" in tech_blob:
                    recommended.extend(["settings.py", ".env", "config.yaml"])
                if "node.js" in tech_blob or "express" in tech_blob:
                    recommended.extend([".env", "config.js", "config.json"])
                ch.recommended_checks = sorted(set(recommended))

            # JS data
            js_for_host = [
                r for r in self.js_results
                if ch.host in r.url
            ]
            ch.js_files = len(js_for_host)
            ch.secrets_found = sum(len(r.secrets) for r in js_for_host)
            for r in js_for_host:
                ch.endpoints.extend(r.endpoints)
                ch.parameters.extend(r.parameters)

            # Sensitive files
            ch.sensitive_files = [
                f["url"] for f in self.sensitive_findings
                if ch.host in f["url"]
            ]

            # Risk score from prioritization
            for pt in self.prioritized_targets:
                if ch.host in pt.url:
                    ch.risk_score = max(ch.risk_score, pt.risk_score)
                    ch.priority = pt.priority

            self.correlated[host_key] = ch

        self._save_correlation()
        self._build_graph()

        display.success(f"Correlation complete: [bold green]{len(self.correlated)}[/bold green] hosts mapped")
        return self.correlated

    def _save_correlation(self):
        lines = ["=" * 60, f"RECON CORRELATION — {self.domain}", "=" * 60]

        for url, ch in sorted(
            self.correlated.items(),
            key=lambda x: x[1].risk_score, reverse=True
        ):
            lines.append(f"\n{'─'*50}")
            lines.append(f"Host:         {ch.url}")
            lines.append(f"Technology:   {ch.technology or 'Unknown'}")
            lines.append(f"Server:       {ch.server or 'Unknown'}")
            if ch.cdn:
                lines.append(f"CDN:          {ch.cdn}")
            if ch.waf:
                lines.append(f"WAF:          {ch.waf}")
            lines.append(f"JS Files:     {ch.js_files}")
            lines.append(f"Endpoints:    {len(ch.endpoints)}")
            lines.append(f"Parameters:   {len(ch.parameters)}")
            if ch.secrets_found:
                lines.append(f"Secrets:      {ch.secrets_found} detected")
            if ch.sensitive_files:
                lines.append(f"Sensitive:    {len(ch.sensitive_files)} files")
            lines.append(f"Risk Score:   {ch.risk_score}/100 ({ch.priority})")

        out_file = self.output_dir / "correlation.txt"
        out_file.write_text("\n".join(lines))

    def _build_graph(self):
        """Build JSON graph and interactive HTML visualization."""
        graph_dir = Path("graphs")
        graph_dir.mkdir(parents=True, exist_ok=True)

        # Build graph data structure
        nodes = []
        edges = []
        node_id = 0
        id_map = {}

        # Root domain node — Bright Orange
        root_id = node_id
        nodes.append({
            "id": root_id,
            "label": self.domain,
            "type": "domain",
            "color": {"background": "#FF8C00", "border": "#FFA500"},
            "size": 35,
        })
        id_map[self.domain] = root_id
        node_id += 1

        for url, ch in self.correlated.items():
            host = ch.host

            # Host node
            if host not in id_map:
                # Neon Green for subdomains, with bigger size for HIGH/CRITICAL
                if ch.priority == "CRITICAL":
                    node_color = {"background": "#FF2D55", "border": "#FF5577"}
                    node_size = 28
                elif ch.priority == "HIGH":
                    node_color = {"background": "#FF6B00", "border": "#FF8C00"}
                    node_size = 22
                else:
                    node_color = {"background": "#39FF14", "border": "#55FF30"}
                    node_size = 18
                nodes.append({
                    "id": node_id,
                    "label": host,
                    "type": "host",
                    "color": node_color,
                    "size": node_size,
                    "tech": ch.technology,
                    "risk": ch.risk_score,
                    "priority": ch.priority,
                })
                id_map[host] = node_id
                edges.append({"from": root_id, "to": node_id})
                node_id += 1

            host_node_id = id_map[host]

            # Endpoint nodes (top 5 per host)
            for ep in ch.endpoints[:5]:
                ep_label = ep[:40]
                nodes.append({
                    "id": node_id,
                    "label": ep_label,
                    "type": "endpoint",
                    "color": {"background": "#7C3AED", "border": "#9D5DF0"},
                    "size": 10,
                })
                edges.append({"from": host_node_id, "to": node_id})
                node_id += 1

            # Sensitive files (top 3)
            for sf in ch.sensitive_files[:3]:
                sf_label = sf.split("/")[-1] or sf
                nodes.append({
                    "id": node_id,
                    "label": sf_label,
                    "type": "sensitive",
                    "color": {"background": "#FF2D55", "border": "#FF4D70"},
                    "size": 14,
                })
                edges.append({"from": host_node_id, "to": node_id})
                node_id += 1

        graph_data = {"nodes": nodes, "edges": edges, "domain": self.domain}

        # Save JSON
        json_file = graph_dir / f"{self.domain}_graph.json"
        json_file.write_text(json.dumps(graph_data, indent=2))

        # Save interactive HTML
        self._build_html_graph(graph_data, graph_dir)
        display.success(f"Attack surface graph saved to [bold]graphs/[/bold]")

    def _build_html_graph(self, graph_data: dict, graph_dir: Path):
        nodes_json = json.dumps(graph_data["nodes"])
        edges_json = json.dumps(graph_data["edges"])
        domain = graph_data["domain"]
        n_nodes = len(graph_data["nodes"])
        n_edges = len(graph_data["edges"])
        n_critical = sum(1 for n in graph_data["nodes"] if n.get("priority") in ("CRITICAL", "HIGH"))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RECO-NOVA | {domain} — Attack Surface Graph</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css"/>
<style>
  /* ── Reset & Base ──────────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; }}
  :root {{
    --bg:       #050B18;
    --bg2:      #080F1E;
    --border:   #0f1e35;
    --neon:     #39FF14;
    --orange:   #FF8C00;
    --red:      #FF2D55;
    --cyan:     #00D4FF;
    --text:     #b4bcd0;
    --text-dim: #3d4f6a;
  }}
  html, body {{
    margin: 0; padding: 0; width: 100%; height: 100%;
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', system-ui, sans-serif;
    overflow: hidden;
  }}

  /* ── Dot-grid background ───────────────────────────────── */
  body::before {{
    content: '';
    position: fixed; inset: 0;
    background-image: radial-gradient(rgba(0,212,255,.07) 1px, transparent 1px);
    background-size: 28px 28px;
    pointer-events: none;
    z-index: 0;
  }}

  /* ── Scanline ──────────────────────────────────────────── */
  @keyframes scanline {{
    0%   {{ transform: translateY(-100%); }}
    100% {{ transform: translateY(100vh); }}
  }}
  .scanline {{
    pointer-events: none;
    position: fixed; top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(to bottom, transparent, rgba(57,255,20,.1), transparent);
    animation: scanline 7s linear infinite;
    z-index: 9999;
  }}

  /* ── Top Bar ───────────────────────────────────────────── */
  #topbar {{
    position: fixed; top: 0; left: 0; right: 0;
    height: 52px;
    background: rgba(5,11,24,.92);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center;
    padding: 0 20px;
    z-index: 100;
    gap: 20px;
  }}
  #topbar .brand {{
    font-size: 1rem; font-weight: 700;
    letter-spacing: 3px; color: var(--neon);
    flex-shrink: 0;
  }}
  #topbar .brand span {{ color: var(--orange); }}
  #topbar .meta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; color: var(--text-dim);
    display: flex; gap: 18px; flex-wrap: wrap;
  }}
  #topbar .meta b {{ color: var(--text); }}
  #topbar .spacer {{ flex: 1; }}
  #topbar .auditor {{
    font-size: 0.72rem; color: var(--text-dim);
    font-family: 'JetBrains Mono', monospace;
    border-left: 1px solid var(--border);
    padding-left: 16px;
  }}
  #topbar .auditor b {{ color: var(--orange); }}

  /* ── Graph Canvas ──────────────────────────────────────── */
  #graph {{
    position: fixed;
    top: 52px; left: 0; right: 320px; bottom: 38px;
    z-index: 1;
  }}

  /* ── Controls ──────────────────────────────────────────── */
  #controls {{
    position: fixed;
    top: 66px; left: 12px;
    z-index: 50;
    display: flex; flex-direction: column; gap: 6px;
  }}
  .ctrl-btn {{
    background: rgba(5,11,24,.85);
    backdrop-filter: blur(8px);
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 7px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-family: 'Rajdhani', sans-serif;
    font-size: 0.78rem; font-weight: 600;
    letter-spacing: 1px;
    transition: all .15s;
    display: flex; align-items: center; gap: 7px;
    white-space: nowrap;
  }}
  .ctrl-btn:hover {{
    background: rgba(57,255,20,.08);
    border-color: var(--neon);
    color: var(--neon);
  }}
  .ctrl-btn svg {{ width: 14px; height: 14px; fill: currentcolor; }}
  #filter-panel {{
    background: rgba(5,11,24,.9);
    backdrop-filter: blur(8px);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 12px;
    display: none;
    flex-direction: column;
    gap: 6px;
  }}
  #filter-panel label {{
    font-size: 0.74rem;
    color: var(--text-dim);
    display: flex; align-items: center; gap: 7px;
    cursor: pointer;
  }}
  #filter-panel label:hover {{ color: var(--text); }}
  #filter-panel input[type=checkbox] {{ accent-color: var(--neon); }}

  /* ── Info Panel (right side) ───────────────────────────── */
  #info-panel {{
    position: fixed;
    top: 52px; right: 0;
    width: 320px; bottom: 38px;
    background: var(--bg2);
    border-left: 1px solid var(--border);
    z-index: 50;
    display: flex; flex-direction: column;
    overflow: hidden;
  }}
  #info-header {{
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,.02);
    font-size: 0.72rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--neon);
    display: flex; align-items: center; gap: 8px;
  }}
  #info-body {{
    flex: 1; overflow-y: auto;
    padding: 16px;
  }}
  #info-placeholder {{
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    height: 100%;
    color: var(--text-dim);
    font-size: 0.78rem; text-align: center;
    gap: 10px;
  }}
  #info-placeholder .big {{ font-size: 2rem; opacity: .25; }}
  .info-field {{
    margin-bottom: 14px;
  }}
  .info-field-label {{
    font-size: 0.6rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 3px;
  }}
  .info-field-value {{
    font-size: 0.82rem;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all;
  }}
  .info-field-value.url-val {{ color: var(--cyan); }}
  .info-badge {{
    display: inline-block;
    padding: 2px 8px; border-radius: 3px;
    font-size: 0.65rem; font-weight: 700;
    border: 1px solid; letter-spacing: 1px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }}
  .b-critical {{ color: var(--red);    border-color: var(--red);    background: rgba(255,45,85,.12); }}
  .b-high     {{ color: var(--orange); border-color: var(--orange); background: rgba(255,140,0,.12); }}
  .b-medium   {{ color: #FFD60A; border-color: #FFD60A; background: rgba(255,214,10,.08); }}
  .b-low      {{ color: #475569; border-color: #334155; background: rgba(71,85,105,.08); }}
  .b-domain   {{ color: var(--orange); border-color: var(--orange); background: rgba(255,140,0,.1); }}
  .b-endpoint {{ color: var(--neon);   border-color: var(--neon);   background: rgba(57,255,20,.08); }}
  .b-sensitive {{ color: var(--red);  border-color: var(--red);    background: rgba(255,45,85,.1); }}

  /* ── Pulsing node animation for critical ───────────────── */
  @keyframes pulse-ring {{
    0%   {{ transform: scale(1);    opacity: .7; }}
    100% {{ transform: scale(2.5); opacity: 0; }}
  }}

  /* ── Legend ────────────────────────────────────────────── */
  #legend {{
    position: fixed;
    bottom: 50px; left: 12px;
    background: rgba(5,11,24,.88);
    backdrop-filter: blur(8px);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 14px;
    z-index: 50;
    font-size: 0.72rem;
  }}
  #legend-title {{
    font-size: 0.6rem; letter-spacing: 2px;
    text-transform: uppercase; color: var(--neon);
    margin-bottom: 8px;
  }}
  .leg-item {{
    display: flex; align-items: center;
    gap: 8px; margin: 5px 0;
    color: var(--text-dim);
  }}
  .leg-dot {{ width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }}

  /* ── Status Bar ──────────────────────────────────────────── */
  #statusbar {{
    position: fixed;
    bottom: 0; left: 0; right: 0;
    height: 38px;
    background: rgba(5,11,24,.95);
    border-top: 1px solid var(--border);
    display: flex; align-items: center;
    padding: 0 16px; gap: 24px;
    z-index: 100;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem; color: var(--text-dim);
  }}
  #statusbar span b {{ color: var(--text); }}
  #statusbar .crit {{ color: var(--red); }}
  #statusbar .hint {{ margin-left: auto; color: var(--text-dim); opacity: .6; }}

  /* vis.js tooltip override */
  .vis-tooltip {{
    background: rgba(5,11,24,.95) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    border-radius: 4px !important;
    padding: 8px 12px !important;
  }}
</style>
</head>
<body>
<div class="scanline"></div>

<!-- Top Bar -->
<div id="topbar">
  <div class="brand">RECO<span>-NOVA</span></div>
  <div class="meta">
    <span>TARGET: <b>{domain}</b></span>
    <span>NODES: <b>{n_nodes}</b></span>
    <span>EDGES: <b>{n_edges}</b></span>
    <span class="crit">HIGH-RISK: <b style="color:var(--red)">{n_critical}</b></span>
  </div>
  <div class="spacer"></div>
  <div class="auditor">Lead Auditor: <b>Daniyal Shahid (CEH v13)</b></div>
</div>

<!-- Controls -->
<div id="controls">
  <button class="ctrl-btn" onclick="network.fit()">
    <svg viewBox="0 0 24 24"><path d="M4 8V4h4V2H2v6h2zm16-4h-4V2h6v6h-2V4zM4 16H2v6h6v-2H4v-4zm16 4h-4v2h6v-6h-2v4z"/></svg>
    Fit View
  </button>
  <button class="ctrl-btn" onclick="network.zoomIn(0.3)">
    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16a6.471 6.471 0 0 0 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14zm.5-7H9v2H7v1h2v2h1v-2h2V9h-2z"/></svg>
    Zoom In
  </button>
  <button class="ctrl-btn" onclick="network.zoomOut(0.3)">
    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16a6.471 6.471 0 0 0 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14zM7 9h5v1H7z"/></svg>
    Zoom Out
  </button>
  <button class="ctrl-btn" onclick="toggleFilter()" id="filter-btn">
    <svg viewBox="0 0 24 24"><path d="M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z"/></svg>
    Filter
  </button>
  <div id="filter-panel">
    <label><input type="checkbox" id="f-domain"    checked onchange="applyFilter()"> Root Domain</label>
    <label><input type="checkbox" id="f-host"      checked onchange="applyFilter()"> Live Hosts</label>
    <label><input type="checkbox" id="f-endpoint"  checked onchange="applyFilter()"> Endpoints</label>
    <label><input type="checkbox" id="f-sensitive" checked onchange="applyFilter()"> Sensitive Files</label>
  </div>
</div>

<!-- Graph Canvas -->
<div id="graph"></div>

<!-- Info Panel -->
<div id="info-panel">
  <div id="info-header">
    &#9670; Node Inspector
  </div>
  <div id="info-body">
    <div id="info-placeholder">
      <div class="big">&#9673;</div>
      <div>Click a node to inspect</div>
    </div>
    <div id="info-content" style="display:none;"></div>
  </div>
</div>

<!-- Legend -->
<div id="legend">
  <div id="legend-title">Legend</div>
  <div class="leg-item"><div class="leg-dot" style="background:#FF8C00;box-shadow:0 0 6px #FF8C00;"></div>Root Domain</div>
  <div class="leg-item"><div class="leg-dot" style="background:#39FF14;box-shadow:0 0 6px rgba(57,255,20,.5);"></div>Subdomain / Host</div>
  <div class="leg-item"><div class="leg-dot" style="background:#7C3AED;"></div>Endpoint</div>
  <div class="leg-item"><div class="leg-dot" style="background:#FF2D55;box-shadow:0 0 6px rgba(255,45,85,.5);"></div>Sensitive File</div>
</div>

<!-- Status Bar -->
<div id="statusbar">
  <span>NODES: <b>{n_nodes}</b></span>
  <span>EDGES: <b>{n_edges}</b></span>
  <span class="crit">CRITICAL/HIGH: <b>{n_critical}</b></span>
  <span class="hint">Click a node to inspect &nbsp;|&nbsp; Scroll to zoom &nbsp;|&nbsp; Drag to pan</span>
</div>

<script>
var allNodes = new vis.DataSet({nodes_json});
var allEdges = new vis.DataSet({edges_json});
var container = document.getElementById("graph");
var data = {{ nodes: allNodes, edges: allEdges }};

var options = {{
  nodes: {{
    shape: "dot",
    font: {{
      color: "#b4bcd0",
      size: 12,
      face: "JetBrains Mono, monospace"
    }},
    borderWidth: 1.5,
    shadow: {{ enabled: true, size: 18 }}
  }},
  edges: {{
    color: {{ color: "#0f2040", highlight: "#39FF14", hover: "#00D4FF" }},
    arrows: {{ to: {{ enabled: true, scaleFactor: 0.45 }} }},
    smooth: {{ type: "cubicBezier", forceDirection: "vertical", roundness: 0.5 }},
    width: 1.2,
    selectionWidth: 2.5
  }},
  physics: {{
    forceAtlas2Based: {{
      gravitationalConstant: -55,
      centralGravity: 0.012,
      springLength: 140,
      springConstant: 0.08
    }},
    solver: "forceAtlas2Based",
    stabilization: {{ iterations: 175, updateInterval: 25 }}
  }},
  interaction: {{
    hover: true,
    tooltipDelay: 80,
    zoomView: true,
    dragView: true
  }},
  configure: {{ enabled: false }}
}};

var network = new vis.Network(container, data, options);

// ── Node click → info panel ───────────────────────────────────────
network.on("click", function(params) {{
  if (params.nodes.length === 0) return;
  var nodeId = params.nodes[0];
  var node = allNodes.get(nodeId);
  if (!node) return;

  var typeLabel = {{ domain:"domain", host:"host", endpoint:"endpoint", sensitive:"sensitive" }}[node.type] || node.type;
  var badgeClass = {{
    domain: "b-domain", host: "b-high", endpoint: "b-endpoint", sensitive: "b-sensitive"
  }}[node.type] || "b-low";
  var priorityBadge = "";
  if (node.priority) {{
    var pc = {{ CRITICAL:"b-critical", HIGH:"b-high", MEDIUM:"b-medium", LOW:"b-low" }}[node.priority] || "b-low";
    priorityBadge = "<span class='info-badge " + pc + "'>" + node.priority + "</span>";
  }}

  var html = "<div class='info-field'>" +
    "<div class='info-field-label'>Type</div>" +
    "<span class='info-badge " + badgeClass + "'>" + typeLabel + "</span> " + priorityBadge +
  "</div>";

  if (node.label) html += "<div class='info-field'><div class='info-field-label'>Label</div>" +
    "<div class='info-field-value url-val'>" + escHtml(node.label) + "</div></div>";

  if (node.tech) html += "<div class='info-field'><div class='info-field-label'>Technology</div>" +
    "<div class='info-field-value'>" + escHtml(node.tech) + "</div></div>";

  if (node.risk != null) html += "<div class='info-field'><div class='info-field-label'>Risk Score</div>" +
    "<div class='info-field-value'><span style='color:var(--orange);font-size:1.1rem;font-weight:700;'>" + node.risk + "</span>/100</div></div>";

  document.getElementById("info-placeholder").style.display = "none";
  var ic = document.getElementById("info-content");
  ic.innerHTML = html;
  ic.style.display = "block";
}});

function escHtml(s) {{
  if (!s) return "";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}}

// ── Filter ───────────────────────────────────────────────────────
function toggleFilter() {{
  var p = document.getElementById("filter-panel");
  p.style.display = p.style.display === "flex" ? "none" : "flex";
}}
function applyFilter() {{
  var types = [];
  if (document.getElementById("f-domain").checked)    types.push("domain");
  if (document.getElementById("f-host").checked)      types.push("host");
  if (document.getElementById("f-endpoint").checked)  types.push("endpoint");
  if (document.getElementById("f-sensitive").checked) types.push("sensitive");

  var show = allNodes.get().filter(n => types.includes(n.type)).map(n => n.id);
  var hide = allNodes.get().filter(n => !types.includes(n.type)).map(n => n.id);

  allNodes.update(show.map(id => ({{ id, hidden: false }})));
  allNodes.update(hide.map(id => ({{ id, hidden: true  }})));
}}

// ── Stabilise → fit ──────────────────────────────────────────────
network.on("stabilizationIterationsDone", function() {{
  network.setOptions({{ physics: false }});
  network.fit({{ animation: {{ duration: 800, easingFunction: "easeInOutQuad" }} }});
}});
</script>
</body>
</html>"""

        html_file = graph_dir / f"{domain}_graph.html"
        html_file.write_text(html)