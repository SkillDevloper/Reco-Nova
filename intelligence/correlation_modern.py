"""
Modern Interactive Graph Generator with D3.js.
Creates an interactive, zoomable network graph with modern UI.
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
        self._correlate_data()
        
        # Generate graphs
        graph_dir = Path("graphs")
        graph_dir.mkdir(parents=True, exist_ok=True)
        
        self._generate_d3_graph()
        display.success(f"Attack surface graph saved to [bold]graphs/[/bold]")
        
        return self.correlated

    def _correlate_data(self):
        """Correlate all reconnaissance data."""
        display.info("Correlating reconnaissance data...")
        
        # Create domain node
        domain_node = {
            "id": "domain",
            "label": self.domain,
            "type": "domain",
            "color": "#0d6efd",
            "size": 20,
            "title": f"Domain: {self.domain}",
            "level": 0
        }
        
        nodes = [domain_node]
        node_id = 1
        
        # Process live hosts
        for host_data in self.probe_results:
            if isinstance(host_data, dict):
                host = host_data.get("url", "")
                status = host_data.get("status_code", 0)
                title = host_data.get("title", "")
                server = host_data.get("server", "")
                
                node = {
                    "id": f"host_{node_id}",
                    "label": host,
                    "type": "host",
                    "title": f"{host}\\nStatus: {status}\\nTitle: {title}\\nServer: {server}",
                    "color": "#198754",
                    "size": 15,
                    "level": 1
                }
                
                nodes.append(node)
                edges.append({"from": "domain", "to": f"host_{node_id}", "color": "#6c757d"})
                node_id += 1
        
        # Process URLs and parameters
        url_nodes = {}
        for host_data in self.probe_results:
            if isinstance(host_data, dict):
                host = host_data.get("url", "")
                if host not in url_nodes:
                    url_nodes[host] = f"url_{node_id}"
                    node = {
                        "id": f"url_{node_id}",
                        "label": f"{host}\\n({len(host_data.get('urls', []))} URLs)",
                        "type": "url_collection",
                        "color": "#17a2b8",
                        "size": 12,
                        "level": 2,
                        "title": f"URLs for {host}"
                    }
                    nodes.append(node)
                    edges.append({"from": f"host_{node_id-1}", "to": f"url_{node_id}", "color": "#6c757d"})
                    node_id += 1
        
        # Process fingerprinting data
        for host, fp in self.fingerprints.items():
            host_node_id = None
            for i, node in enumerate(nodes):
                if node.get("label") == host:
                    host_node_id = node["id"]
                    break
            
            if host_node_id and fp.framework:
                framework_node = {
                    "id": f"fp_{node_id}",
                    "label": fp.framework,
                    "type": "framework",
                    "color": "#ffc107",
                    "size": 10,
                    "level": 2,
                    "title": f"Framework: {fp.framework}"
                }
                nodes.append(framework_node)
                edges.append({"from": host_node_id, "to": f"fp_{node_id}", "color": "#6c757d"})
                node_id += 1
        
        # Process sensitive findings
        for finding in self.sensitive_findings[:20]:
            host = finding.get("url", "")
            host_node_id = None
            for i, node in enumerate(nodes):
                if node.get("label") == host:
                    host_node_id = node["id"]
                    break
            
            if host_node_id:
                severity = finding.get("severity", "Medium")
                color_map = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#6c757d"}
                
                sensitive_node = {
                    "id": f"sens_{node_id}",
                    "label": finding.get("file", ""),
                    "type": "sensitive_file",
                    "color": color_map.get(severity, "#6c757d"),
                    "size": 8,
                    "level": 2,
                    "title": f"Sensitive File: {finding.get('file', '')}\\nSeverity: {severity}"
                }
                nodes.append(sensitive_node)
                edges.append({"from": host_node_id, "to": f"sens_{node_id}", "color": "#dc3545"})
                node_id += 1
        
        # Store correlated data
        for host_data in self.probe_results:
            if isinstance(host_data, dict):
                host = host_data.get("url", "")
                self.correlated[host] = CorrelatedHost(
                    host=host,
                    url=host,
                    endpoints=[],
                    parameters=[],
                    js_files=0,
                    secrets_found=0,
                    technology="",
                    server=host_data.get("server", ""),
                    sensitive_files=[],
                    risk_score=0,
                    priority="LOW"
                )

    def _generate_d3_graph(self):
        """Generate modern D3.js interactive graph."""
        graph_dir = Path("graphs")
        graph_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare nodes and edges for D3.js
        nodes = []
        edges = []
        
        # Add domain node
        nodes.append({
            "id": "domain",
            "name": self.domain,
            "type": "domain",
            "color": "#0d6efd",
            "size": 20,
            "level": 0,
            "description": f"Primary domain: {self.domain}"
        })
        
        # Add host nodes
        for host_data in self.probe_results:
            if isinstance(host_data, dict):
                host = host_data.get("url", "")
                status = host_data.get("status_code", 0)
                title = host_data.get("title", "")
                server = host_data.get("server", "")
                
                nodes.append({
                    "id": f"host_{len(nodes)}",
                    "name": host,
                    "type": "host",
                    "color": "#198754" if 200 <= status < 300 else "#dc3545",
                    "size": 15,
                    "level": 1,
                    "description": f"{host}\\nStatus: {status}\\nTitle: {title}\\nServer: {server}"
                })
                
                edges.append({
                    "source": "domain",
                    "target": f"host_{len(nodes)}",
                    "color": "#6c757d"
                })
        
        # Add URL collection nodes
        for host_data in self.probe_results:
            if isinstance(host_data, dict):
                host = host_data.get("url", "")
                urls = host_data.get('urls', [])
                if urls and len(urls) > 0:
                    nodes.append({
                        "id": f"urls_{len(nodes)}",
                        "name": f"{host}\\n({len(urls)} URLs)",
                        "type": "url_collection",
                        "color": "#17a2b8",
                        "size": 12,
                        "level": 2,
                        "description": f"URLs discovered for {host}"
                    })
                    
                    edges.append({
                        "source": f"host_{len(nodes)-1}",
                        "target": f"urls_{len(nodes)}",
                        "color": "#6c757d"
                    })
        
        # Add framework nodes
        for host, fp in self.fingerprints.items():
            if fp.framework:
                nodes.append({
                    "id": f"fp_{len(nodes)}",
                    "name": fp.framework,
                    "type": "framework",
                    "color": "#ffc107",
                    "size": 10,
                    "level": 2,
                    "description": f"Framework detected: {fp.framework}"
                })
                
                # Find host node to connect to
                host_node_id = None
                for i, node in enumerate(nodes):
                    if node.get("name") == host:
                        host_node_id = node["id"]
                        break
                
                if host_node_id:
                    edges.append({
                        "source": host_node_id,
                        "target": f"fp_{len(nodes)}",
                        "color": "#6c757d"
                    })
        
        # Add sensitive file nodes
        for finding in self.sensitive_findings[:20]:
            host = finding.get("url", "")
            severity = finding.get("severity", "Medium")
            color_map = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107", "Low": "#6c757d"}
            
            nodes.append({
                "id": f"sens_{len(nodes)}",
                "name": finding.get("file", ""),
                "type": "sensitive_file",
                "color": color_map.get(severity, "#6c757d"),
                "size": 8,
                "level": 2,
                "description": f"Sensitive file: {finding.get('file', '')}\\nSeverity: {severity}"
            })
            
            # Find host node to connect to
            host_node_id = None
            for i, node in enumerate(nodes):
                if node.get("name") == host:
                    host_node_id = node["id"]
                    break
            
            if host_node_id:
                edges.append({
                    "source": host_node_id,
                    "target": f"sens_{len(nodes)}",
                    "color": "#dc3545"
                })
        
        # Generate HTML with D3.js
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reco-Nova — {self.domain} Attack Surface Graph</title>
    
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- D3.js -->
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <!-- Custom Dark Theme -->
    <style>
        :root {{
            --bs-dark: #1a1a1a;
            --bs-darker: #0d0d0d;
            --bs-primary: #0d6efd;
            --bs-success: #198754;
            --bs-danger: #dc3545;
            --bs-warning: #ffc107;
            --bs-info: #0dcaf0;
            --bs-light: #212529;
        }}
        
        body {{
            background-color: var(--bs-dark);
            color: #e9ecef;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            overflow: hidden;
        }}
        
        .navbar {{
            background-color: var(--bs-darker) !important;
            border-bottom: 1px solid #495057;
            padding: 1rem 0;
        }}
        
        .controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            z-index: 1000;
            background: rgba(0,0,0,0.8);
            padding: 10px;
            border-radius: 5px;
        }}
        
        .control-btn {{
            background: var(--bs-primary);
            border: none;
            color: white;
            padding: 5px 10px;
            margin: 2px;
            border-radius: 3px;
            cursor: pointer;
        }}
        
        .control-btn:hover {{
            background: #0a58ca;
        }}
        
        #graph {{
            width: 100%;
            height: calc(100vh - 80px);
            background: radial-gradient(circle, #212529 1px, transparent 1px);
        }}
        
        .node {{
            cursor: pointer;
            stroke-width: 2px;
        }}
        
        .node:hover {{
            stroke-width: 4px;
            filter: brightness(1.2);
        }}
        
        .link {{
            stroke: #6c757d;
            stroke-width: 2px;
            fill: none;
        }}
        
        .tooltip {{
            position: absolute;
            background: rgba(0,0,0,0.9);
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            max-width: 300px;
            word-wrap: break-word;
        }}
        
        .legend {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(0,0,0,0.8);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 5px 0;
        }}
        
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 2px;
            margin-right: 8px;
        }}
        
        .footer {{
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            background: var(--bs-darker);
            border-top: 1px solid #495057;
            padding: 10px;
            text-align: center;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-diagram-3-fill"></i>
                Reco-Nova Graph
            </a>
            <span class="navbar-text text-light">
                <i class="bi bi-globe"></i> {self.domain}
            </span>
        </div>
    </nav>

    <!-- Controls -->
    <div class="controls">
        <button class="control-btn" onclick="zoomIn()">
            <i class="bi bi-zoom-in"></i> Zoom In
        </button>
        <button class="control-btn" onclick="zoomOut()">
            <i class="bi bi-zoom-out"></i> Zoom Out
        </button>
        <button class="control-btn" onclick="resetZoom()">
            <i class="bi bi-arrow-clockwise"></i> Reset
        </button>
    </div>

    <!-- Graph Container -->
    <div id="graph"></div>

    <!-- Legend -->
    <div class="legend">
        <div class="legend-item">
            <div class="legend-color" style="background: #0d6efd;"></div>
            <span>Domain</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #198754;"></div>
            <span>Live Host</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #17a2b8;"></div>
            <span>URL Collection</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #ffc107;"></div>
            <span>Framework</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #dc3545;"></div>
            <span>Sensitive File</span>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <strong>Reco-Nova v1.2</strong> | Interactive Attack Surface Graph<br>
        <small>Click and drag to explore • Scroll to zoom • Right-click for options</small>
    </div>

    <!-- D3.js Script -->
    <script>
        // Graph data
        const nodes = {json.dumps(nodes)};
        const links = {json.dumps(edges)};
        
        // Set up dimensions
        const width = window.innerWidth;
        const height = window.innerHeight - 80;
        
        // Create SVG
        const svg = d3.select("#graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        // Create zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on("zoom", function(event) {{
                g.attr("transform", event.transform);
            }});
        
        const g = svg.append("g");
        
        // Create force simulation
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2));
        
        // Create links
        const link = g.append("g")
            .selectAll(".link")
            .data(links)
            .enter().append("line")
            .attr("class", "link")
            .attr("stroke-width", 2);
        
        // Create nodes
        const node = g.append("g")
            .selectAll(".node")
            .data(nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", d => d.size || 10)
            .attr("fill", d => d.color || "#999")
            .call(d3.drag()
                .on("start", function(event, d) {{
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }})
                .on("drag", function(event, d) {{
                    d.fx = event.x;
                    d.fy = event.y;
                }})
                .on("end", function(event, d) {{
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }})
            );
        
        // Add tooltips
        const tooltip = d3.select("body").append("div")
            .attr("class", "tooltip")
            .style("opacity", 0);
        
        node.on("mouseover", function(event, d) {{
            tooltip.transition()
                .duration(200)
                .style("opacity", .9);
            tooltip.html(d.description || d.name || d.id)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        }})
        .on("mouseout", function(d) {{
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        }});
        
        // Update positions on tick
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
        }});
        
        // Apply zoom behavior
        svg.call(zoom);
        
        // Control functions
        function zoomIn() {{
            svg.transition().duration(300).call(zoom.scaleBy, 1.3);
        }}
        
        function zoomOut() {{
            svg.transition().duration(300).call(zoom.scaleBy, 0.7);
        }}
        
        function resetZoom() {{
            svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);
        }}
        
        // Handle window resize
        window.addEventListener("resize", () => {{
            const newWidth = window.innerWidth;
            const newHeight = window.innerHeight - 80;
            svg.attr("width", newWidth).attr("height", newHeight);
            zoom.translateTo(svg.node().getBBox().x, svg.node().getBBox().y);
        }});
        
        // Start simulation
        simulation.on("end", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
        }});
    </script>
</body>
</html>"""
        
        # Save HTML file
        html_file = graph_dir / f"{self.domain}_graph.html"
        html_file.write_text(html_content)
        
        # Save JSON data
        json_file = graph_dir / f"{self.domain}_graph.json"
        json_file.write_text(json.dumps({"nodes": nodes, "edges": edges, "domain": self.domain}, indent=2))
        
        logger.info(f"Interactive graph saved: {html_file}")
        logger.info(f"Graph data saved: {json_file}")
