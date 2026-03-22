import json
import os
from datetime import datetime
from jinja2 import Template

class ReportGenerator:
    def __init__(self, domain, output_dir="output"):
        self.domain = domain
        self.output_dir = output_dir
        self.reports_dir = os.path.join(output_dir, "reports")
        
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_json_report(self, data):
        """Generate JSON report"""
        report = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "scan_summary": {},
            "detailed_results": {}
        }
        
        # Process each data type
        for data_type, items in data.items():
            if items:
                report["scan_summary"][data_type] = len(items)
                report["detailed_results"][data_type] = items
        
        json_path = os.path.join(self.reports_dir, f"report_{self.domain}.json")
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return json_path
    
    def generate_html_report(self, data):
        """Generate professional HTML report with CSS"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reco-Nova Report - {{ domain }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        
        .header .meta {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            font-size: 0.9em;
        }
        
        .meta-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 20px;
            border-radius: 25px;
            backdrop-filter: blur(10px);
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }
        
        .summary-card .label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section-title {
            font-size: 1.8em;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3498db;
        }
        
        .data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }
        
        .data-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            transition: background-color 0.3s ease;
        }
        
        .data-item:hover {
            background: #e3f2fd;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #95a5a6;
            font-style: italic;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .badge {
            display: inline-block;
            background: #e74c3c;
            color: white;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        
        .sensitive {
            border-left-color: #e74c3c;
            background: #fdf2f2;
        }
        
        .sensitive:hover {
            background: #f5c6cb;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .header .meta {
                flex-direction: column;
                gap: 10px;
            }
            
            .summary {
                grid-template-columns: 1fr;
            }
            
            .data-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reco-Nova Report</h1>
            <div class="subtitle">Professional Reconnaissance Results</div>
            <div class="meta">
                <div class="meta-item">
                    <strong>Domain:</strong> {{ domain }}
                </div>
                <div class="meta-item">
                    <strong>Date:</strong> {{ timestamp }}
                </div>
                <div class="meta-item">
                    <strong>Status:</strong> <span style="color: #2ecc71;">✓ Completed</span>
                </div>
            </div>
        </div>
        
        <div class="summary">
            {% for data_type, count in summary.items() %}
            <div class="summary-card">
                <div class="number">{{ count }}</div>
                <div class="label">{{ data_type|title }}</div>
            </div>
            {% endfor %}
        </div>
        
        <div class="content">
            {% for data_type, items in data.items() %}
            <div class="section">
                <h2 class="section-title">
                    {{ data_type|title }}
                    {% if data_type == 'sensitive_files' %}
                    <span class="badge">High Risk</span>
                    {% endif %}
                </h2>
                
                {% if items %}
                    <div class="data-grid">
                        {% for item in items[:50] %}
                        <div class="data-item {% if data_type == 'sensitive_files' %}sensitive{% endif %}">
                            {{ item }}
                        </div>
                        {% endfor %}
                        
                        {% if items|length > 50 %}
                        <div class="data-item">
                            ... and {{ items|length - 50 }} more items
                        </div>
                        {% endif %}
                    </div>
                {% else %}
                    <div class="empty-state">
                        No {{ data_type }} found
                    </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by Reco-Nova Professional Edition | Developed by Daniyal Shahid</p>
            <p style="margin-top: 10px; opacity: 0.7;">⚠️ This report contains sensitive information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data for template
        summary = {}
        for data_type, items in data.items():
            if items:
                summary[data_type] = len(items)
        
        template = Template(html_template)
        html_content = template.render(
            domain=self.domain,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            summary=summary,
            data=data
        )
        
        html_path = os.path.join(self.reports_dir, f"report_{self.domain}.html")
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_path
