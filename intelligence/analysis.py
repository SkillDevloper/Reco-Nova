"""
Parameter Intelligence Engine & Endpoint Prioritization Engine.
Analyzes parameters for vulnerability potential and ranks targets by risk.
"""

import re
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse
from config.settings import config
from core.display import Display
from core.logger import get_logger

logger = get_logger("intelligence")
display = Display()

SEVERITY_SCORE = {
    "Critical": 100,
    "High": 75,
    "Medium": 50,
    "Low": 25,
}


@dataclass
class ParameterFinding:
    param: str
    vuln_type: str
    severity: str
    urls: list[str]
    score: int


@dataclass
class PrioritizedTarget:
    url: str
    risk_score: int
    reasons: list[str]
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW


class ParameterIntelligence:
    def __init__(self, parameters: dict, output_dir: Path):
        self.parameters = parameters  # {param_name: set_of_urls}
        self.output_dir = output_dir
        self.findings: list[ParameterFinding] = []

    def run(self) -> list[ParameterFinding]:
        display.info("Running parameter intelligence analysis...")

        for param, urls in self.parameters.items():
            param_lower = param.lower()

            # Direct match
            if param_lower in config.param_vulns:
                vuln_type, severity = config.param_vulns[param_lower]
                self.findings.append(ParameterFinding(
                    param=param,
                    vuln_type=vuln_type,
                    severity=severity,
                    urls=list(urls)[:5],
                    score=SEVERITY_SCORE.get(severity, 0),
                ))
                continue

            # Fuzzy match
            for known_param, (vuln_type, severity) in config.param_vulns.items():
                if known_param in param_lower or param_lower in known_param:
                    self.findings.append(ParameterFinding(
                        param=param,
                        vuln_type=f"{vuln_type} (fuzzy match)",
                        severity=severity,
                        urls=list(urls)[:5],
                        score=SEVERITY_SCORE.get(severity, 0) - 10,
                    ))
                    break

        # Sort by score
        self.findings.sort(key=lambda x: x.score, reverse=True)

        self._save_results()

        critical = sum(1 for f in self.findings if f.severity == "Critical")
        high = sum(1 for f in self.findings if f.severity == "High")

        display.success(f"Parameter analysis: [bold]{len(self.findings)}[/bold] findings "
                        f"([red]{critical} Critical[/red], [yellow]{high} High[/yellow])")
        logger.info(f"Parameter findings: {len(self.findings)}")
        return self.findings

    def _save_results(self):
        lines = []
        for f in self.findings:
            color_map = {"Critical": "!!!", "High": "!", "Medium": "*", "Low": "-"}
            marker = color_map.get(f.severity, " ")
            lines.append(f"\n[{marker}] Parameter: {f.param}")
            lines.append(f"    Vulnerability: {f.vuln_type}")
            lines.append(f"    Severity:      {f.severity}")
            lines.append(f"    Sample URLs:")
            for u in f.urls[:3]:
                lines.append(f"      {u}")

        out_file = self.output_dir / "parameter_analysis.txt"
        out_file.write_text("\n".join(lines))


class EndpointPrioritization:
    def __init__(self, probe_results, js_results, param_findings: list[ParameterFinding],
                 fingerprints: dict, output_dir: Path):
        self.probe_results = probe_results      # list of ProbeResult
        self.js_results = js_results            # list of JSAnalysisResult
        self.param_findings = param_findings
        self.fingerprints = fingerprints
        self.output_dir = output_dir
        self.targets: list[PrioritizedTarget] = []

    def run(self) -> list[PrioritizedTarget]:
        display.info("Running endpoint prioritization...")

        # Build URL → param findings map
        param_url_map = {}
        for finding in self.param_findings:
            for url in finding.urls:
                if url not in param_url_map:
                    param_url_map[url] = []
                param_url_map[url].append(finding)

        # Score each live endpoint
        for result in self.probe_results:
            score, reasons = self._score_endpoint(result, param_url_map)
            if score > 0:
                self.targets.append(PrioritizedTarget(
                    url=result.url,
                    risk_score=score,
                    reasons=reasons,
                    priority=self._score_to_priority(score),
                ))

        # Add high-value endpoints from JS analysis
        for js_result in self.js_results:
            for ep in js_result.endpoints:
                reasons = [f"Endpoint found in JS: {js_result.url}"]
                if js_result.secrets:
                    reasons.append(f"{len(js_result.secrets)} secret(s) in same JS file")
                score = 60 + (len(js_result.secrets) * 20)
                self.targets.append(PrioritizedTarget(
                    url=ep,
                    risk_score=min(score, 100),
                    reasons=reasons,
                    priority=self._score_to_priority(score),
                ))

        # Deduplicate and sort
        seen = set()
        unique = []
        for t in self.targets:
            if t.url not in seen:
                seen.add(t.url)
                unique.append(t)
        self.targets = sorted(unique, key=lambda x: x.risk_score, reverse=True)

        self._save_results()

        critical = sum(1 for t in self.targets if t.priority == "CRITICAL")
        high = sum(1 for t in self.targets if t.priority == "HIGH")

        display.success(
            f"Prioritized [bold]{len(self.targets)}[/bold] targets "
            f"([red]{critical} Critical[/red], [yellow]{high} High[/yellow])"
        )
        return self.targets

    def _score_endpoint(self, result, param_url_map: dict) -> tuple[int, list[str]]:
        score = 0
        reasons = []

        # Login page
        if result.has_login:
            score += 30
            reasons.append("Login panel detected")

        # Admin panel
        if result.has_admin:
            score += 40
            reasons.append("Admin panel detected")

        # API endpoint
        if result.is_api:
            score += 20
            reasons.append("API endpoint")

        # Admin / API keywords in URL
        url_lower = result.url.lower()
        parsed = urlparse(result.url)
        path_lower = parsed.path.lower()
        for kw in config.admin_keywords:
            if kw in url_lower:
                score += 15
                reasons.append(f"Keyword '{kw}' in URL")
                break

        # Vulnerable parameters (with contextual weighting)
        url_params = param_url_map.get(result.url, [])
        for finding in url_params:
            score += finding.score // 3
            reasons.append(f"Param '{finding.param}' → {finding.vuln_type}")

            # Contextual weighting: high-value params on sensitive paths
            pname = finding.param.lower()
            if pname in {"id", "user_id", "account_id"}:
                if "/admin" in path_lower or "/api/v2" in path_lower:
                    bonus = 25
                    score += bonus
                    reasons.append(
                        f"Context: '{finding.param}' on sensitive path '{parsed.path}' (+{bonus})"
                    )

        # Low-auth indicators
        if result.status == 403:
            score += 10
            reasons.append("403 Forbidden — may bypass")
        elif result.status == 401:
            score += 15
            reasons.append("401 Unauthorized — auth endpoint")

        # WAF present (still worth noting)
        fp = self.fingerprints.get(result.url)
        if fp and fp.waf:
            reasons.append(f"WAF: {fp.waf}")

        # Contextual down-weighting for obviously public content
        if any(seg in path_lower for seg in ["/blog", "/news", "/static/"]):
            score = int(score * 0.8)
            reasons.append("Context: public content path (blog/news/static) — slightly reduced risk")

        return min(score, 100), reasons

    def _score_to_priority(self, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 35:
            return "MEDIUM"
        return "LOW"

    def _save_results(self):
        lines = ["=" * 60, "ENDPOINT PRIORITIZATION REPORT", "=" * 60]

        for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            tier = [t for t in self.targets if t.priority == priority]
            if not tier:
                continue
            lines.append(f"\n{'─'*40}")
            lines.append(f"[{priority}] — {len(tier)} targets")
            lines.append(f"{'─'*40}")
            for t in tier[:20]:
                lines.append(f"\n  [{t.risk_score:3}/100] {t.url}")
                for r in t.reasons:
                    lines.append(f"    • {r}")

        out_file = self.output_dir / "prioritized_targets.txt"
        out_file.write_text("\n".join(lines))