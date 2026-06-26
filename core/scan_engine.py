"""
Recon Control Engine — v1.2
Orchestrates all scanning modules in sequence, manages output, and produces summary.

v1.2 changes:
  - Phase 2: TCP port scan fallback (80/443/8080) when HTTP probe yields 0 live hosts
  - Phase 2: 401/403 explicitly treated as LIVE; timeout bumped to 15s
  - Phase 4: fallback_urls (from Phase 3) passed to JSIntelligence for Deep JS Crawl
  - Global crash protection: every phase wrapped in try/except — tool NEVER crashes;
    always proceeds to save the final report with whatever data was collected
"""

import asyncio
import socket
import sys
import time
import random
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from rich.progress import Progress, SpinnerColumn, TextColumn
import aiohttp

from config.settings import get_output_dirs
from modules.subdomain_discovery import SubdomainDiscovery
from modules.http_probe import HTTPProbe
from modules.url_discovery import URLDiscovery
from modules.js_intelligence import JSIntelligence
from modules.sensitive_assets import SensitiveAssetDetection
from modules.fingerprinting import AssetFingerprinting
from modules.vulnerability_scanner import NucleiScanner
from modules.screenshots import ScreenshotCapture
from intelligence.analysis import ParameterIntelligence, EndpointPrioritization
from intelligence.correlation_modern import CorrelationEngine
from core.display import Display
from core.logger import get_logger, get_audit_logger
# Hybrid Reporting: Import both modern and classic reporters
from core.reporter_modern import Reporter as ModernReporter
from core.reporter import Reporter as ClassicReporter

logger = get_logger("scan_engine")
display = Display()

# Ports probed in TCP fallback when HTTP gives 0 live hosts
TCP_FALLBACK_PORTS = [80, 443, 8080]


class ScanEngine:
    def __init__(self, targets: list[str], threads: int = 20, timeout: int = 15,
                 output_dir: str = "output", full_scan: bool = False,
                 generate_graph: bool = False, screenshots: bool = True,
                 passive_only: bool = False, verbose: bool = False,
                 nuclei: bool = False,
                 simple_report: bool = False, debug: bool = False,
                 delay: bool = False):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout          # Default bumped to 15s in v1.2
        self.output_dir = output_dir
        self.full_scan = full_scan
        self.generate_graph = generate_graph
        self.screenshots = screenshots
        self.passive_only = passive_only
        self.nuclei = nuclei
        self.verbose = verbose
        self.simple_report = simple_report  # False = modern report (default), True = classic report
        self.debug = debug
        self.delay = delay                # Execution jitter flag
        
        # Delay range for execution jitter (0.5s to 2s)
        self.delay_range = (0.5, 2.0) if delay else None
        
        # Re-initialize display with debug flag
        global display
        display = Display(debug=debug)

    # ──────────────────────────────────────────────────────────────
    # Top-level runner
    # ──────────────────────────────────────────────────────────────

    async def run(self):
        start_time = time.time()

        for domain in self.targets:
            try:
                await self._scan_domain(domain)
            except Exception as e:
                display.error(f"Scan failed for {domain}: {e}")
                logger.exception(f"Scan failed for {domain}")

        elapsed = time.time() - start_time
        display.console.print()
        display.console.rule("[bold red] All Scans Complete [/bold red]")
        display.info(f"Total time: [bold]{elapsed:.1f}s[/bold]")

    # ──────────────────────────────────────────────────────────────
    # Per-domain scan — every phase is individually crash-protected
    # ──────────────────────────────────────────────────────────────

    async def _scan_domain(self, domain: str):
        display.section(f"Scanning: {domain}")
        dirs = get_output_dirs(domain, self.output_dir)
        output_dir    = dirs["base"]
        screenshot_dir = dirs["screenshots"]

        scan_start = time.time()

        # Accumulated data — defaults so the report always has something
        subdomains:        list[str] = []
        live_hosts:        list[str] = []
        api_endpoints:     list[str] = []
        all_urls:          list[str] = []
        urls:              list[str] = []
        parameters:        list[str] = []
        js_results:        list      = []
        sensitive_findings:list      = []
        cloud_assets:      list[str] = []
        fingerprints:      list      = []
        param_findings:    list      = []
        prioritized:       list      = []
        correlated:        list      = []
        probe_results:     list      = []
        nuclei_findings:   list[dict] = []

        # Initialize forensic audit logger
        audit_logger = get_audit_logger(output_dir, domain)
        audit_logger.start_time = datetime.now()

        # ── Phase 1: Subdomain Discovery ──────────────────────────
        phase_name = "Subdomain Discovery"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(1, 7, phase_name, "subdomain")
            audit_logger.log_phase_start(1, phase_name)
            
            try:
                # Use progress bar only (no nested status)
                with display.progress_bar(phase_name) as progress:
                    task = progress.add_task(f"Scanning subdomains for {domain}...", total=100)
                    
                    sub_engine = SubdomainDiscovery(
                        domain=domain,
                        output_dir=output_dir,
                        timeout=self.timeout,
                        passive_only=self.passive_only,
                        delay_range=self.delay_range,
                    )
                    
                    # Update progress callback
                    async def update_progress(count):
                        progress.update(task, completed=min(count, 100), description=f"Scanning subdomains for {domain}... Found: {count}")
                    
                    # Run the discovery
                    subdomains = await sub_engine.run()
                    await update_progress(len(subdomains))
                        
                display.success(f"Found {len(subdomains)} subdomains")
                audit_logger.log_phase_end(1, len(subdomains), "Success")
            except Exception as e:
                display.warning(f"Phase 1 error (subdomain discovery): {e} — continuing")
                logger.exception("Phase 1 failed")
                audit_logger.log_phase_end(1, 0, "Failed", str(e))
                subdomains = []  # Ensure subdomains is initialized even on failure
        else:
            display.warning(f"[-] Skipping {phase_name}....")
            subdomains = []

        # Lightweight WAF detection
        waf_name = None
        try:
            waf_name = await self._detect_waf(subdomains)
        except Exception:
            pass
        waf_slow_mode = bool(waf_name)

        # ── Phase 2: HTTP Probing ─────────────────────────────────
        phase_name = "HTTP Probing & Endpoint Discovery"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(2, 7, phase_name, "probe")
            audit_logger.log_phase_start(2, phase_name)
            
            try:
                probe_threads = self.threads
                delay_range   = None
                if waf_slow_mode:
                    probe_threads = max(2, self.threads // 3 or 2)
                    delay_range   = (0.5, 2.0)

                # Use progress bar only (no nested status)
                with display.progress_bar(phase_name) as progress:
                    task = progress.add_task(f"Probing {len(subdomains)} subdomains...", total=len(subdomains))
                    
                    probe_engine = HTTPProbe(
                        subdomains=subdomains,
                        output_dir=output_dir,
                        timeout=self.timeout,
                        threads=probe_threads,
                        delay_range=delay_range,
                    )
                    
                    # Run the probe
                    probe_results, api_endpoints = await probe_engine.run()
                    
                    # Update progress to complete
                    progress.update(task, completed=len(subdomains), description=f"Probing {len(subdomains)} subdomains... Live: {len([r for r in probe_results if r.status in range(200, 500) or r.status in (401, 403)])}")
                    
                    # 401 and 403 are LIVE — authentication-gated hosts are still targets
                    live_hosts = [
                        r.url for r in probe_results
                        if r.status in range(200, 500) or r.status in (401, 403)
                    ]
                    live_hosts = list(dict.fromkeys(live_hosts))  # deduplicate, preserve order

                forbidden_count = sum(1 for r in probe_results if r.status in (401, 403))
                if forbidden_count:
                    display.info(
                        f"{forbidden_count} hosts returned 401/403 — treated as LIVE (authentication-gated)"
                    )
                display.success(f"Found {len(live_hosts)} live hosts")
                audit_logger.log_phase_end(2, len(live_hosts), "Success")

                # ── TCP Fallback ──────────────────────────────────────
                # If HTTP probing found 0 live hosts, do a quick TCP port scan.
                # Any open port forces the host into live_hosts.
                if not live_hosts and subdomains:
                    display.warning(
                        "HTTP probe returned 0 live hosts — "
                        f"running TCP fallback scan on ports {TCP_FALLBACK_PORTS}..."
                    )
                    tcp_live = await self._tcp_port_scan(subdomains)
                    if tcp_live:
                        live_hosts.extend(tcp_live)
                        live_hosts = list(dict.fromkeys(live_hosts))
                        display.success(
                            f"TCP fallback recovered {len(tcp_live)} additional live hosts"
                        )
                        logger.info(f"TCP fallback added {len(tcp_live)} hosts: {tcp_live[:5]}")
                        # Persist
                        live_file = output_dir / "live_hosts.txt"
                        live_file.write_text("\n".join(live_hosts))
                    else:
                        display.warning("TCP fallback: no open ports found on any subdomain")

            except Exception as e:
                display.warning(f"Phase 2 error (HTTP probe): {e} — continuing with empty live_hosts")
                logger.exception("Phase 2 failed")
                audit_logger.log_phase_end(2, len(live_hosts), "Failed", str(e))
        else:
            display.warning(f"[-] Skipping {phase_name}....")
            live_hosts = []
            probe_results = []
            api_endpoints = []

        # ── Phase 3: URL & Parameter Discovery ───────────────────
        phase_name = "URL & Parameter Discovery"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(3, 7, phase_name, "url")
            audit_logger.log_phase_start(3, phase_name)
        
        # Skip gracefully if no live hosts
        if not live_hosts:
            display.warning("No live hosts found — skipping URL & Parameter Discovery")
            audit_logger.log_phase_end(3, 0, "Skipped", "No live hosts available")
            urls = []
            parameters = []
            param_findings = []
            all_urls = []
        else:
            try:
                # Use progress bar only (no nested status)
                with display.progress_bar("URL Discovery") as progress:
                    task_wayback = progress.add_task("Wayback Machine", total=100)
                    task_commoncrawl = progress.add_task("CommonCrawl", total=100)
                    task_crawl = progress.add_task("Live Crawling", total=100)
                    
                    url_engine = URLDiscovery(
                        domain=domain,
                        live_hosts=live_hosts,
                        output_dir=output_dir,
                        timeout=self.timeout,
                        threads=self.threads,
                        delay_range=self.delay_range,
                    )
                    
                    # Run the discovery
                    urls, parameters = await url_engine.run()
                    
                    # Convert parameters dict to param_findings list format for reporter
                    param_findings = []
                    for param_name, param_urls in parameters.items():
                        # Simple vulnerability classification based on parameter name
                        severity = "Medium"
                        vuln_type = "Information Disclosure"
                        
                        if any(x in param_name.lower() for x in ["id", "user", "pass", "key", "token", "secret"]):
                            severity = "High"
                            vuln_type = "Sensitive Parameter"
                        elif any(x in param_name.lower() for x in ["admin", "debug", "test", "dev"]):
                            severity = "Medium" 
                            vuln_type = "Development Parameter"
                        elif any(x in param_name.lower() for x in ["file", "upload", "download", "path"]):
                            severity = "Medium"
                            vuln_type = "File Operation"
                        
                        # Create a simple param finding object
                        class ParamFinding:
                            def __init__(self, param, vuln_type, severity):
                                self.param = param
                                self.vuln_type = vuln_type
                                self.severity = severity
                        
                        param_findings.append(ParamFinding(param_name, vuln_type, severity))
                    
                    # Update progress to complete
                    progress.update(task_wayback, completed=100, description=f"Wayback Machine - Found: {len(urls)}")
                    progress.update(task_commoncrawl, completed=100)
                    progress.update(task_crawl, completed=100)
                        
                all_urls = list(urls)

                # URL-to-Live Fallback: >10 URLs → extract unique domains as live hosts
                if len(all_urls) > 10:
                    display.info(
                        f"URL-to-Live Fallback: {len(all_urls)} URLs discovered — extracting unique domains..."
                    )
                    url_hosts: set[str] = set()
                    for url in all_urls:
                        try:
                            parsed = urlparse(url)
                            if parsed.netloc:
                                url_hosts.add(f"https://{parsed.netloc}")
                                url_hosts.add(f"http://{parsed.netloc}")
                        except Exception:
                            continue

                    live_hosts_set = set(live_hosts)
                    added_count = 0
                    for host in url_hosts:
                        if host not in live_hosts_set:
                            live_hosts.append(host)
                            live_hosts_set.add(host)
                            added_count += 1

                    if added_count:
                        display.success(f"URL-to-Live Fallback added {added_count} additional live hosts")
                        (output_dir / "live_hosts.txt").write_text("\n".join(live_hosts))

                audit_logger.log_phase_end(3, len(urls), "Success")

            except Exception as e:
                display.warning(f"Phase 3 error (URL discovery): {e} — continuing")
                logger.exception("Phase 3 failed")
                audit_logger.log_phase_end(3, len(urls) if 'urls' in locals() else 0, "Failed", str(e))
                urls = []
                parameters = []
                param_findings = []
                all_urls = []
        
            else:
                display.warning(f"[-] Skipping {phase_name}....")
                urls = []
                parameters = []
                param_findings = []
                all_urls = []

        # ── Phase 4: JavaScript Intelligence ─────────────────────
        phase_name = "JavaScript Intelligence"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(4, 7, phase_name, "js")
            audit_logger.log_phase_start(4, phase_name)
        
        # Skip gracefully if no live hosts
        if not live_hosts:
            display.warning("No live hosts found — skipping JavaScript Intelligence")
            audit_logger.log_phase_end(4, 0, "Skipped", "No live hosts available")
            js_results = []
        else:
            try:
                # Use progress bar only (no nested status)
                with display.progress_bar("JavaScript Intelligence") as progress:
                    task_collect = progress.add_task("Collecting JS files", total=100)
                    task_analyze = progress.add_task("Analyzing patterns", total=100)
                    task_match = progress.add_task("Matching hashes", total=100)
                    
                    js_engine = JSIntelligence(
                        live_hosts=live_hosts,
                        output_dir=output_dir,
                        timeout=self.timeout,
                        threads=self.threads,
                        fallback_urls=all_urls,
                        delay_range=self.delay_range,
                    )
                    
                    # Run the analysis
                    js_results = await js_engine.run()
                    secrets_count = sum(len(r.secrets) for r in js_results)
                    
                    # Update progress to complete
                    progress.update(task_collect, completed=100, description=f"Collecting JS files - Found: {len(js_results)}")
                    progress.update(task_analyze, completed=100, description=f"Analyzing patterns - Secrets: {secrets_count}")
                    progress.update(task_match, completed=100)
                    
                display.success(f"Analyzed {len(js_results)} JavaScript files")
                secrets_count = sum(len(r.secrets) for r in js_results)
                audit_logger.log_phase_end(4, len(js_results), "Success", 
                                           details=f"Secrets found: {secrets_count}")
            except Exception as e:
                display.warning(f"Phase 4 error (JS intelligence): {e} — continuing")
                logger.exception("Phase 4 failed")
                audit_logger.log_phase_end(4, 0, "Failed", str(e))
                js_results = []
        
            else:
                display.warning(f"[-] Skipping {phase_name}....")
                js_results = []

        # ── Phase 5: Sensitive Asset Detection ───────────────────
        phase_name = "Sensitive Asset Detection"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(5, 7, phase_name, "sensitive")
            audit_logger.log_phase_start(5, phase_name)
        
        # Skip gracefully if no live hosts
        if not live_hosts:
            display.warning("No live hosts found — skipping Sensitive Asset Detection")
            audit_logger.log_phase_end(5, 0, "Skipped", "No live hosts available")
            sensitive_findings = []
            cloud_assets = []
        else:
            try:
                # Use progress bar only (no nested status)
                with display.progress_bar("Sensitive Asset Detection") as progress:
                    task_baseline = progress.add_task("Building baselines", total=100)
                    task_scan = progress.add_task("Scanning files", total=len(live_hosts))
                    task_cloud = progress.add_task("Detecting cloud assets", total=100)
                    
                    sensitive_engine = SensitiveAssetDetection(
                        live_hosts=live_hosts,
                        output_dir=output_dir,
                        timeout=self.timeout,
                        threads=self.threads,
                        delay_range=self.delay_range,
                    )
                    
                    # Run the detection
                    sensitive_findings, cloud_assets = await sensitive_engine.run()
                    
                    # Update progress to complete
                    progress.update(task_baseline, completed=100)
                    progress.update(task_scan, completed=len(live_hosts), description=f"Scanning files - Found: {len(sensitive_findings)}")
                    progress.update(task_cloud, completed=100, description=f"Detecting cloud assets - Found: {len(cloud_assets)}")
                    
                display.success(f"Found {len(sensitive_findings)} sensitive files, {len(cloud_assets)} cloud assets")
                audit_logger.log_phase_end(5, len(sensitive_findings) + len(cloud_assets), "Success",
                                           details=f"Sensitive: {len(sensitive_findings)}, Cloud: {len(cloud_assets)}")
            except Exception as e:
                display.warning(f"Phase 5 error (sensitive assets): {e} — continuing")
                logger.exception("Phase 5 failed")
                audit_logger.log_phase_end(5, 0, "Failed", str(e))
                sensitive_findings = []
                cloud_assets = []
        
            else:
                display.warning(f"[-] Skipping {phase_name}....")
                sensitive_findings = []
                cloud_assets = []

        # ── Phase 6: Intelligence & Analysis ─────────────────────
        phase_name = "Intelligence & Correlation"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(6, 7, phase_name, "fingerprint")
            audit_logger.log_phase_start(6, phase_name)
        
        fingerprints = []
        param_findings = []
        prioritized = []
        correlated = []
        
        try:
            # Use progress bar only (no nested status)
            with display.progress_bar("Intelligence & Analysis") as progress:
                task_fingerprint = progress.add_task("Fingerprinting", total=100)
                task_param = progress.add_task("Parameter Analysis", total=100)
                task_priority = progress.add_task("Endpoint Prioritization", total=100)
                task_correlation = progress.add_task("Correlation Analysis", total=100)
                
                # Always try to run fingerprinting - imports handled at module level
                fp_engine = AssetFingerprinting(
                    live_hosts=live_hosts,
                    output_dir=output_dir,
                    timeout=self.timeout,
                    threads=self.threads,
                    delay_range=self.delay_range,
                )
                fingerprints = await fp_engine.run()
                progress.update(task_fingerprint, completed=100, description=f"Fingerprinting - Found: {len(fingerprints)}")

                # Optional Nuclei vulnerability scan (after fingerprinting)
                if self.nuclei:
                    nuclei_scanner = NucleiScanner(
                        targets=live_hosts,
                        output_dir=output_dir,
                        timeout=max(self.timeout * 8, 120),
                    )
                    nuclei_findings = await nuclei_scanner.run()

                # Parameter Intelligence Analysis
                param_engine = ParameterIntelligence(parameters=parameters, output_dir=output_dir)
                param_findings = param_engine.run()
                progress.update(task_param, completed=100, description=f"Parameter Analysis - Found: {len(param_findings)}")

                # Endpoint Prioritization
                priority_engine = EndpointPrioritization(
                    probe_results=probe_results,
                    js_results=js_results,
                    param_findings=param_findings,
                    fingerprints=fingerprints,
                    output_dir=output_dir,
                )
                prioritized = priority_engine.run()
                progress.update(task_priority, completed=100, description=f"Endpoint Prioritization - Found: {len(prioritized)}")

                # Correlation Analysis
                correlation_engine = CorrelationEngine(
                    domain=domain,
                    probe_results=probe_results,
                    js_results=js_results,
                    fingerprints=fingerprints,
                    sensitive_findings=sensitive_findings,
                    prioritized_targets=prioritized,
                    output_dir=output_dir,
                )
                correlated = correlation_engine.run()
                progress.update(task_correlation, completed=100, description=f"Correlation Analysis - Found: {len(correlated)}")
                    
            audit_logger.log_phase_end(6, len(fingerprints), "Success",
                                      details=f"Fingerprints: {len(fingerprints)}, Prioritized: {len(prioritized)}")
        except Exception as e:
            display.warning(f"[!] Phase 6 failed due to missing dependencies, skipping to Phase 7...")
            logger.exception(f"Phase 6 failed: {e}")
            audit_logger.log_phase_end(6, 0, "Failed", str(e))
            fingerprints = []
            param_findings = []
            prioritized = []
            correlated = []
            nuclei_findings = []
        else:
            display.warning(f"[-] Skipping {phase_name}....")
            fingerprints = []
            param_findings = []
            prioritized = []
            correlated = []
            nuclei_findings = []

        # ── Phase 7: Screenshots & Report ─────────────────────────
        phase_name = "Screenshots & Report"
        if input(f'[?] Start {phase_name}? (Y/n): ').lower() != 'n':
            display.phase_start(7, 7, phase_name, "screenshot")
            audit_logger.log_phase_start(7, "Screenshots & Report Generation")

        # Screenshots — always attempted, crash-protected
        screenshot_count = 0
        if self.screenshots:
            try:
                # Use progress bar only (no nested status)
                with display.progress_bar("Screenshot Capture") as progress:
                    task = progress.add_task("Capturing screenshots", total=len(live_hosts[:30] if live_hosts else []))
                    
                    ss_engine = ScreenshotCapture(
                        live_hosts=live_hosts[:30] if live_hosts else [],
                        screenshot_dir=screenshot_dir,
                        threads=min(self.threads, 5),
                        all_urls=all_urls,   # Force-logic fallback when live_hosts=0
                    )
                    
                    # Run screenshot capture
                    screenshot_results = await ss_engine.run()
                    screenshot_count = len(screenshot_results) if screenshot_results else 0
                    
                    # Update progress to complete
                    progress.update(task, completed=screenshot_count, description=f"Capturing screenshots - Completed: {screenshot_count}")
                    
            except Exception as e:
                display.warning(f"Phase 7 screenshots error: {e} — skipping screenshots")
                logger.exception("Phase 7 screenshots failed")

        # Report — always generated, even if all phases above failed
        # Hybrid Reporting: Modern report by default, Classic when --simple is used
        report_status = "Failed"
        try:
            if self.simple_report:
                # Use Classic Reporter (simple HTML)
                display.info("Generating [bold yellow]Classic[/bold yellow] HTML report...")
                reporter = ClassicReporter(domain, output_dir=self.output_dir)
                reporter.generate(
                    subdomains=subdomains,
                    live_hosts=live_hosts,
                    api_endpoints=api_endpoints,
                    urls=urls,
                    parameters=parameters,
                    js_results=js_results,
                    sensitive_findings=sensitive_findings,
                    cloud_assets=cloud_assets,
                    fingerprints=fingerprints,
                    param_findings=param_findings,
                    prioritized=prioritized,
                    correlated=correlated,
                )
                display.success("Classic report generated")
                report_status = "Success (Classic)"
            else:
                # Use Modern Reporter (Bootstrap dark theme) - DEFAULT
                display.info("Generating [bold green]Modern[/bold green] Bootstrap HTML report...")
                reporter = ModernReporter(domain, output_dir=self.output_dir)
                reporter.generate(
                    subdomains=subdomains,
                    live_hosts=live_hosts,
                    api_endpoints=api_endpoints,
                    urls=urls,
                    parameters=parameters,
                    js_results=js_results,
                    sensitive_findings=sensitive_findings,
                    cloud_assets=cloud_assets,
                    fingerprints=fingerprints,
                    param_findings=param_findings,
                    prioritized=prioritized,
                    correlated=correlated,
                )
                display.success("Modern report generated")
                report_status = "Success (Modern)"
        except Exception as e:
            display.error(f"Report generation failed: {e}")
            logger.exception("Report generation failed")
            report_status = f"Failed: {str(e)}"
        
        # Log Phase 7 completion
        if screenshot_count > 0:
            audit_logger.log_phase_end(7, screenshot_count, "Success", 
                                       details=f"Report: {report_status}, Screenshots: {screenshot_count}")
        else:
            display.warning(f"[-] Skipping {phase_name}....")
            # Still generate a minimal report even if screenshots are skipped
            try:
                if self.simple_report:
                    display.info("Generating [bold yellow]Minimal Classic[/bold yellow] HTML report...")
                    reporter = ClassicReporter(domain, output_dir=self.output_dir)
                    reporter.generate(
                        subdomains=subdomains,
                        live_hosts=live_hosts,
                        api_endpoints=api_endpoints,
                        urls=urls,
                        parameters=parameters,
                        js_results=js_results,
                        sensitive_findings=sensitive_findings,
                        cloud_assets=cloud_assets,
                        fingerprints=fingerprints,
                        param_findings=param_findings,
                        prioritized=prioritized,
                        correlated=correlated,
                    )
                    display.success("Minimal classic report generated")
                else:
                    display.info("Generating [bold green]Minimal Modern[/bold green] Bootstrap HTML report...")
                    reporter = ModernReporter(domain, output_dir=self.output_dir)
                    reporter.generate(
                        subdomains=subdomains,
                        live_hosts=live_hosts,
                        api_endpoints=api_endpoints,
                        urls=urls,
                        parameters=parameters,
                        js_results=js_results,
                        sensitive_findings=sensitive_findings,
                        cloud_assets=cloud_assets,
                        fingerprints=fingerprints,
                        param_findings=param_findings,
                        prioritized=prioritized,
                        correlated=correlated,
                    )
                    display.success("Minimal modern report generated")
            except Exception as e:
                display.error(f"Minimal report generation failed: {e}")
                logger.exception("Minimal report generation failed")

        # ── Summary ───────────────────────────────────────────────
        elapsed  = time.time() - scan_start
        critical = sum(1 for t in prioritized if t.priority == "CRITICAL")
        high     = sum(1 for t in prioritized if t.priority == "HIGH")
        secrets  = sum(len(r.secrets) for r in js_results)
        vuln_total = len(nuclei_findings)

        def _nuclei_severity_count(level: str) -> int:
            level = level.lower()
            count = 0
            for finding in nuclei_findings:
                sev = (
                    str(finding.get("severity", "")) or
                    str(finding.get("info", {}).get("severity", ""))
                ).lower()
                if sev == level:
                    count += 1
            return count

        vuln_critical = _nuclei_severity_count("critical")
        vuln_high = _nuclei_severity_count("high")

        # Log findings summary
        audit_logger.log_findings_summary({
            'subdomains': len(subdomains),
            'live_hosts': len(live_hosts),
            'api_endpoints': len(api_endpoints),
            'urls': len(urls),
            'parameters': len(parameters),
            'js_files': len(js_results),
            'secrets': secrets,
            'sensitive_files': len(sensitive_findings),
            'cloud_assets': len(cloud_assets),
            'critical_targets': critical,
            'high_targets': high,
            'vulnerabilities': vuln_total,
            'vuln_critical': vuln_critical,
            'vuln_high': vuln_high,
        })
        
        # Finalize audit log
        audit_logger.finalize_log(elapsed)

        display.console.print()
        display.summary_box(domain, {
            "Subdomains":       len(subdomains),
            "Live Hosts":       len(live_hosts),
            "API Endpoints":    len(api_endpoints),
            "URLs":             len(urls),
            "Parameters":       len(parameters),
            "JS Files":         len(js_results),
            "Secrets Found":    secrets,
            "Sensitive Files":  len(sensitive_findings),
            "Cloud Assets":     len(cloud_assets),
            "Critical Targets": critical,
            "High Targets":     high,
            "Vulnerabilities Found": vuln_total,
            "Vuln Critical":    vuln_critical,
            "Vuln High":        vuln_high,
            "Scan Duration":    f"{elapsed:.1f}s",
            "Output Directory": str(output_dir),
        })

        logger.info(
            f"[{domain}] Scan complete in {elapsed:.1f}s — "
            f"{len(subdomains)} subs, {len(live_hosts)} live, "
            f"{critical} critical targets"
        )

    # ──────────────────────────────────────────────────────────────
    # TCP Port Scan Fallback (Phase 2)
    # ──────────────────────────────────────────────────────────────

    async def _tcp_port_scan(self, subdomains: list[str]) -> list[str]:
        """
        Async TCP port scan on common ports.
        If a port is open, that host is added to live_hosts with the
        appropriate scheme (http for 80/8080, https for 443).
        """
        live: list[str] = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent socket connections
        loop = asyncio.get_event_loop()

        async def _check(host: str, port: int):
            scheme = "https" if port == 443 else "http"
            async with semaphore:
                try:
                    # Use asyncio to open a TCP connection with a short timeout
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=3.0,
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                    live.append(url)
                    logger.debug(f"TCP open: {host}:{port}")
                except Exception:
                    pass  # Port closed or unreachable

        tasks = [
            asyncio.create_task(_check(sub, port))
            for sub in subdomains[:100]   # Cap to 100 hosts
            for port in TCP_FALLBACK_PORTS
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Deduplicate while preserving insertion order
        return list(dict.fromkeys(live))

    # ──────────────────────────────────────────────────────────────
    # WAF Detection
    # ──────────────────────────────────────────────────────────────

    async def _detect_waf(self, subdomains: list[str]) -> str | None:
        """
        Probe a small sample of hosts to detect common WAFs and enable
        adaptive rate limiting when needed.
        """
        if not subdomains:
            return None

        sample = subdomains[:min(10, len(subdomains))]
        patterns = {
            "cloudflare":   "Cloudflare",
            "cf-ray":       "Cloudflare",
            "akamai":       "Akamai",
            "mod_security": "ModSecurity",
            "modsecurity":  "ModSecurity",
            "x-sucuri-id":  "Sucuri",
            "imperva":      "Imperva",
            "x-imperva":    "Imperva",
        }

        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as session:
                for host in sample:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}"
                        try:
                            await asyncio.sleep(random.uniform(0.1, 0.4))
                            async with session.get(url, allow_redirects=True) as resp:
                                header_blob = " ".join(
                                    f"{k.lower()}:{v.lower()}"
                                    for k, v in resp.headers.items()
                                )
                                body = (await resp.text(errors="ignore"))[:3000].lower()
                                blob = header_blob + " " + body
                                for sig, name in patterns.items():
                                    if sig in blob:
                                        display.info(
                                            f"WAF detected ([bold]{name}[/bold]) — "
                                            "enabling adaptive rate limiting"
                                        )
                                        logger.info(f"WAF detected: {name} on {host}")
                                        return name
                        except Exception:
                            continue
        except Exception:
            return None

        return None