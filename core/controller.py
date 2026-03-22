import logging
from core.validator import DomainValidator
from core.output_manager import OutputManager
from modules.wayback import WaybackCollector
from modules.parameters import ParameterExtractor
from modules.subdomains import SubdomainEnumerator
from modules.live_hosts import LiveHostDetector
from modules.javascript import JavaScriptAnalyzer
from modules.sensitive_files import SensitiveFileScanner
from modules.screenshots import ScreenshotCapture
from utils.helpers import print_success, print_error, print_info

logger = logging.getLogger(__name__)

class ReconController:
    def __init__(self, domain, save_output=True):
        self.domain = DomainValidator.validate(domain)
        if not self.domain:
            raise ValueError("Invalid domain provided")
        
        self.save_output = save_output
        self.output_manager = OutputManager(self.domain, save_output)
        
        self.wayback_collector = WaybackCollector(self.domain)
        self.parameter_extractor = ParameterExtractor(self.domain)
        self.subdomain_enumerator = SubdomainEnumerator(self.domain)
        self.live_host_detector = LiveHostDetector(self.domain)
        self.js_analyzer = JavaScriptAnalyzer(self.domain)
        self.sensitive_scanner = SensitiveFileScanner(self.domain)
        self.screenshot_capture = ScreenshotCapture(self.domain)
        
        # Store results for report generation
        self.scan_results = {}
        
        logger.info(f"Initialized recon controller for domain: {self.domain}")
    
    def collect_wayback_urls(self):
        print_info(f"Collecting Wayback URLs for {self.domain}")
        try:
            urls = self.wayback_collector.collect()
            self.scan_results['urls'] = urls
            self.output_manager.save_urls(urls)
            logger.info(f"Collected {len(urls)} Wayback URLs")
            return urls
        except Exception as e:
            print_error(f"Failed to collect Wayback URLs: {e}")
            logger.error(f"Wayback collection failed: {e}")
            return []
    
    def extract_parameters(self):
        print_info(f"Extracting parameters for {self.domain}")
        try:
            parameters = self.parameter_extractor.extract()
            self.scan_results['parameters'] = parameters
            self.output_manager.save_parameters(parameters)
            logger.info(f"Extracted {len(parameters)} parameters")
            return parameters
        except Exception as e:
            print_error(f"Failed to extract parameters: {e}")
            logger.error(f"Parameter extraction failed: {e}")
            return []
    
    def discover_subdomains(self):
        print_info(f"Discovering subdomains for {self.domain}")
        try:
            subdomains = self.subdomain_enumerator.enumerate()
            self.scan_results['subdomains'] = subdomains
            self.output_manager.save_subdomains(subdomains)
            logger.info(f"Discovered {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            print_error(f"Failed to discover subdomains: {e}")
            logger.error(f"Subdomain discovery failed: {e}")
            return []
    
    def detect_live_hosts(self):
        print_info(f"Detecting live hosts for {self.domain}")
        try:
            live_hosts = self.live_host_detector.detect()
            self.scan_results['live_hosts'] = live_hosts
            self.output_manager.save_live_hosts(live_hosts)
            logger.info(f"Detected {len(live_hosts)} live hosts")
            return live_hosts
        except Exception as e:
            print_error(f"Failed to detect live hosts: {e}")
            logger.error(f"Live host detection failed: {e}")
            return []
    
    def analyze_javascript(self):
        print_info(f"Analyzing JavaScript for {self.domain}")
        try:
            js_files, js_endpoints = self.js_analyzer.analyze()
            self.scan_results['javascript_files'] = js_files
            self.scan_results['js_endpoints'] = js_endpoints
            self.output_manager.save_javascript_files(js_files)
            self.output_manager.save_js_endpoints(js_endpoints)
            logger.info(f"Found {len(js_files)} JS files and {len(js_endpoints)} endpoints")
            return js_files, js_endpoints
        except Exception as e:
            print_error(f"Failed to analyze JavaScript: {e}")
            logger.error(f"JavaScript analysis failed: {e}")
            return [], []
    
    def scan_sensitive_files(self):
        print_info(f"Scanning sensitive files for {self.domain}")
        try:
            sensitive_files = self.sensitive_scanner.scan()
            self.scan_results['sensitive_files'] = sensitive_files
            self.output_manager.save_sensitive_files(sensitive_files)
            logger.info(f"Found {len(sensitive_files)} sensitive files")
            return sensitive_files
        except Exception as e:
            print_error(f"Failed to scan sensitive files: {e}")
            logger.error(f"Sensitive file scan failed: {e}")
            return []
    
    def capture_screenshots(self):
        print_info(f"Capturing screenshots for {self.domain}")
        try:
            screenshots = self.screenshot_capture.capture()
            self.scan_results['screenshots'] = screenshots
            logger.info(f"Captured {len(screenshots)} screenshots")
            return screenshots
        except Exception as e:
            print_error(f"Failed to capture screenshots: {e}")
            logger.error(f"Screenshot capture failed: {e}")
            return []
    
    def run_full_recon(self):
        print_info(f"Starting full reconnaissance for {self.domain}")
        
        results = {}
        
        results['urls'] = self.collect_wayback_urls()
        results['parameters'] = self.extract_parameters()
        results['subdomains'] = self.discover_subdomains()
        results['live_hosts'] = self.detect_live_hosts()
        
        if results['live_hosts']:
            results['javascript_files'], results['js_endpoints'] = self.analyze_javascript()
            results['screenshots'] = self.capture_screenshots()
        
        results['sensitive_files'] = self.scan_sensitive_files()
        
        # Generate reports
        json_path, html_path = self.output_manager.generate_reports(results)
        
        if json_path and html_path:
            print_success(f"Reports generated:")
            print_success(f"  JSON: {json_path}")
            print_success(f"  HTML: {html_path}")
        
        print_success(f"Full reconnaissance completed for {self.domain}")
        logger.info(f"Full reconnaissance completed for {self.domain}")
        
        return results
