import os
import json
from datetime import datetime
from colorama import Fore, Style
from utils.helpers import save_to_file, print_success, print_warning, ensure_output_dir
from utils.report_generator import ReportGenerator

class OutputManager:
    def __init__(self, domain, save_output=True):
        self.domain = domain
        self.save_output = save_output
        self.output_dir = ensure_output_dir()
        self.screenshot_dir = os.path.join(self.output_dir, "screenshots")
        self.report_generator = ReportGenerator(domain)
        
        if not os.path.exists(self.screenshot_dir):
            os.makedirs(self.screenshot_dir)
        
        if not save_output:
            print_warning("Output saving is disabled. Results will not be saved to files.")
    
    def save_urls(self, urls):
        if not self.save_output:
            self.display_results("URLs", urls)
            return None
        filepath = save_to_file("urls.txt", urls)
        print_success(f"Saved {len(urls)} URLs to {filepath}")
        return filepath
    
    def save_parameters(self, parameters):
        if not self.save_output:
            self.display_results("Parameters", parameters)
            return None
        filepath = save_to_file("parameters.txt", parameters)
        print_success(f"Saved {len(parameters)} parameters to {filepath}")
        return filepath
    
    def save_subdomains(self, subdomains):
        if not self.save_output:
            self.display_results("Subdomains", subdomains)
            return None
        filepath = save_to_file("subdomains.txt", subdomains)
        print_success(f"Saved {len(subdomains)} subdomains to {filepath}")
        return filepath
    
    def save_live_hosts(self, hosts):
        if not self.save_output:
            self.display_results("Live Hosts", hosts)
            return None
        filepath = save_to_file("live_hosts.txt", hosts)
        print_success(f"Saved {len(hosts)} live hosts to {filepath}")
        return filepath
    
    def save_javascript_files(self, js_files):
        if not self.save_output:
            self.display_results("JavaScript Files", js_files)
            return None
        filepath = save_to_file("javascript_files.txt", js_files)
        print_success(f"Saved {len(js_files)} JavaScript files to {filepath}")
        return filepath
    
    def save_js_endpoints(self, endpoints):
        if not self.save_output:
            self.display_results("JavaScript Endpoints", endpoints)
            return None
        filepath = save_to_file("js_endpoints.txt", endpoints)
        print_success(f"Saved {len(endpoints)} JS endpoints to {filepath}")
        return filepath
    
    def save_sensitive_files(self, files):
        if not self.save_output:
            self.display_results("Sensitive Files", files)
            return None
        filepath = save_to_file("sensitive_files.txt", files)
        print_success(f"Saved {len(files)} sensitive files to {filepath}")
        return filepath
    
    def save_api_endpoints(self, endpoints):
        if not self.save_output:
            self.display_results("API Endpoints", endpoints)
            return None
        filepath = save_to_file("api_endpoints.txt", endpoints)
        print_success(f"Saved {len(endpoints)} API endpoints to {filepath}")
        return filepath
    
    def display_results(self, title, results):
        """Display results on screen when output saving is disabled"""
        if not results:
            print_warning(f"No {title.lower()} found")
            return
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] {title} Results ({len(results)} found){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Show first 20 results
        for i, result in enumerate(results[:20], 1):
            print(f"{Fore.GREEN}[{i:2d}] {Style.RESET_ALL}{result}")
        
        if len(results) > 20:
            print(f"\n{Fore.YELLOW}... and {len(results) - 20} more {title.lower()}{Style.RESET_ALL}")
        
        print(f"\n{Fore.MAGENTA}Total {title.lower()}: {len(results)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def get_screenshot_path(self, hostname):
        return os.path.join(self.screenshot_dir, f"{hostname}.png")
    
    def generate_reports(self, scan_data):
        """Generate both JSON and HTML reports"""
        if not self.save_output:
            print_warning("Report generation is disabled due to output saving being disabled.")
            return None, None
        
        try:
            # Generate JSON report
            json_path = self.report_generator.generate_json_report(scan_data)
            print_success(f"Generated JSON report: {json_path}")
            
            # Generate HTML report
            html_path = self.report_generator.generate_html_report(scan_data)
            print_success(f"Generated HTML report: {html_path}")
            
            return json_path, html_path
            
        except Exception as e:
            print_warning(f"Failed to generate reports: {e}")
            return None, None
