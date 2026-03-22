import re
import requests
import os
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import remove_duplicates, print_info, print_success, print_error

class JavaScriptAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.urls_file = os.path.join("output", "urls.txt")
        self.live_hosts_file = os.path.join("output", "live_hosts.txt")
    
    def analyze(self):
        print_info("Analyzing JavaScript files...")
        
        js_files = self._discover_js_files()
        if not js_files:
            print_warning("No JavaScript files found")
            return [], []
        
        print_info(f"Found {len(js_files)} JavaScript files")
        
        js_endpoints = self._extract_endpoints_from_js(js_files)
        
        return js_files, js_endpoints
    
    def _discover_js_files(self):
        js_files = set()
        
        if os.path.exists(self.urls_file):
            js_files.update(self._extract_js_from_urls())
        
        if os.path.exists(self.live_hosts_file):
            js_files.update(self._crawl_live_hosts_for_js())
        
        return list(js_files)
    
    def _extract_js_from_urls(self):
        js_files = set()
        
        try:
            with open(self.urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            for url in urls:
                if url.lower().endswith('.js'):
                    js_files.add(url)
                elif any(pattern in url.lower() for pattern in ['script', 'js/', 'javascript']):
                    js_files.add(url)
            
        except Exception as e:
            print_error(f"Error extracting JS from URLs: {e}")
        
        return js_files
    
    def _crawl_live_hosts_for_js(self):
        js_files = set()
        
        try:
            with open(self.live_hosts_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
            
            def crawl_host(host):
                try:
                    response = requests.get(host, timeout=10, verify=False)
                    content = response.text
                    
                    js_pattern = r'(?:src|href)=["\']([^"\']+\.js)["\']'
                    matches = re.findall(js_pattern, content, re.IGNORECASE)
                    
                    found_js = []
                    for match in matches:
                        if match.startswith('http'):
                            found_js.append(match)
                        else:
                            full_url = urljoin(host, match)
                            found_js.append(full_url)
                    
                    return found_js
                    
                except:
                    return []
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_host = {executor.submit(crawl_host, host): host for host in hosts[:20]}
                
                for future in as_completed(future_to_host):
                    js_files.update(future.result())
            
        except Exception as e:
            print_error(f"Error crawling hosts for JS: {e}")
        
        return js_files
    
    def _extract_endpoints_from_js(self, js_files):
        endpoints = set()
        
        def analyze_js_file(js_url):
            try:
                response = requests.get(js_url, timeout=15, verify=False)
                content = response.text
                
                patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/v[0-9]/[^"\']+)["\']',
                    r'["\'](/rest/[^"\']+)["\']',
                    r'["\'](/graphql[^"\']*)["\']',
                    r'["\'](/admin/[^"\']+)["\']',
                    r'["\'](/internal/[^"\']+)["\']',
                    r'["\'](/[a-zA-Z0-9/_-]+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.[^(]+\(["\']([^"\']+)["\']',
                    r'\.get\(["\']([^"\']+)["\']',
                    r'\.post\(["\']([^"\']+)["\']',
                ]
                
                found_endpoints = []
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    found_endpoints.extend(matches)
                
                return found_endpoints
                
            except:
                return []
        
        print_info("Extracting endpoints from JavaScript files...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_js = {executor.submit(analyze_js_file, js_url): js_url for js_url in js_files[:50]}
            
            for future in as_completed(future_to_js):
                try:
                    endpoints.update(future.result())
                except:
                    continue
        
        filtered_endpoints = []
        for endpoint in endpoints:
            if (endpoint.startswith('/') and 
                not endpoint.endswith('.js') and 
                not endpoint.endswith('.css') and
                len(endpoint) > 3):
                filtered_endpoints.append(endpoint)
        
        unique_endpoints = remove_duplicates(filtered_endpoints)
        
        print_success(f"Extracted {len(unique_endpoints)} endpoints from JavaScript")
        return unique_endpoints
