import subprocess
import os
from utils.helpers import check_tool_installed, remove_duplicates, print_info, print_success, print_error, print_warning

class LiveHostDetector:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains_file = os.path.join("output", "subdomains.txt")
    
    def detect(self):
        print_info("Detecting live hosts...")
        
        if not os.path.exists(self.subdomains_file):
            print_error("Subdomains file not found. Run subdomain enumeration first.")
            return []
        
        live_hosts = []
        
        if check_tool_installed('httpx'):
            print_info("Using httpx for live host detection...")
            live_hosts = self._run_httpx()
        else:
            print_warning("httpx not found. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
            print_info("Falling back to basic HTTP checks...")
            live_hosts = self._basic_http_check()
        
        unique_hosts = remove_duplicates(live_hosts)
        
        print_success(f"Detected {len(unique_hosts)} live hosts")
        return unique_hosts
    
    def _run_httpx(self):
        try:
            result = subprocess.run(
                ['httpx', '-l', self.subdomains_file, '-silent', '-status-code', '-title', '-tech-detect'],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                live_hosts = []
                
                for line in lines:
                    if line.strip():
                        parts = line.split(' ')
                        if parts and len(parts) >= 1:
                            url = parts[0]
                            if not url.startswith(('http://', 'https://')):
                                url = f"https://{url}"
                            live_hosts.append(url)
                
                return live_hosts
            else:
                print_error(f"httpx failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print_error("httpx timed out")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            print_error(f"Error running httpx: {e}")
            return []
    
    def _basic_http_check(self):
        import requests
        import concurrent.futures
        
        def check_host(subdomain):
            try:
                urls = [f"https://{subdomain}", f"http://{subdomain}"]
                
                for url in urls:
                    try:
                        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                        if response.status_code < 400:
                            return url
                    except:
                        continue
                
                return None
            except:
                return None
        
        try:
            with open(self.subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            live_hosts = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(check_host, subdomain): subdomain for subdomain in subdomains}
                
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
            
            return live_hosts
            
        except Exception as e:
            print_error(f"Error in basic HTTP check: {e}")
            return []
