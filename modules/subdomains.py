import subprocess
import os
from utils.helpers import check_tool_installed, remove_duplicates, print_info, print_success, print_error, print_warning

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
    
    def enumerate(self):
        print_info("Enumerating subdomains...")
        
        all_subdomains = set()
        
        if check_tool_installed('subfinder'):
            print_info("Using subfinder...")
            subfinder_results = self._run_subfinder()
            all_subdomains.update(subfinder_results)
        else:
            print_warning("subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        
        if check_tool_installed('assetfinder'):
            print_info("Using assetfinder...")
            assetfinder_results = self._run_assetfinder()
            all_subdomains.update(assetfinder_results)
        else:
            print_warning("assetfinder not found. Install with: go install github.com/tomnomnom/assetfinder@latest")
        
        if not all_subdomains:
            print_warning("No subdomain enumeration tools found. Using basic methods...")
            basic_results = self._basic_enumeration()
            all_subdomains.update(basic_results)
        
        unique_subdomains = list(all_subdomains)
        sorted_subdomains = sorted(unique_subdomains)
        
        print_success(f"Discovered {len(sorted_subdomains)} subdomains")
        return sorted_subdomains
    
    def _run_subfinder(self):
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return subdomains
            else:
                print_error(f"subfinder failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print_error("subfinder timed out")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            print_error(f"Error running subfinder: {e}")
            return []
    
    def _run_assetfinder(self):
        try:
            result = subprocess.run(
                ['assetfinder', '--subs-only', self.domain],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                return subdomains
            else:
                print_error(f"assetfinder failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print_error("assetfinder timed out")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            print_error(f"Error running assetfinder: {e}")
            return []
    
    def _basic_enumeration(self):
        basic_subdomains = [
            f"www.{self.domain}",
            f"mail.{self.domain}",
            f"ftp.{self.domain}",
            f"admin.{self.domain}",
            f"api.{self.domain}",
            f"dev.{self.domain}",
            f"test.{self.domain}",
            f"staging.{self.domain}",
            f"blog.{self.domain}",
            f"shop.{self.domain}",
            f"app.{self.domain}",
            f"cdn.{self.domain}",
            f"static.{self.domain}",
            f"assets.{self.domain}",
            f"images.{self.domain}"
        ]
        
        return basic_subdomains
