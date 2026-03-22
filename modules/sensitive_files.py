import os
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import print_info, print_success, print_error

class SensitiveFileScanner:
    def __init__(self, domain):
        self.domain = domain
        self.live_hosts_file = os.path.join("output", "live_hosts.txt")
        self.sensitive_files = [
            '.env',
            '.git/config',
            '.git/HEAD',
            'backup.zip',
            'backup.sql',
            'database.sql',
            'config.php',
            'config.ini',
            'settings.py',
            'debug.log',
            'error.log',
            'access.log',
            'wp-config.php',
            '.htaccess',
            '.htpasswd',
            'web.config',
            'composer.json',
            'package.json',
            'requirements.txt',
            'Pipfile',
            'Dockerfile',
            'docker-compose.yml',
            'kubernetes.yml',
            'secrets.json',
            'private.key',
            'id_rsa',
            'sitemap.xml',
            'robots.txt',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
            '.well-known/',
            'phpinfo.php',
            'test.php',
            'info.php',
            'admin.php',
            'login.php',
            'panel/',
            'admin/',
            'wp-admin/',
            'phpmyadmin/',
            'cpanel/',
            'webmail/',
            '.svn/',
            '.DS_Store',
            'Thumbs.db',
            'npm-debug.log',
            'yarn-error.log'
        ]
    
    def scan(self):
        print_info("Scanning for sensitive files...")
        
        if not os.path.exists(self.live_hosts_file):
            print_error("Live hosts file not found. Run live host detection first.")
            return []
        
        sensitive_files_found = []
        
        try:
            with open(self.live_hosts_file, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
            
            print_info(f"Scanning {len(hosts)} hosts for sensitive files...")
            
            for host in hosts:
                host_sensitive = self._scan_host(host)
                sensitive_files_found.extend(host_sensitive)
            
            print_success(f"Found {len(sensitive_files_found)} potentially sensitive files")
            return sensitive_files_found
            
        except Exception as e:
            print_error(f"Error scanning sensitive files: {e}")
            return []
    
    def _scan_host(self, host):
        sensitive_found = []
        
        def check_file(file_path):
            try:
                full_url = urljoin(host, file_path)
                
                response = requests.get(
                    full_url, 
                    timeout=10, 
                    allow_redirects=True, 
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if (len(response.content) > 100 and 
                        not any(ct in content_type for ct in ['text/html', 'image/', 'video/', 'audio/'])):
                        return full_url
                    elif (file_path.endswith(('.php', '.asp', '.aspx', '.jsp')) and 
                          len(response.content) > 500):
                        return full_url
                    elif file_path.endswith(('.txt', '.log', '.sql', '.json', '.xml', '.yml', '.yaml')):
                        return full_url
                    
            except:
                pass
            
            return None
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            future_to_file = {executor.submit(check_file, file_path): file_path for file_path in self.sensitive_files}
            
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    sensitive_found.append(result)
        
        return sensitive_found
