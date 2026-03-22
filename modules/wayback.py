import requests
import time
from urllib.parse import urljoin, urlparse
from utils.helpers import remove_duplicates, print_info, print_success, print_error

class WaybackCollector:
    def __init__(self, domain):
        self.domain = domain
        self.base_url = "http://web.archive.org/cdx/search/cdx"
        self.urls = []
    
    def collect(self):
        print_info("Collecting URLs from Wayback Machine...")
        
        params = {
            'url': f'*.{self.domain}/*',
            'output': 'json',
            'collapse': 'timestamp:8',
            'filter': 'statuscode:200',
            'fl': 'original',
            'limit': '100000'
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if len(data) < 2:
                print_error("No URLs found in Wayback Machine")
                return []
            
            urls = [row[0] for row in data[1:] if len(row) > 0]
            
            unique_urls = remove_duplicates(urls)
            filtered_urls = self._filter_urls(unique_urls)
            
            print_success(f"Collected {len(filtered_urls)} unique URLs from Wayback Machine")
            return filtered_urls
            
        except requests.exceptions.RequestException as e:
            print_error(f"Failed to fetch Wayback URLs: {e}")
            return []
        except Exception as e:
            print_error(f"Error processing Wayback data: {e}")
            return []
    
    def _filter_urls(self, urls):
        filtered = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                
                if self.domain not in parsed.netloc:
                    continue
                
                if parsed.scheme not in ['http', 'https']:
                    continue
                
                if any(ext in url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg']):
                    continue
                
                filtered.append(url)
                
            except:
                continue
        
        return filtered
