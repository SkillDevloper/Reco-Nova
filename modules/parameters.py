import os
from urllib.parse import urlparse, parse_qs
from utils.helpers import extract_parameters_from_url, remove_duplicates, print_info, print_success

class ParameterExtractor:
    def __init__(self, domain):
        self.domain = domain
        self.urls_file = os.path.join("output", "urls.txt")
    
    def extract(self):
        print_info("Extracting parameters from URLs...")
        
        if not os.path.exists(self.urls_file):
            print_error("URLs file not found. Run wayback collection first.")
            return []
        
        parameters = set()
        
        try:
            with open(self.urls_file, 'r', encoding='utf-8') as f:
                urls = f.read().strip().split('\n')
                
                for url in urls:
                    if url.strip():
                        url_params = extract_parameters_from_url(url.strip())
                        parameters.update(url_params)
            
            parameter_list = list(parameters)
            unique_parameters = remove_duplicates(parameter_list)
            
            print_success(f"Extracted {len(unique_parameters)} unique parameters")
            return unique_parameters
            
        except Exception as e:
            print_error(f"Failed to extract parameters: {e}")
            return []
