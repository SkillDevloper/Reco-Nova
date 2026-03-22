import re
import os
import subprocess
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style

def validate_domain(domain):
    domain = domain.strip().lower()
    
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if not re.match(domain_pattern, domain):
        return None
    
    return domain

def ensure_output_dir():
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    return output_dir

def save_to_file(filename, data, mode='w'):
    output_dir = ensure_output_dir()
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, mode, encoding='utf-8') as f:
        if isinstance(data, list):
            f.write('\n'.join(data))
        else:
            f.write(str(data))
    
    return filepath

def extract_parameters_from_url(url):
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return list(query_params.keys())
    except:
        return []

def remove_duplicates(data):
    if isinstance(data, list):
        return list(dict.fromkeys(data))
    return data

def print_success(message):
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_error(message):
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

def print_info(message):
    print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")

def print_warning(message):
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

def print_progress(message):
    print(f"{Fore.MAGENTA}[~] {message}{Style.RESET_ALL}")

def print_complete(message):
    print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

def print_header(message):
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} {message}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def print_subheader(message):
    print(f"\n{Fore.MAGENTA}{'-'*50}{Style.RESET_ALL}")
    print(f"{Fore.WHITE} {message}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'-'*50}{Style.RESET_ALL}")

def check_tool_installed(tool_name):
    try:
        result = subprocess.run([tool_name, '-h'], capture_output=True, text=True, timeout=5)
        return result.returncode == 0 or tool_name in result.stdout.lower()
    except:
        return False
