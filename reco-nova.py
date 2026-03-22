#!/usr/bin/env python3

import sys
import argparse
import os
from colorama import init, Fore, Style

# Check Python version
if sys.version_info < (3, 12):
    print(f"{Fore.RED}Error: Reco-Nova requires Python 3.12 or higher. Current version: {sys.version}{Style.RESET_ALL}")
    sys.exit(1)

from utils.dependency_checker import DependencyChecker

# Check and install dependencies
if not DependencyChecker.check_and_install_dependencies():
    sys.exit(1)

from core.controller import ReconController
from utils.logger import setup_logger

init()

def print_banner():
    banner = r"""
 ____                      _   _                 
|  _ \ ___  ___ ___       | \ | | _____   ____ _ 
| |_) / _ \/ __/ _ \ _____|  \| |/ _ \ \ / / _` |
|  _ <  __/ (_| (_) |_____| |\  | (_) \ V / (_| |
|_| \_\___|\___\___/      |_| \_|\___/ \_/ \__,_|

    Recon Automation Framework
    Developer: Daniyal Shahid
    Version: 1.1
"""
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")

def print_menu():
    menu = f"""
{Fore.CYAN}================================================================
{Fore.YELLOW}                    Recon Automation Framework                    
{Fore.GREEN}                        Professional Edition                        
{Fore.CYAN}================================================================{Style.RESET_ALL}

{Fore.MAGENTA}-----------------------------------------------------------------
{Fore.YELLOW}1.{Style.RESET_ALL} {Fore.WHITE}Collect Wayback URLs        {Fore.MAGENTA}
{Fore.YELLOW}2.{Style.RESET_ALL} {Fore.WHITE}Extract Parameters           {Fore.MAGENTA}
{Fore.YELLOW}3.{Style.RESET_ALL} {Fore.WHITE}Discover Subdomains         {Fore.MAGENTA}
{Fore.YELLOW}4.{Style.RESET_ALL} {Fore.WHITE}Detect Live Hosts           {Fore.MAGENTA}
{Fore.YELLOW}5.{Style.RESET_ALL} {Fore.WHITE}Analyze JavaScript          {Fore.MAGENTA}
{Fore.YELLOW}6.{Style.RESET_ALL} {Fore.WHITE}Scan Sensitive Files        {Fore.MAGENTA}
{Fore.YELLOW}7.{Style.RESET_ALL} {Fore.WHITE}Capture Screenshots         {Fore.MAGENTA}
{Fore.YELLOW}8.{Style.RESET_ALL} {Fore.WHITE}Run Full Recon              {Fore.MAGENTA}
{Fore.YELLOW}9.{Style.RESET_ALL} {Fore.RED}Exit                          {Fore.MAGENTA}
{Fore.MAGENTA}-----------------------------------------------------------------{Style.RESET_ALL}

{Fore.CYAN}Select option:{Style.RESET_ALL} """
    print(menu)

def interactive_mode(save_output=True):
    while True:
        print_menu()
        choice = input(f"{Fore.GREEN}> {Style.RESET_ALL}").strip()
        
        if choice == '9':
            print(f"\n{Fore.YELLOW}================================================================{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}           Thank you for using Reco-Nova!           {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}              Stay Ethical, Stay Safe!              {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}================================================================{Style.RESET_ALL}")
            break
        
        if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
            print(f"\n{Fore.CYAN}================================================================{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}           Target Domain Input           {Style.RESET_ALL}")
            print(f"{Fore.CYAN}================================================================{Style.RESET_ALL}")
            domain = input(f"{Fore.GREEN}> Enter target domain: {Style.RESET_ALL}").strip()
            
            if not domain:
                print(f"{Fore.RED}[-] Please enter a valid domain{Style.RESET_ALL}")
                input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                continue
            
            # Ask about saving output
            if save_output:
                save_choice = input(f"{Fore.YELLOW}> Save output to files? (Y/n): {Style.RESET_ALL}").strip().lower()
                current_save_output = not save_choice.startswith('n')
            else:
                current_save_output = False
            
            # Full reconnaissance always saves output
            if choice == '8':
                current_save_output = True
                if not save_output:
                    print(f"{Fore.YELLOW}[!] Note: Full reconnaissance always saves output for comprehensive reporting{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Initializing reconnaissance for {Fore.YELLOW}{domain}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}{'='*50}{Style.RESET_ALL}")
            
            if current_save_output:
                print(f"{Fore.BLUE}[*] Output saving: ENABLED{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Output saving: DISABLED{Style.RESET_ALL}")
            
            controller = ReconController(domain, current_save_output)
            
            try:
                if choice == '1':
                    print(f"{Fore.BLUE}[*] Starting Wayback URL Collection...{Style.RESET_ALL}")
                    controller.collect_wayback_urls()
                elif choice == '2':
                    print(f"{Fore.BLUE}[*] Starting Parameter Extraction...{Style.RESET_ALL}")
                    controller.extract_parameters()
                elif choice == '3':
                    print(f"{Fore.BLUE}[*] Starting Subdomain Discovery...{Style.RESET_ALL}")
                    controller.discover_subdomains()
                elif choice == '4':
                    print(f"{Fore.BLUE}[*] Starting Live Host Detection...{Style.RESET_ALL}")
                    controller.detect_live_hosts()
                elif choice == '5':
                    print(f"{Fore.BLUE}[*] Starting JavaScript Analysis...{Style.RESET_ALL}")
                    controller.analyze_javascript()
                elif choice == '6':
                    print(f"{Fore.BLUE}[*] Starting Sensitive File Scan...{Style.RESET_ALL}")
                    controller.scan_sensitive_files()
                elif choice == '7':
                    print(f"{Fore.BLUE}[*] Starting Screenshot Capture...{Style.RESET_ALL}")
                    controller.capture_screenshots()
                elif choice == '8':
                    print(f"{Fore.BLUE}[*] Starting Full Reconnaissance...{Style.RESET_ALL}")
                    controller.run_full_recon()
                
                print(f"\n{Fore.GREEN}[+] Operation completed successfully!{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Invalid option. Please try again.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}Recon Automation Framework - Professional Edition{Style.RESET_ALL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  {Fore.GREEN}python reco-nova.py -d example.com --full{Style.RESET_ALL}
  {Fore.GREEN}python reco-nova.py -d example.com --full --no-save{Style.RESET_ALL}
  {Fore.GREEN}python reco-nova.py -d example.com --wayback{Style.RESET_ALL}
  {Fore.GREEN}python reco-nova.py -i{Style.RESET_ALL}
  {Fore.GREEN}python reco-nova.py --check-deps{Style.RESET_ALL}

{Fore.YELLOW}Modules:{Style.RESET_ALL}
  {Fore.CYAN}wayback{Style.RESET_ALL}    - Collect Wayback URLs
  {Fore.CYAN}params{Style.RESET_ALL}     - Extract parameters
  {Fore.CYAN}subs{Style.RESET_ALL}       - Discover subdomains
  {Fore.CYAN}live{Style.RESET_ALL}       - Detect live hosts
  {Fore.CYAN}js{Style.RESET_ALL}         - Analyze JavaScript
  {Fore.CYAN}sensitive{Style.RESET_ALL}  - Scan sensitive files
  {Fore.CYAN}shots{Style.RESET_ALL}      - Capture screenshots

{Fore.YELLOW}Output Options:{Style.RESET_ALL}
  {Fore.CYAN}--no-save{Style.RESET_ALL}      - Don't save results to files
  {Fore.CYAN}--reports-only{Style.RESET_ALL} - Generate reports only
        """
    )
    
    parser.add_argument('-d', '--domain', 
                       help=f'{Fore.YELLOW}Target domain for reconnaissance{Style.RESET_ALL}')
    parser.add_argument('--full', action='store_true', 
                       help=f'{Fore.YELLOW}Run full reconnaissance{Style.RESET_ALL}')
    parser.add_argument('--wayback', action='store_true', 
                       help=f'{Fore.YELLOW}Collect Wayback URLs{Style.RESET_ALL}')
    parser.add_argument('--params', action='store_true', 
                       help=f'{Fore.YELLOW}Extract parameters{Style.RESET_ALL}')
    parser.add_argument('--subs', action='store_true', 
                       help=f'{Fore.YELLOW}Discover subdomains{Style.RESET_ALL}')
    parser.add_argument('--live', action='store_true', 
                       help=f'{Fore.YELLOW}Detect live hosts{Style.RESET_ALL}')
    parser.add_argument('--js', action='store_true', 
                       help=f'{Fore.YELLOW}Analyze JavaScript{Style.RESET_ALL}')
    parser.add_argument('--sensitive', action='store_true', 
                       help=f'{Fore.YELLOW}Scan sensitive files{Style.RESET_ALL}')
    parser.add_argument('--shots', action='store_true', 
                       help=f'{Fore.YELLOW}Capture screenshots{Style.RESET_ALL}')
    parser.add_argument('-i', '--interactive', action='store_true', 
                       help=f'{Fore.YELLOW}Run in interactive mode{Style.RESET_ALL}')
    parser.add_argument('--check-deps', action='store_true', 
                       help=f'{Fore.YELLOW}Check dependencies only{Style.RESET_ALL}')
    parser.add_argument('--no-save', action='store_true', 
                       help=f'{Fore.YELLOW}Do not save results to files{Style.RESET_ALL}')
    parser.add_argument('--reports-only', action='store_true', 
                       help=f'{Fore.YELLOW}Generate reports only (no file saving){Style.RESET_ALL}')
    
    args = parser.parse_args()
    
    if args.check_deps:
        print_banner()
        DependencyChecker.check_external_tools()
        return
    
    print_banner()
    
    setup_logger()
    
    # Check external tools
    DependencyChecker.check_external_tools()
    
    # Determine save_output setting
    save_output = not args.no_save and not args.reports_only
    
    # Full reconnaissance always saves output regardless of --no-save
    if args.full:
        save_output = True
        if args.no_save:
            print(f"{Fore.YELLOW}[!] Note: Full reconnaissance always saves output for comprehensive reporting{Style.RESET_ALL}")
    
    if args.interactive or not args.domain:
        interactive_mode(save_output)
        return
    
    print(f"{Fore.CYAN}================================================================{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}         Starting Reconnaissance        {Style.RESET_ALL}")
    print(f"{Fore.GREEN}           Target: {args.domain}            {Style.RESET_ALL}")
    print(f"{Fore.CYAN}================================================================{Style.RESET_ALL}")
    
    if save_output:
        print(f"{Fore.BLUE}[*] Output saving: ENABLED{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Output saving: DISABLED{Style.RESET_ALL}")
    
    controller = ReconController(args.domain, save_output)
    
    try:
        if args.full:
            print(f"{Fore.BLUE}[*] Starting Full Reconnaissance...{Style.RESET_ALL}")
            controller.run_full_recon()
        elif args.wayback:
            print(f"{Fore.BLUE}[*] Starting Wayback URL Collection...{Style.RESET_ALL}")
            controller.collect_wayback_urls()
        elif args.params:
            print(f"{Fore.BLUE}[*] Starting Parameter Extraction...{Style.RESET_ALL}")
            controller.extract_parameters()
        elif args.subs:
            print(f"{Fore.BLUE}[*] Starting Subdomain Discovery...{Style.RESET_ALL}")
            controller.discover_subdomains()
        elif args.live:
            print(f"{Fore.BLUE}[*] Starting Live Host Detection...{Style.RESET_ALL}")
            controller.detect_live_hosts()
        elif args.js:
            print(f"{Fore.BLUE}[*] Starting JavaScript Analysis...{Style.RESET_ALL}")
            controller.analyze_javascript()
        elif args.sensitive:
            print(f"{Fore.BLUE}[*] Starting Sensitive File Scan...{Style.RESET_ALL}")
            controller.scan_sensitive_files()
        elif args.shots:
            print(f"{Fore.BLUE}[*] Starting Screenshot Capture...{Style.RESET_ALL}")
            controller.capture_screenshots()
        else:
            print(f"{Fore.YELLOW}No module specified. Running basic reconnaissance...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}[*] Starting Basic Reconnaissance...{Style.RESET_ALL}")
            controller.collect_wayback_urls()
            controller.extract_parameters()
            controller.discover_subdomains()
            controller.detect_live_hosts()
            print(f"\n{Fore.GREEN}[+] Basic reconnaissance completed successfully!{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Operation completed successfully!{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
