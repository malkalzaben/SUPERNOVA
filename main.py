#!/usr/bin/env python3
import argparse
import sys
import os
import ipaddress
import json

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, current_dir)

from core.scanner import run_scan


def print_banner():    
    CYAN = "\033[96m"
    RED = "\033[91m"
    WHITE = "\033[97m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    ascii_art = r"""
   _____ _    _ _____  ______ _____  _   _  ______      __      
  / ____| |  | |  __ \|  ____|  __ \| \ | |/ __ \ \    / /\     
 | (___ | |  | | |__) | |__  | |__) |  \| | |  | \ \  / /  \    
  \___ \| |  | |  ___/|  __| |  _  /| . ` | |  | |\ \/ / /\ \   
  ____) | |__| | |    | |____| | \ \| |\  | |__| | \  / ____ \  
 |_____/ \____/|_|    |______|_|  \_\_| \_|\____/   \/_/    \_\ 
    """
    
    print(CYAN + ascii_art + RESET)
    print(f"    {RED}[+] {WHITE}Internal Vulnerability Scanner Core")
    print(f"    {RED}[+] {YELLOW}Developed by: ErrorCatchers Team\n{RESET}")

    print(banner)

def get_ips_from_target(target_str):
    try:
        if '/' in target_str:
            network = ipaddress.ip_network(target_str, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            ip = ipaddress.ip_address(target_str)
            return [str(ip)]
    except ValueError:
        return None

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="SUPERNOVA Internal Vulnerability Scanner",
        usage="supernova -t <TARGET_IP_OR_CIDR> [options]"
    )
    
    parser.add_argument("-t", "--target", dest="target", required=True, 
                        help="Target IP or Subnet CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
    
    parser.add_argument("-p", "--ports", dest="ports", 
                        help="Specific ports separated by commas. Default is common ports.")
    
    parser.add_argument("-s", "--speed", dest="speed", type=float, default=1.0, 
                        help="Timeout in seconds per port (default: 1.0).")

    parser.add_argument("-o", "--output", dest="output", default="report.json", 
                        help="Output JSON file name (default: report.json).")

    parser.add_argument("--all", action="store_true", help="Run all security checks")
    parser.add_argument("--ftp", action="store_true", help="Run FTP checks only")
    parser.add_argument("--smb", action="store_true", help="Run SMB checks only")
    parser.add_argument("--http", action="store_true", help="Run HTTP/HTTPS checks only")

    return parser.parse_args()

def main():
    print_banner()
    if len(sys.argv) == 1:
        print("\033[93m[!] Missing required arguments.\033[0m")
        print("\033[97m[*] Tip: Type \033[96msupernova -h\033[0m \033[97mto see the help menu.\033[0m\n")
        sys.exit(1)    
    args = parse_arguments()
    
    target_ips = get_ips_from_target(args.target)
    if not target_ips:
        print(f"\033[91m[!] Error: Invalid Target format '{args.target}'. Please use a valid IP or CIDR.\033[0m")
        sys.exit(1)
        
    if args.ports:
        try:
            target_ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(f"\033[91m[!] Error: Ports must be numbers separated by commas.\033[0m")
            sys.exit(1)
    else:
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

    try:
        scan_results = run_scan(target_ips=target_ips, scope_name=args.target, ports_to_scan=target_ports, timeout_sec=args.speed)
        
        with open(args.output, 'w') as json_file:
            json.dump(scan_results, json_file, indent=4)
            
        print(f"\n\033[92m[+] Scan report successfully saved to: {args.output}\033[0m")

    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Scan interrupted by user. Exiting...\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()




