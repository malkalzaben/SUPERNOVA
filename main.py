#!/usr/bin/env python3
import argparse
import sys
import ipaddress
from core.scanner import run_scan


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
        description="SUPERNOVA Internal Vulnerability Scanner - Core Engine",
        usage="python main.py -t <TARGET_IP_OR_CIDR> [options]"
    )

    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP or Subnet CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")

    parser.add_argument("-p", "--ports", dest="ports",
                        help="Specific ports separated by commas. Default is common ports.")

    parser.add_argument("-s", "--speed", dest="speed", type=float, default=1.0,
                        help="Timeout in seconds per port (default: 1.0).")

    parser.add_argument("--all", action="store_true", help="Run all security checks (For future modules)")
    parser.add_argument("--ftp", action="store_true", help="Run FTP checks only (For future modules)")
    parser.add_argument("--smb", action="store_true", help="Run SMB checks only (For future modules)")
    parser.add_argument("--http", action="store_true", help="Run HTTP/HTTPS checks only (For future modules)")

    return parser.parse_args()


def main():
    args = parse_arguments()

    target_ips = get_ips_from_target(args.target)
    if not target_ips:
        print(f"[!] Error: Invalid Target format '{args.target}'. Please use a valid IP or CIDR.")
        sys.exit(1)

    if args.ports:
        try:
            target_ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("[!] Error: Ports must be numbers separated by commas.")
            sys.exit(1)
    else:
        target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

    try:
        run_scan(target_ips=target_ips, scope_name=args.target, ports_to_scan=target_ports, timeout_sec=args.speed)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)


if __name__ == "__main__":

    main()


