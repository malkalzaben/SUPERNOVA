import datetime
import getpass
from core.discovery import is_host_up
from core.portscan import scan_multiple_ports
from core.banner_grabber import grab_banner
from core.service_detection import detect_service_and_version


def run_scan(target_ips, scope_name, ports_to_scan, timeout_sec=1.0):

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_user = getpass.getuser()

    print("=" * 65)
    print(f"[*] Team           : SUPERNOVA")
    print(f"[*] Scope (Target) : {scope_name} (Total Hosts: {len(target_ips)})")
    print(f"[*] Time of Scan   : {scan_time}")
    print(f"[*] Scan run by    : {current_user}")
    print("=" * 65)

    for ip in target_ips:
        print(f"\n{'=' * 20} TARGET: {ip} {'=' * 20}")

        print(f"[{ip}] Step 1: Checking if host is UP...")
        if not is_host_up(ip, timeout_sec=timeout_sec):
            print(f"[-] Host {ip} is DOWN. Skipping to next host...")
            continue  

        print(f"[+] Host {ip} is UP!")

        print(f"[{ip}] Step 2: Scanning ports...")
        open_ports = scan_multiple_ports(ip, ports_to_scan, timeout_sec=timeout_sec)

        if not open_ports:
            print(f"[-] No open ports found on {ip}.")
            continue

        print(f"[+] Found {len(open_ports)} open ports: {open_ports}")

        print(f"[{ip}] Step 3: Detecting Services and Versions...")
        print("-" * 55)
        print(f"{'PORT':<8} | {'SERVICE':<10} | {'VERSION'}")
        print("-" * 55)

        for port in open_ports:
            banner = grab_banner(ip, port, timeout_sec=timeout_sec)
            service, version = detect_service_and_version(banner, port)
            print(f"{port:<8} | {service:<10} | {version}")

        print("-" * 55)


    print("\n[+] All tasks completed for the given scope!")
