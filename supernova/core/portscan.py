import socket
import concurrent.futures


def scan_single_port(ip_address, port, timeout_sec=1.0):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        result = sock.connect_ex((ip_address, port))
        sock.close()

        if result == 0:
            return port
        return None
    except Exception:
        return None


def scan_multiple_ports(ip_address, ports_list, timeout_sec=1.0, max_threads=50):


    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_port, ip_address, port, timeout_sec): port for port in ports_list}

        for future in concurrent.futures.as_completed(futures):
            port_result = future.result()
            if port_result:
                open_ports.append(port_result)

    return sorted(open_ports)



# testing
# ==========================================
if __name__ == "__main__":
    target_ip = "192.168.100.1"

    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

    scan_timeout = 0.5
    print(f"[*] Starting Port Scan on {target_ip}...")
    print(f"[*] Scanning {len(ports_to_scan)} common ports...\n")

    found_ports = scan_multiple_ports(target_ip, ports_to_scan, timeout_sec=scan_timeout)

    if found_ports:
        print(f"[+] Scan Completed! Open Ports found:")
        for p in found_ports:
            print(f"    - Port {p} is OPEN")
    else:
        print("[-] Scan Completed. No open ports found from the list.")