import socket
def grab_banner(ip_address, port, timeout_sec=2.0):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect((ip_address, port))

        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            pass
        http_request = f"GET / HTTP/1.1\r\nHost: {ip_address}\r\n\r\n"
        sock.sendall(http_request.encode())

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if banner:
            return banner

    except Exception:
        return None

    return None



#testing
# ==========================================
if __name__ == "__main__":
    target_ip = "192.168.100.1"

    target_port = 80

    print(f"[*] Grabbing banner from {target_ip} on port {target_port}...")

    result_banner = grab_banner(target_ip, target_port)

    if result_banner:
        print(f"[+] Banner Found:\n{'-' * 20}\n{result_banner}\n{'-' * 20}")
    else:
        print("[-] No banner grabbed. Service might be filtered or not responding.")