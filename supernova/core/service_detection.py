import re
import socket
import time

def active_probe(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            if port in [80, 443, 8080]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: scan\r\n\r\n")
            elif port == 21:
                s.sendall(b"HELP\r\n")
            else:
                s.sendall(b"\r\n")
                time.sleep(0.5)

            return s.recv(1024).decode('utf-8', errors='ignore')
    except:
        return ""

def detect_service_and_version(banner, port=None, target_ip=None):
    service = "Unknown"
    version = "Unknown"

    def is_empty(b):
        return not b or not str(b).strip('\x00\r\n\t ')

    if is_empty(banner) and target_ip and port:
        banner = active_probe(target_ip, port)

    if is_empty(banner):
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "rpcbind", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 2049: "NFS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
        }
        if port in common_ports:
            return f"Unknown (Maybe: {common_ports[port]}?)", "Unknown (No Banner)"
        return service, version

    banner_upper = str(banner).upper()

    if "SSH-" in banner_upper:
        service = "SSH (Verified)"
        match = re.search(r'SSH-\d\.\d-(.+)', str(banner))
        if match:
            version = match.group(1).strip()
        else:
            version = str(banner).split()[0].strip()

    elif "HTTP/" in banner_upper or "SERVER:" in banner_upper:
        service = "HTTP (Verified)" if port != 443 else "HTTPS (Verified)"
        match = re.search(r'Server:\s*(.+)', str(banner), re.IGNORECASE)
        if match:
            version = match.group(1).strip()
        else:
            version = "Web Server Detected"

    elif "SMTP" in banner_upper or "ESMTP" in banner_upper:
        service = "SMTP (Verified)"
        clean_banner = str(banner).replace("220 ", "").replace("-", " ").strip()
        version = clean_banner.split('\r')[0].split('\n')[0].strip()

    elif "FTP" in banner_upper or str(banner).startswith("220 "):
        service = "FTP (Verified)"
        clean_banner = str(banner).replace("220 ", "").replace("-", " ").strip()
        version = clean_banner.split('\r')[0].split('\n')[0].strip()

    elif "SMB" in banner_upper or "SAMBA" in banner_upper:
        service = "SMB (Verified)"
        version = "SMB Service Detected"

    else:
        common_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}
        guessed = common_ports.get(port, "Unknown")
        service = f"{guessed} (Verified)" if guessed != "Unknown" else "Unknown Service (Verified)"
        version = str(banner).split('\n')[0].strip()[:50]

    return service, version
