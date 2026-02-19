import re
def detect_service_and_version(banner, port=None, target_ip=None):

    service = "Unknown"
    version = "Unknown"

    if not banner:
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
        }
        if port in common_ports:
            return common_ports[port], "Unknown (No Banner)"
        return service, version

    banner_upper = banner.upper()

    if "SSH-" in banner_upper:
        service = "SSH"
        match = re.search(r'SSH-\d\.\d-(.+)', banner)
        if match:
            version = match.group(1).strip()

    elif "HTTP/" in banner_upper or "SERVER:" in banner_upper:
        service = "HTTP (Verified)" if port != 443 else "HTTPS (Verified)"
        match = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
        if match:
            version = match.group(1).strip()
        else:
            version = "Web Server Detected"

    elif "SMTP" in banner_upper or "ESMTP" in banner_upper:
        service = "SMTP (Verified)"
        clean_banner = banner.replace("220 ", "").replace("-", " ").strip()
        version = clean_banner.split('\r')[0].split('\n')[0].strip()

    elif "FTP" in banner_upper or banner.startswith("220 "):
        service = "FTP (Verified)"
        clean_banner = banner.replace("220 ", "").replace("-", " ").strip()
        version = clean_banner.split('\r')[0].split('\n')[0].strip()

    elif "SMB" in banner_upper or "SAMBA" in banner_upper:
        service = "SMB (Verified)"
        version = "SMB Service Detected"


    return service, version
