import socket

def grab_banner(ip_address, port, timeout_sec=2.0):
    """
    Attempts to grab the service banner from a specific open port.
    Uses a two-step approach: Passive listening, followed by an Active HTTP probe.
    """
    try:
        # Initialize a standard TCP (IPv4) socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set the connection timeout to prevent hanging on unresponsive ports
        sock.settimeout(timeout_sec)
        sock.connect((ip_address, port))

        try:
            # Step 1: Passive Banner Grabbing
            # Wait to see if the service sends a welcome message automatically (e.g., SSH, FTP, SMTP)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            # If the service is silent (times out), ignore the error and proceed to Step 2
            pass
            
        # Step 2: Active Probing
        # If no passive banner was received, send a generic HTTP GET request to provoke a response
        http_request = f"GET / HTTP/1.1\r\nHost: {ip_address}\r\n\r\n"
        sock.sendall(http_request.encode())

        # Read the response triggered by the active HTTP probe
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if banner:
            return banner

    except Exception:
        # Handle connection errors (e.g., Connection Refused, Network Unreachable) gracefully
        return None

    # Return None if both passive and active methods fail to retrieve a banner
    return None
