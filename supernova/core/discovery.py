import subprocess
import platform

def is_host_up(ip_address, timeout_sec=2):
    """
    Performs an ICMP Ping to check if the target host is alive (Up).
    Includes cross-platform support to work on both Windows and Linux/macOS.
    """
    # Detect the current operating system running the script
    current_os = platform.system().lower()

    # Construct the appropriate ping command based on the OS
    if current_os == 'windows':
        # Windows uses '-n' for packet count and '-w' for timeout in milliseconds
        ping_cmd = ['ping', '-n', '1', '-w', str(timeout_sec * 1000), ip_address]
    else:
        # Linux/macOS uses '-c' for packet count and '-W' for timeout in seconds
        ping_cmd = ['ping', '-c', '1', '-W', str(timeout_sec), ip_address]

    try:
        # Execute the ping command silently (hiding the standard output and errors to keep the terminal clean)
        result = subprocess.call(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # A return code of 0 means the ping was successful and the host responded
        if result == 0:
            return True
        else:
            return False

    except Exception as e:
        # Handle unexpected system errors (e.g., the 'ping' utility is missing)
        print(f"[!] Error checking host {ip_address}: {e}")
        return False
