import subprocess
import platform


def is_host_up(ip_address, timeout_sec=2):


    current_os = platform.system().lower()

    if current_os == 'windows':
        ping_cmd = ['ping', '-n', '1', '-w', str(timeout_sec * 1000), ip_address]
    else:
        ping_cmd = ['ping', '-c', '1', '-W', str(timeout_sec), ip_address]

    try:
        result = subprocess.call(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if result == 0:
            return True
        else:
            return False

    except Exception as e:
        print(f"[!] Error checking host {ip_address}: {e}")
        return False
