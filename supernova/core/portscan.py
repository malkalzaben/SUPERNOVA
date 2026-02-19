import socket
import concurrent.futures

def scan_single_port(ip_address, port, timeout_sec=1.0):
    """
    Attempts to connect to a specific port on the target IP.
    Returns the port number if it is open, otherwise returns None.
    """
    try:
        # Initialize a standard TCP (IPv4) socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set the timeout to prevent the scanner from hanging on closed/filtered ports
        sock.settimeout(timeout_sec)
        
        # Use connect_ex() instead of connect() because it returns an error indicator (0 means success)
        # rather than throwing an exception if the port is closed
        result = sock.connect_ex((ip_address, port))
        sock.close()

        # A result of 0 indicates that the connection was successful and the port is OPEN
        if result == 0:
            return port
        return None
    except Exception:
        # Handle any unexpected network errors gracefully
        return None

def scan_multiple_ports(ip_address, ports_list, timeout_sec=1.0, max_threads=50):
    """
    Scans a list of ports concurrently using multiple threads to significantly speed up the process.
    Returns a sorted list of all open ports discovered on the target.
    """
    open_ports = []

    # Utilize ThreadPoolExecutor to run multiple port scans simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        
        # Submit each port scan as an individual task (future) to the thread pool
        futures = {executor.submit(scan_single_port, ip_address, port, timeout_sec): port for port in ports_list}

        # As each thread completes its scanning task, collect and process the result
        for future in concurrent.futures.as_completed(futures):
            port_result = future.result()
            if port_result:
                # If a port number is returned (meaning it's open), add it to the list
                open_ports.append(port_result)

    # Return the final list of open ports sorted in ascending numerical order
    return sorted(open_ports)
