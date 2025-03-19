import socket
import threading

# Common ports and their services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP"
}

def get_service(port):
    """Returns the service name if known, otherwise 'Unknown'."""
    return COMMON_SERVICES.get(port, "Unknown")

def scan_port(target_ip, port, progress_callback):
    """Scans a single port and updates the progress callback."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:  # Port is Open
            service = get_service(port)
            sock.close()
            progress_callback(port, "Open", service)  # Update UI with service name
    except Exception:
        pass  # Ignore errors

def scan_ports(target_ip, port_range, progress_callback):
    """Scans a range of ports using multithreading."""
    threads = []
    
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, progress_callback))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to finish
    for thread in threads:
        thread.join()


