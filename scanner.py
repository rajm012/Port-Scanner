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

def banner_grab(ip, port):
    """Attempts to grab the banner of an open port. Sends an HTTP request for web servers."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        # Send HTTP Request
        http_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        sock.send(http_request)

        # Receive response (increase buffer size to avoid truncation)
        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        if "Server:" in response:
            for line in response.split("\r\n"):
                if line.startswith("Server:"):
                    return line  # Return exact server info

        return response.split("\r\n")[0]
    
    except Exception as e:
        return f"Unknown ({str(e)})"


def scan_port(target_ip, port, progress_callback):
    """Scans a single port and updates the progress callback."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:  # Port is Open
            service = get_service(port)
            if service == "Unknown":
                service = banner_grab(target_ip, port)
            sock.close()
            progress_callback(port, "Open", service)

    except Exception as e:
        print("Possible Issues: ", e)

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
