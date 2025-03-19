import socket
import threading

# Common ports and their services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP"
}

def get_service(port):
    """Detects service running on the port using known services and banner grabbing."""
    try:
        return socket.getservbyport(port)  # Get service name (if known)
    except:
        return "Unknown"


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
    """Scans a single port and detects if it is open, closed, or filtered."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            service = get_service(port)
            if service == "Unknown":
                service = banner_grab(target_ip, port)  # Try banner grabbing
            sock.close()
            progress_callback(port, "Open", service)
        
        elif result == 10061:  # Windows-specific "connection refused" error
            progress_callback(port, "Closed", "N/A")
        
        else:
            progress_callback(port, "Filtered", "Possibly Firewalled")
    
    except Exception as e:
        progress_callback(port, "Error", str(e))


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


# def scan_ports(target_ip, port_range, update_progress):
#     for port in port_range:
#         try:
#             # Create a socket object
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(1)  # Set a timeout for the connection attempt

#             # Attempt to connect to the port
#             result = sock.connect_ex((target_ip, port))
#             if result == 0:
#                 # Port is open, try to identify the service
#                 service = identify_service(sock, port)
#                 update_progress(port, "Open", service)
#             else:
#                 update_progress(port, "Closed", "Unknown")
#             sock.close()
#         except Exception as e:
#             update_progress(port, "Error", str(e))

# def identify_service(sock, port):
#     if port == 5000:
#         try:
#             # Send a simple HTTP GET request to the port
#             sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
#             response = sock.recv(1024).decode('utf-8')
#             if "Flask" in response:
#                 return "Flask"
#         except:
#             pass
#     return "Unknown"