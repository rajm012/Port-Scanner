import socket
import threading
import concurrent.futures


# Common services mapping
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5000: "Flask Server"
}


def get_service(port):
    """Try to get the service name using known mappings or socket."""
    try:
        return COMMON_SERVICES.get(port, socket.getservbyport(port, "tcp"))
    except (OSError, socket.error):
        return "Unknown"


def banner_grab(ip, port):
    """Attempts to grab the banner of an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        response = sock.recv(1024).decode(errors="ignore")
        sock.close()

        if "Server:" in response:
            return response.split("\n")[0]
        return response[:50]
    except:
        return "Unknown"


def scan_tcp_port(target_ip, port, progress_callback):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            service = get_service(port)
            if service == "Unknown":
                service = banner_grab(target_ip, port)
            sock.close()
            progress_callback(port, "Open", service)
        else:
            progress_callback(port, "Closed", "N/A")
    except Exception as e:
        progress_callback(port, "Error", str(e))


def scan_udp_port(target_ip, port, progress_callback):
    """Scan a single UDP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(b"\x00", (target_ip, port))  # Send empty UDP packet

        try:
            data, _ = sock.recvfrom(1024)
            progress_callback(port, "Open", "UDP Response Received")
        except socket.timeout:
            progress_callback(port, "Filtered", "No Response")
    except Exception as e:
        progress_callback(port, "Error", str(e))
    finally:
        sock.close()


def scan_ports(target_ip, port_range, progress_callback, scan_type="tcp"):
    """Scan ports using ThreadPoolExecutor."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for port in port_range:
            if scan_type == "tcp":
                futures.append(executor.submit(scan_tcp_port, target_ip, port, progress_callback))
            elif scan_type == "udp":
                futures.append(executor.submit(scan_udp_port, target_ip, port, progress_callback))

        for future in concurrent.futures.as_completed(futures):
            future.result()

