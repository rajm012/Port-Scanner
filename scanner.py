import socket
import threading

def scan_port(target_ip, port, results):
    """Scans a single port to check if it's open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            results.append((port, "Open"))
        sock.close()
    except Exception as e:
        pass  # Ignore errors for now

def scan_ports(target_ip, port_range):
    """Scans multiple ports using threading."""
    threads = []
    results = []

    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(target_ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results


if __name__ == "__main__":
    target = "127.0.0.1"
    ports = range(20, 1025)
    results = scan_ports(target, ports)
    for port, status in results:
        print(f"Port {port}: {status}")
