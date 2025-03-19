import socket
import threading

def scan_port(target_ip, port, progress_callback):
    """Scans a single port and updates the progress callback."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:  # Port is Open
            sock.close()
            progress_callback(port, "Open")  # Update only open ports
    except Exception as e:
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



# if __name__ == "__main__":
#     target = "127.0.0.1"  # Change to test
#     ports = range(20, 1025)
#     results = scan_ports(target, ports, dummy_progress_callback)
#     for port, status in results:
#         print(f"Port {port}: {status}")



# if __name__ == "__main__":
#     target = input("Enter Target IP: ")
#     start_port = int(input("Enter Start Port: "))
#     end_port = int(input("Enter End Port: "))

#     ports = range(start_port, end_port + 1)
#     results = scan_ports(target, ports, progress_callback)

#     for port, status in results:
#         print(f"Port {port}: {status}")
