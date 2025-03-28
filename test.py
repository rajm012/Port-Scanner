# import socket

# def scan_port(target, port):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.settimeout(1)
#     result = s.connect_ex((target, port))
#     if result == 0:
#         print(f"Port {port} is open on {target}")
    
#     s.close()

# target_ip = "192.168.1.1"
# for port in range(20, 1025):  # Scanning common ports
#     scan_port(target_ip, port)


# def banner_grab(ip, port):
#     try:
#         s = socket.socket()
#         s.connect((ip, port))
#         s.send(b'Hello\r\n')
#         banner = s.recv(1024)
#         print(f"Banner from {ip}:{port} --> {banner.decode().strip()}")
#         s.close()
#     except:
#         pass


# from scapy.all import *

# ip = "192.168.1.1"
# pkt = IP(dst=ip)/ICMP()
# reply = sr1(pkt, timeout=2, verbose=0)
# if reply:
#     ttl = reply.ttl
#     if ttl <= 64:
#         print("Target OS: Linux/Unix")
#     elif ttl <= 128:
#         print("Target OS: Windows")
#     else:
#         print("Target OS: Mac")


# import json
# results = {"ip": "192.168.1.1", "open_ports": [22, 80, 443]}
# with open("scan_report.json", "w") as f:
#     json.dump(results, f, indent=4)


# import os
# import sys
# import platform
# import socket
# import struct

# def is_admin():
#     """Check if the script is running with administrative privileges."""
#     try:
#         if platform.system() == "Windows":
#             import ctypes
#             return ctypes.windll.shell32.IsUserAnAdmin()
#         else:
#             return os.geteuid() == 0
#     except:
#         return False

# if not is_admin():
#     print("This script requires administrative privileges.")
#     if platform.system() == "Windows":
#         # Re-run the script with admin rights on Windows
#         import ctypes
#         ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
#     else:
#         # Re-run the script with sudo on Linux/macOS
#         os.execvp("sudo", ["sudo", "python3"] + sys.argv)
#     sys.exit()

# # # OS Detection Logic
# def get_ttl(target_ip):
#     """Get the TTL value from an ICMP ping."""
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
#         sock.settimeout(1)
#         sock.sendto(b'\x08\x00\x00\x00\x00\x00\x00\x00', (target_ip, 1))

#         response, _ = sock.recvfrom(1024)
#         ttl = struct.unpack("B", response[8:9])[0]
#         sock.close()

#         return ttl
#     except Exception:
#         return None

# def detect_os(ttl):
#     """Detect OS based on TTL value."""
#     if ttl > 128:
#         return "Windows"
#     elif 64 < ttl <= 128:
#         return "Linux/Unix"
#     elif ttl <= 64:
#         return "BSD/MacOS"
#     return "Unknown"

# # Test OS Detection
# target_ip = "8.8.8.8"
# ttl = get_ttl(target_ip)
# if ttl:
#     os_guess = detect_os(ttl)
#     print(f"Detected OS: {os_guess} (TTL={ttl})")
# else:
#     print("Could not determine OS. Ensure the target IP is reachable.")


# from scapy.all import IP, TCP, sr1, send
# import sys

# def syn_scan(target_ip, port):
#     """
#     Performs a stealth SYN scan on a specific port.
#     """
#     # Create SYN packet
#     syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

#     # Send SYN packet and wait for response
#     response = sr1(syn_packet, timeout=2, verbose=0)

#     if response is None:
#         print(f"[Filtered] Port {port}: No response (Firewall may be blocking)")
    
#     elif response.haslayer(TCP):
#         if response[TCP].flags == 0x12:  # SYN-ACK received (Port Open)
#             print(f"[Open] Port {port}: SYN-ACK received")
#             # Send RST to gracefully close the connection
#             rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
#             send(rst_packet, verbose=0)
        
#         elif response[TCP].flags == 0x14:  # RST received (Port Closed)
#             print(f"[Closed] Port {port}: RST received")
    
#     else:
#         print(f"[Unknown] Port {port}: Unexpected response")

# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print("Usage: python syn_scan.py <target_ip> <port>")
#         sys.exit(1)
    
#     target = sys.argv[1]
#     port = int(sys.argv[2])

#     print(f"Performing SYN scan on {target}:{port}...\n")
#     syn_scan(target, port)

# # PS E:\Important Mails\IMP\Port-Scanner> python test.py 192.168.1.1 80
# # Performing SYN scan on 192.168.1.1:80...

# # [Filtered] Port 80: No response (Firewall may be blocking)



# from scapy.all import IP, TCP, sr1, conf
# import sys

# # Ensure compatibility with Windows
# if "win" in sys.platform:
#     conf.L3socket = conf.L3socket or conf.L2socket  # Windows-compatible socket

# target_ip = "192.168.1.1"
# target_port = 80

# print(f"Performing SYN scan on {target_ip}:{target_port}...")

# # Craft SYN packet
# syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

# # Send SYN and receive response
# response = sr1(syn_packet, timeout=2, verbose=False)

# if response:
#     if response.haslayer(TCP) and response[TCP].flags == 0x12:
#         print(f"Port {target_port} is OPEN")
#     elif response.haslayer(TCP) and response[TCP].flags == 0x14:
#         print(f"Port {target_port} is CLOSED")
#     else:
#         print(f"Port {target_port} is FILTERED")
# else:
#     print(f"No response from port {target_port} (Might be filtered by firewall)")

# -----------------------------------------




# ----------Previous version SYN lookup-------

# def syn_scan_gui(target_ip, port_range):
#     """Handle SYN scan updates."""
#     global scanning
#     num_ports = len(port_range)
#     progress_step = 100 / num_ports if num_ports > 0 else 100
#     progress = 0

#     for port in port_range:
#         if not scanning:
#             break

#         # Craft SYN packet
#         syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

#         # Send SYN and receive response
#         response = sr1(syn_packet, timeout=2, verbose=False)

#         if response:
#             if response.haslayer(TCP) and response[TCP].flags == 0x12:
#                 status = STATUS_OPEN
#                 tag = TAG_OPEN
#             elif response.haslayer(TCP) and response[TCP].flags == 0x14:
#                 status = STATUS_CLOSED
#                 tag = TAG_CLOSED
#             else:
#                 status = STATUS_FILTERED
#                 tag = TAG_FILTERED
#         else:
#             status = "No Response (Filtered)"
#             tag = TAG_FILTERED

#         result_list.insert("", "end", values=(port, status, ""), tags=(tag,))
#         progress += progress_step
#         update_progress(progress)

#     # Ensure full progress when done
#     with scanning_lock:
#         if scanning:
#             progress_bar["value"] = 100
#             status_label.config(text=f"SYN scan completed for {target_ip}")
    
#         scanning = False

