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


# # from scapy.all import *

# # ip = "192.168.1.1"
# # pkt = IP(dst=ip)/ICMP()
# # reply = sr1(pkt, timeout=2, verbose=0)
# # if reply:
# #     ttl = reply.ttl
# #     if ttl <= 64:
# #         print("Target OS: Linux/Unix")
# #     elif ttl <= 128:
# #         print("Target OS: Windows")
# #     else:
# #         print("Target OS: Mac")


# import json
# results = {"ip": "192.168.1.1", "open_ports": [22, 80, 443]}
# with open("scan_report.json", "w") as f:
#     json.dump(results, f, indent=4)


import os
import sys
import platform
import socket
import struct

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

if not is_admin():
    print("This script requires administrative privileges.")
    if platform.system() == "Windows":
        # Re-run the script with admin rights on Windows
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        # Re-run the script with sudo on Linux/macOS
        os.execvp("sudo", ["sudo", "python3"] + sys.argv)
    sys.exit()

# OS Detection Logic
def get_ttl(target_ip):
    """Get the TTL value from an ICMP ping."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1)
        sock.sendto(b'\x08\x00\x00\x00\x00\x00\x00\x00', (target_ip, 1))

        response, _ = sock.recvfrom(1024)
        ttl = struct.unpack("B", response[8:9])[0]
        sock.close()

        return ttl
    except Exception:
        return None

def detect_os(ttl):
    """Detect OS based on TTL value."""
    if ttl > 128:
        return "Windows"
    elif 64 < ttl <= 128:
        return "Linux/Unix"
    elif ttl <= 64:
        return "BSD/MacOS"
    return "Unknown"

# Test OS Detection
target_ip = "8.8.8.8"
ttl = get_ttl(target_ip)
if ttl:
    os_guess = detect_os(ttl)
    print(f"Detected OS: {os_guess} (TTL={ttl})")
else:
    print("Could not determine OS. Ensure the target IP is reachable.")

