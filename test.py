import socket

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is open on {target}")
    
    s.close()

target_ip = "192.168.1.1"
for port in range(20, 1025):  # Scanning common ports
    scan_port(target_ip, port)


def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'Hello\r\n')
        banner = s.recv(1024)
        print(f"Banner from {ip}:{port} --> {banner.decode().strip()}")
        s.close()
    except:
        pass


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


import json
results = {"ip": "192.168.1.1", "open_ports": [22, 80, 443]}
with open("scan_report.json", "w") as f:
    json.dump(results, f, indent=4)

