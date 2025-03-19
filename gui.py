import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
from scanner import scan_ports, shodan_lookup, get_ttl, detect_os
from scapy.all import IP, TCP, sr1, conf
import os
import ctypes
import sys
import platform

# Constants for repeated strings
STATUS_OPEN = "Open"
STATUS_CLOSED = "Closed"
STATUS_FILTERED = "Filtered"
STATUS_ERROR = "Error"
TAG_OPEN = "open"
TAG_CLOSED = "closed"
TAG_FILTERED = "filtered"
TAG_ERROR = "error"

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "S0EA8Co1efoOunYbc1EIPOuZDZCo45Cx")

# Global variable to control scanning
scanning = False
scanning_lock = threading.Lock()

# Ensure compatibility with Windows
if "win" in sys.platform:
    conf.L3socket = conf.L3socket or conf.L2socket  # Windows-compatible socket

# To check and try to get admin permission
def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False


if not is_admin():
    print("This script requires administrative privileges.")
    script_path = os.path.abspath(sys.argv[0])  # Get the absolute path of the script
    if platform.system() == "Windows":
        # Re-run the script with admin rights on Windows
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
    else:
        # Re-run the script with sudo on Linux/macOS
        os.execvp("sudo", ["sudo", "python3", script_path] + sys.argv[1:])
    sys.exit()


# Your script logic here
print("Running with administrative privileges!")


def stop_scan():
    """Stop the ongoing scan."""
    global scanning
    with scanning_lock:
        scanning = False
    status_label.config(text="Scan stopped.")


def update_progress(value):
    """Update the progress bar."""
    progress_bar["value"] = value
    root.update_idletasks()


def clear_results():
    """Clear the result table and reset the progress bar."""
    result_list.delete(*result_list.get_children())
    progress_bar["value"] = 0
    status_label.config(text="")


def run_scan():
    """Start the scan based on the selected scan type."""
    global scanning
    with scanning_lock:
        scanning = True

    target_ip = ip_entry.get().strip()
    start = int(start_port.get())
    end = int(end_port.get())
    scan_type = scan_mode.get()  # "tcp", "udp", or "syn"

    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    port_range = range(start, end + 1)
    clear_results()  # Clear previous results
    status_label.config(text=f"Scanning {target_ip} ({scan_type.upper()})...")

    # Start scanning in a separate thread
    if scan_type == "syn":
        scan_thread = threading.Thread(target=syn_scan_gui, args=(target_ip, port_range))

    else:
        scan_thread = threading.Thread(target=scan_ports_gui, args=(target_ip, port_range, scan_type))
    scan_thread.start()


def scan_ports_gui(target_ip, port_range, scan_type):
    """Handle scanning updates for TCP/UDP scans."""
    global scanning
    num_ports = len(port_range)
    progress_step = 100 / num_ports if num_ports > 0 else 100
    progress = 0

    def thread_callback(port, status, service):
        nonlocal progress
        if not scanning:
            return
        
        tag = TAG_OPEN if status == STATUS_OPEN else TAG_CLOSED

        if STATUS_ERROR in status or STATUS_FILTERED in status:
            tag = TAG_ERROR if STATUS_ERROR in status else TAG_FILTERED

        result_list.insert("", "end", values=(port, status, service), tags=(tag,))
        progress += progress_step
        
        update_progress(progress)

    # Call scanner function
    scan_ports(target_ip, port_range, thread_callback, scan_type)

    # Ensure full progress when done
    with scanning_lock:
        if scanning:
            progress_bar["value"] = 100
            status_label.config(text=f"Scan completed for {target_ip} ({scan_type.upper()})")
    
        scanning = False


def syn_scan_gui(target_ip, port_range):
    """Handle SYN scan updates."""
    global scanning
    num_ports = len(port_range)
    progress_step = 100 / num_ports if num_ports > 0 else 100
    progress = 0

    for port in port_range:
        if not scanning:
            break

        # Craft SYN packet
        syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send SYN and receive response
        response = sr1(syn_packet, timeout=2, verbose=False)

        if response:
            if response.haslayer(TCP) and response[TCP].flags == 0x12:
                status = STATUS_OPEN
                tag = TAG_OPEN
            elif response.haslayer(TCP) and response[TCP].flags == 0x14:
                status = STATUS_CLOSED
                tag = TAG_CLOSED
            else:
                status = STATUS_FILTERED
                tag = TAG_FILTERED
        else:
            status = "No Response (Filtered)"
            tag = TAG_FILTERED

        result_list.insert("", "end", values=(port, status, ""), tags=(tag,))
        progress += progress_step
        update_progress(progress)

    # Ensure full progress when done
    with scanning_lock:
        if scanning:
            progress_bar["value"] = 100
            status_label.config(text=f"SYN scan completed for {target_ip}")
    
        scanning = False


def save_results():
    """Save scan results to a file."""
    file = filedialog.asksaveasfilename(defaultextension=".csv",
                                        filetypes=[("CSV Files", "*.csv"),
                                                   ("Text Files", "*.txt"),
                                                   ("JSON Files", "*.json")])
    if file:
        results = []
        for row in result_list.get_children():
            port, status, service = result_list.item(row, "values")
            results.append({"port": port, "status": status, "service": service})

        # Save based on file type
        if file.endswith(".json"):
            with open(file, "w") as f:
                json.dump(results, f, indent=4)
        else:
            with open(file, "w") as f:
                for result in results:
                    f.write(f"{result['port']},{result['status']},{result['service']}\n")


def run_shodan_lookup():
    """Run Shodan lookup and display results in a pop-up."""
    if not SHODAN_API_KEY:
        messagebox.showerror("Error", "Shodan API key not found. Please set the SHODAN_API_KEY environment variable.")
        return

    target_ip = ip_entry.get().strip()
    
    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    try:
        result = shodan_lookup(target_ip)

        if "Error" in result:
            messagebox.showerror("Shodan Error", result["Error"])

        else:
            info_text = f"IP: {result['IP']}\nOrganization: {result['Organization']}\n"
            info_text += f"ISP: {result['ISP']}\nOS: {result['OS']}\n"
            info_text += f"Open Ports: {', '.join(map(str, result['Open Ports']))}\n"
            info_text += f"Vulnerabilities: {result['Vulnerabilities']}\n"
            
            messagebox.showinfo("Shodan Lookup", info_text)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during Shodan lookup: {str(e)}")


def run_os_detection():
    """Detect the operating system of the target IP."""
    target_ip = ip_entry.get().strip()
    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    if not is_admin():
        messagebox.showerror("Error", "Administrative privileges required for OS detection.")
        return

    try:
        ttl = get_ttl(target_ip)
        if ttl is None:
            messagebox.showwarning("OS Detection", "Could not determine OS. Ensure the target IP is reachable.")
            return

        os_guess = detect_os(ttl)
        messagebox.showinfo("OS Detection", f"Detected OS: {os_guess} (TTL={ttl})")

    except PermissionError:
        messagebox.showerror("Error", "Administrative privileges required for OS detection.")


# GUI Setup
root = tk.Tk()
root.title("Advanced Port Scanner")
root.geometry("800x550")

# Main Frame
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky="nsew")

# Input Fields
ttk.Label(main_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
ip_entry = ttk.Entry(main_frame, width=30)
ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

ttk.Label(main_frame, text="Start Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
start_port = ttk.Entry(main_frame, width=10)
start_port.grid(row=1, column=1, padx=5, pady=5, sticky="w")

ttk.Label(main_frame, text="End Port:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
end_port = ttk.Entry(main_frame, width=10)
end_port.grid(row=2, column=1, padx=5, pady=5, sticky="w")

# Scan Type Selection (TCP/UDP/SYN)
scan_mode = tk.StringVar(value="tcp")
ttk.Label(main_frame, text="Scan Type:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
tcp_radio = ttk.Radiobutton(main_frame, text="TCP", variable=scan_mode, value="tcp")
tcp_radio.grid(row=3, column=1, sticky="w", padx=5, pady=5)
udp_radio = ttk.Radiobutton(main_frame, text="UDP", variable=scan_mode, value="udp")
udp_radio.grid(row=3, column=1, sticky="e", padx=5, pady=5)
syn_radio = ttk.Radiobutton(main_frame, text="SYN", variable=scan_mode, value="syn")
syn_radio.grid(row=3, column=2, sticky="w", padx=5, pady=5)

# Tooltips
tooltip = ttk.Label(main_frame, text="SYN scan requires admin privileges.", foreground="gray")
tooltip.grid(row=4, column=0, columnspan=3, pady=5, sticky="w")

# Buttons
button_frame = ttk.Frame(main_frame)
button_frame.grid(row=5, column=0, columnspan=2, pady=10)

scan_button = ttk.Button(button_frame, text="Start Scan", command=run_scan)
scan_button.grid(row=0, column=0, padx=5)

stop_button = ttk.Button(button_frame, text="Stop Scan", command=stop_scan)
stop_button.grid(row=0, column=1, padx=5)

save_button = ttk.Button(button_frame, text="Save Results", command=save_results)
save_button.grid(row=0, column=2, padx=5)

clear_button = ttk.Button(button_frame, text="Clear Results", command=clear_results)
clear_button.grid(row=0, column=3, padx=5)

# Shodan lookup
shodan_button = ttk.Button(button_frame, text="Shodan Lookup", command=run_shodan_lookup)
shodan_button.grid(row=0, column=4, padx=5)

# OS detection button
os_button = ttk.Button(button_frame, text="Detect OS", command=run_os_detection)
os_button.grid(row=0, column=5, padx=5)

# Progress Bar
progress_bar = ttk.Progressbar(main_frame, length=300, mode="determinate")
progress_bar.grid(row=6, column=0, columnspan=2, pady=5)

# Status Label
status_label = ttk.Label(main_frame, text="", foreground="blue")
status_label.grid(row=7, column=0, columnspan=2, pady=5)

# Result Table
result_frame = ttk.Frame(main_frame)
result_frame.grid(row=8, column=0, columnspan=2, sticky="nsew")

columns = ("Port", "Status", "Service")
result_list = ttk.Treeview(result_frame, columns=columns, show="headings")
result_list.heading("Port", text="Port")
result_list.heading("Status", text="Status")
result_list.heading("Service", text="Service")

# Add tags for color-coding
result_list.tag_configure(TAG_OPEN, background="light green")
result_list.tag_configure(TAG_CLOSED, background="white")
result_list.tag_configure(TAG_ERROR, background="light coral")  # Red for errors
result_list.tag_configure(TAG_FILTERED, background="light yellow")  # Yellow for filtered

result_list.grid(row=0, column=0, sticky="nsew")

# Scrollbar for result list
scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=result_list.yview)
scrollbar.grid(row=0, column=1, sticky="ns")
result_list.configure(yscrollcommand=scrollbar.set)

# UDP Note
udp_note = ttk.Label(main_frame, text="Note: UDP scanning may be unreliable due to the nature of the protocol.", foreground="gray")
udp_note.grid(row=9, column=0, columnspan=2, pady=5, sticky="w")

# Run GUI
root.mainloop()