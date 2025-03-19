import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
from scanner import scan_ports, shodan_lookup, get_ttl, detect_os
import os
import ctypes
import sys

SHODAN_API_KEY="S0EA8Co1efoOunYbc1EIPOuZDZCo45Cx"


# Global variable to control scanning
scanning = False
scanning_lock = threading.Lock()


def stop_scan():
    global scanning
    with scanning_lock:
        scanning = False
    status_label.config(text="Scan stopped.")


# Function to update progress bar
def update_progress(value):
    progress_bar["value"] = value
    root.update_idletasks()

# Function to run the scan
def run_scan():
    global scanning
    scanning = True
    target_ip = ip_entry.get().strip()
    start = int(start_port.get())
    end = int(end_port.get())
    scan_type = scan_mode.get()  # "tcp" or "udp"

    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    port_range = range(start, end + 1)
    result_list.delete(*result_list.get_children())  # Clear previous results
    status_label.config(text=f"Scanning {target_ip} ({scan_type.upper()})...")

    # Start scanning in a separate thread
    scan_thread = threading.Thread(target=scan_ports_gui, args=(target_ip, port_range, scan_type))
    scan_thread.start()


# Function to handle scanning updates
def scan_ports_gui(target_ip, port_range, scan_type):
    global scanning
    num_ports = len(port_range)
    progress_step = 100 / num_ports if num_ports > 0 else 100
    progress = 0

    def thread_callback(port, status, service):
        nonlocal progress
        if not scanning:
            return
        
        tag = "open" if status == "Open" else "closed"

        if "Error" in status or "Filtered" in status:
            tag = "error" if "Error" in status else "filtered"

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


# Function to save results
def save_results():
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

    result = shodan_lookup(target_ip)


    if "Error" in result:
        messagebox.showerror("Shodan Error", result["Error"])

    else:
        info_text = f"IP: {result['IP']}\nOrganization: {result['Organization']}\n"
        info_text += f"ISP: {result['ISP']}\nOS: {result['OS']}\n"
        info_text += f"Open Ports: {', '.join(map(str, result['Open Ports']))}\n"
        info_text += f"Vulnerabilities: {result['Vulnerabilities']}\n"
        
        messagebox.showinfo("Shodan Lookup", info_text)


def run_os_detection():
    target_ip = ip_entry.get().strip()
    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    try:
        ttl = get_ttl(target_ip)
        if ttl is None:
            messagebox.showwarning("OS Detection", "Could not determine OS. Ensure you have administrative privileges.")
            return

        os_guess = detect_os(ttl)
        messagebox.showinfo("OS Detection", f"Detected OS: {os_guess} (TTL={ttl})")

    except PermissionError:
        messagebox.showerror("Error", "Administrative privileges required for OS detection.")


# GUI Setup
root = tk.Tk()
root.title("Advanced Port Scanner")
root.geometry("800x500")

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

# Scan Type Selection (TCP/UDP)
scan_mode = tk.StringVar(value="tcp")
ttk.Label(main_frame, text="Scan Type:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
tcp_radio = ttk.Radiobutton(main_frame, text="TCP", variable=scan_mode, value="tcp")
tcp_radio.grid(row=3, column=1, sticky="w", padx=5, pady=5)
udp_radio = ttk.Radiobutton(main_frame, text="UDP", variable=scan_mode, value="udp")
udp_radio.grid(row=3, column=1, sticky="e", padx=5, pady=5)

# Buttons
button_frame = ttk.Frame(main_frame)
button_frame.grid(row=4, column=0, columnspan=2, pady=10)

scan_button = ttk.Button(button_frame, text="Start Scan", command=run_scan)
scan_button.grid(row=0, column=0, padx=5)

stop_button = ttk.Button(button_frame, text="Stop Scan", command=stop_scan)
stop_button.grid(row=0, column=1, padx=5)

save_button = ttk.Button(button_frame, text="Save Results", command=save_results)
save_button.grid(row=0, column=2, padx=5)

# Progress Bar
progress_bar = ttk.Progressbar(main_frame, length=300, mode="determinate")
progress_bar.grid(row=5, column=0, columnspan=2, pady=5)

# Status Label
status_label = ttk.Label(main_frame, text="", foreground="blue")
status_label.grid(row=6, column=0, columnspan=2, pady=5)

# Result Table
result_frame = ttk.Frame(main_frame)
result_frame.grid(row=7, column=0, columnspan=2, sticky="nsew")

columns = ("Port", "Status", "Service")
result_list = ttk.Treeview(result_frame, columns=columns, show="headings")
result_list.heading("Port", text="Port")
result_list.heading("Status", text="Status")
result_list.heading("Service", text="Service")

# Add tags for color-coding
result_list.tag_configure("open", background="light green")
result_list.tag_configure("closed", background="white")
result_list.tag_configure("error", background="light coral")  # Red for errors
result_list.tag_configure("filtered", background="light yellow")  # Yellow for filtered

result_list.grid(row=0, column=0, sticky="nsew")

# Scrollbar for result list
scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=result_list.yview)
scrollbar.grid(row=0, column=1, sticky="ns")
result_list.configure(yscrollcommand=scrollbar.set)


# Add a button for Shodan lookup
shodan_button = ttk.Button(button_frame, text="Shodan Lookup", command=run_shodan_lookup)
shodan_button.grid(row=0, column=3, padx=5)

# Add OS detection button
os_button = ttk.Button(button_frame, text="Detect OS", command=run_os_detection)
os_button.grid(row=0, column=4, padx=5)


udp_note = ttk.Label(main_frame, text="Note: UDP scanning may be unreliable due to the nature of the protocol.", foreground="gray")
udp_note.grid(row=9, column=0, columnspan=2, pady=5)

# Run GUI
root.mainloop()



# -------------------------------------
# ------------How to test--------------
# 
# For the OS test only enter the IP:
# 
# Target IP: 8.8.8.8 (Google DNS server):
# Detected OS: Linux/Unix (TTL=64)
# 
# For 192.168.1.1 (local router):
# Detected OS: Windows (TTL=128)
# 
# -----------------------------------------------------------------------------------
# 
# For Shodan Lookup: Enter a public IP address (e.g., 8.8.8.8) in the "Target IP" field:
# 
# IP: 8.8.8.8
# Organization: Google LLC
# ISP: Google LLC
# OS: Unknown
# Open Ports: 53
# Vulnerabilities: None
# 
# ------------------------------------------------------------------------------------