import tkinter as tk
from tkinter import ttk, messagebox
from scanner import scan_ports
import threading

def update_progress(port, status, service):
    """Updates the UI with scan results."""
    if status == "Open":
        result_list.insert("", "end", values=(port, status, service))

def start_scan():
    """Starts the scanning process in a new thread."""
    target_ip = ip_entry.get()
    try:
        start = int(start_port.get())
        end = int(end_port.get())
        port_range = range(start, end + 1)
    except ValueError:
        messagebox.showerror("Error", "Invalid port numbers. Please enter valid integers.")
        return
    
    # Clear previous results
    result_list.delete(*result_list.get_children())

    # Run scan in a new thread to prevent UI freezing
    scan_thread = threading.Thread(target=scan_ports, args=(target_ip, port_range, update_progress))
    scan_thread.start()

# GUI Setup
root = tk.Tk()
root.title("Port Scanner with Service Detection")

# Input Fields
tk.Label(root, text="Target IP:").grid(row=0, column=0)
ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1)

tk.Label(root, text="Start Port:").grid(row=1, column=0)
start_port = tk.Entry(root)
start_port.grid(row=1, column=1)

tk.Label(root, text="End Port:").grid(row=2, column=0)
end_port = tk.Entry(root)
end_port.grid(row=2, column=1)

# Start Scan Button
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.grid(row=3, columnspan=2)

# Result Table
columns = ("Port", "Status", "Service")
result_list = ttk.Treeview(root, columns=columns, show="headings")
result_list.heading("Port", text="Port")
result_list.heading("Status", text="Status")
result_list.heading("Service", text="Service")
result_list.grid(row=4, columnspan=2)

root.mainloop()
