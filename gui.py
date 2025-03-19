import tkinter as tk
from tkinter import ttk
from scanner import scan_ports

def start_scan():
    target_ip = ip_entry.get()
    port_range = range(int(start_port.get()), int(end_port.get()) + 1)
    
    result_list.delete(*result_list.get_children())  # Clear previous results
    results = scan_ports(target_ip, port_range)
    
    for port, status in results:
        result_list.insert("", "end", values=(port, status))

# GUI Setup
root = tk.Tk()
root.title("Port Scanner")

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
columns = ("Port", "Status")
result_list = ttk.Treeview(root, columns=columns, show="headings")
result_list.heading("Port", text="Port")
result_list.heading("Status", text="Status")
result_list.grid(row=4, columnspan=2)

root.mainloop()
