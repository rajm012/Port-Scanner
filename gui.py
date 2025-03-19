import tkinter as tk
from tkinter import ttk, filedialog
import threading
from scanner import scan_ports
import json

def update_progress(value):
    progress_bar["value"] = value
    root.update_idletasks()

def run_scan():
    target_ip = ip_entry.get()
    start = int(start_port.get())
    end = int(end_port.get())
    port_range = range(start, end + 1)

    result_list.delete(*result_list.get_children())  # Clear previous results
    status_label.config(text=f"Scanning {target_ip}...")  # Show scan status

    scan_thread = threading.Thread(target=scan_ports_gui, args=(target_ip, port_range))
    scan_thread.start()



def scan_ports_gui(target_ip, port_range):
    num_ports = len(port_range)
    progress_step = 100 / num_ports if num_ports > 0 else 100
    progress = 0

    def thread_callback(port, status, service):
        nonlocal progress
        result_list.insert("", "end", values=(port, status, service))  # Add result to GUI
        progress += progress_step
        update_progress(progress)  # Update progress bar

    # Start multithreaded scanning
    scan_ports(target_ip, port_range, thread_callback)

    progress_bar["value"] = 100  # Ensure full progress when done


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

# Status Label
status_label = tk.Label(root, text="", fg="blue")
status_label.grid(row=6, columnspan=2)


# Start Scan Button
scan_button = tk.Button(root, text="Start Scan", command=run_scan)
scan_button.grid(row=3, column=0)

# Save Results Button
save_button = tk.Button(root, text="Save Results", command=save_results)
save_button.grid(row=3, column=1)

# Progress Bar
progress_bar = ttk.Progressbar(root, length=200, mode="determinate")
progress_bar.grid(row=4, columnspan=2)

# Result Table
columns = ("Port", "Status", "Service")
result_list = ttk.Treeview(root, columns=columns, show="headings")
result_list.heading("Port", text="Port")
result_list.heading("Status", text="Status")
result_list.heading("Service", text="Service")
result_list.grid(row=5, columnspan=2)

root.mainloop()
