
# **Guide to Basic Port Scanner**

This guide provides an overview of the **Basic Port Scanner** project, explaining its purpose, the concepts behind TCP/UDP scanning, and how to use each function in the code.

---

## **Table of Contents**
1. [What is Port Scanning?](#what-is-port-scanning)
2. [TCP vs. UDP](#tcp-vs-udp)
3. [Why Perform Port Scanning?](#why-perform-port-scanning)
4. [Features of the Advanced Port Scanner](#features-of-the-advanced-port-scanner)
5. [How to Use the Scanner](#how-to-use-the-scanner)
6. [Code Walkthrough](#code-walkthrough)
   - [Key Functions](#key-functions)
   - [How to Modify or Extend the Code](#how-to-modify-or-extend-the-code)
7. [FAQs](#faqs)

---

## **What is Port Scanning?**
Port scanning is a technique used to identify open ports on a target system. Ports are communication endpoints that allow devices to send and receive data. By scanning ports, you can determine which services are running on a system and identify potential vulnerabilities.

---

## **TCP vs. UDP**
### **TCP (Transmission Control Protocol)**
- **Connection-Oriented**: Establishes a connection before data transfer.
- **Reliable**: Ensures data is delivered accurately and in order.
- **Common Uses**: Web browsing (HTTP/HTTPS), email (SMTP), file transfer (FTP).

### **UDP (User Datagram Protocol)**
- **Connectionless**: Does not establish a connection before data transfer.
- **Faster but Less Reliable**: Does not guarantee data delivery or order.
- **Common Uses**: Video streaming, online gaming, DNS queries.

---

## **Why Perform Port Scanning?**
Port scanning is used for:
- **Network Security**: Identifying open ports to detect potential vulnerabilities.
- **Troubleshooting**: Diagnosing network issues by checking if services are running.
- **Penetration Testing**: Assessing the security of a network or system.

---

## **Features of the Advanced Port Scanner**
- **TCP/UDP/SYN Scanning**: Scan ports using different protocols.
- **Shodan Integration**: Look up IP information using the Shodan API.
- **OS Detection**: Detect the operating system of the target IP.
- **Progress Bar**: Real-time progress tracking for scans.
- **Save Results**: Export scan results to CSV, JSON, or text files.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

---

## **How to Use the Scanner**
1. **Enter Target IP**: Provide the IP address of the target system.
2. **Set Port Range**: Specify the start and end ports for scanning.
3. **Select Scan Type**: Choose between TCP, UDP, or SYN scan.
4. **Start Scan**: Click "Start Scan" to begin the scan.
5. **View Results**: Results will be displayed in the table below.
6. **Save Results**: Click "Save Results" to export the scan results.

---

## **Code Walkthrough**

### **Key Functions**
Here’s a breakdown of the key functions in the code:

#### **1. `is_admin()`**
- **Purpose**: Checks if the script is running with administrative privileges.
- **Usage**: Required for SYN scan and OS detection.
- **Location**: Called at the start of the script.

#### **2. `run_scan()`**
- **Purpose**: Starts the scan based on the selected scan type.
- **Usage**: Called when the "Start Scan" button is clicked.
- **Parameters**: Target IP, start port, end port, and scan type.

#### **3. `scan_ports_gui()`**
- **Purpose**: Handles scanning updates for TCP/UDP scans.
- **Usage**: Called by `run_scan()` for TCP/UDP scans.
- **Parameters**: Target IP, port range, and scan type.

#### **4. `syn_scan_gui()`**
- **Purpose**: Handles SYN scan updates.
- **Usage**: Called by `run_scan()` for SYN scans.
- **Parameters**: Target IP and port range.

#### **5. `save_results()`**
- **Purpose**: Saves scan results to a file.
- **Usage**: Called when the "Save Results" button is clicked.
- **File Formats**: CSV, JSON, or text.

#### **6. `run_shodan_lookup()`**
- **Purpose**: Performs a Shodan lookup for the target IP.
- **Usage**: Called when the "Shodan Lookup" button is clicked.
- **Output**: Displays IP information in a pop-up.

#### **7. `run_os_detection()`**
- **Purpose**: Detects the operating system of the target IP.
- **Usage**: Called when the "Detect OS" button is clicked.
- **Output**: Displays the detected OS in a pop-up.

#### **8. `clear_results()`**
- **Purpose**: Clears the result table and resets the progress bar.
- **Usage**: Called when the "Clear Results" button is clicked.

---

### **How to Modify or Extend the Code**
1. **Add New Scan Types**:
   - Add a new scan type (e.g., ACK scan) by creating a new function and updating the GUI.

2. **Enhance Shodan Integration**:
   - Add more fields to the Shodan lookup results (e.g., geolocation, hostnames).

3. **Improve Error Handling**:
   - Add more robust error handling for invalid inputs or network issues.

4. **Add Logging**:
   - Use Python’s `logging` module to log scan progress and errors.

5. **Optimize Performance**:
   - Use multiprocessing to speed up scans for large port ranges.

---

## **FAQs**
### **1. Why does SYN scan require admin privileges?**
SYN scan sends raw packets, which requires low-level network access. This is only available with administrative privileges.

### **2. Why is UDP scanning unreliable?**
UDP is connectionless, so there’s no guarantee of a response. Many UDP ports may appear open even if they’re not.

### **3. How do I get a Shodan API key?**
Sign up for a Shodan account at [shodan.io](https://shodan.io) and generate an API key from your account dashboard.

### **4. Can I scan multiple IPs at once?**
Currently, the scanner supports scanning one IP at a time. You can extend the code to handle multiple IPs.

### **5. How do I stop a scan?**
Click the "Stop Scan" button to halt the ongoing scan.

---

## **Conclusion**
The **Advanced Port Scanner** is a powerful tool for network analysis and security testing. By understanding its features and functionality, you can use it effectively to identify open ports, detect vulnerabilities, and gather information about target systems.

For any questions or feedback, feel free to reach out!

---