# 🔍 Basic GUI-Based Port Scanner

A powerful, multi-threaded **GUI-based Port Scanner** built using Python and Tkinter. This tool enables fast and efficient scanning of network ports, service detection, OS detection, and Shodan lookups.

## 🚀 Features
- ✅ **TCP, UDP, and SYN Scanning** (Requires admin for SYN scans)
- ✅ **Multi-threaded Scanning** for high performance
- ✅ **Service Detection** on open ports
- ✅ **OS Detection** using TTL values
- ✅ **Shodan Integration** for gathering detailed information
- ✅ **Results Export** (CSV, TXT, JSON)
- ✅ **Real-time Progress Bar** and status updates
- ✅ **Intuitive GUI** for easy usage

---

## 📸 Screenshots

Visit the screenshots folder for images.

---

## 🛠️ Installation & Requirements

### 📌 Prerequisites
Ensure you have **Python 3.7+** installed and install the dependencies:

```sh
pip install -r requirements.txt
```

Additional dependencies:
- **Scapy** (for SYN scan)
- **Shodan API Key** (Set via environment variable `SHODAN_API_KEY`)

---

## 🎯 Usage

### 🏁 Running the Scanner
Run the following command:

```sh
python main.py
```

### 🔑 Required Admin Privileges
For **Windows**, run PowerShell as Administrator and execute:

```powershell
python main.py
```

For **Linux/macOS**, use:

```sh
sudo python3 main.py
```

---

## 🎮 GUI Overview

1. Enter the **Target IP**.
2. Choose the **Port Range** (Start & End Port).
3. Select the **Scan Type**:
   - `TCP` - Standard TCP handshake scan.
   - `UDP` - Checks open UDP ports.
   - `SYN` - Stealthy SYN scan (Requires admin privileges).
4. Click **Start Scan** to begin.
5. View results in the table (Color-coded for better visibility).
6. Use **Shodan Lookup** or **OS Detection** for deeper insights.

---

## 🔥 Example Output

| Port | Status   | Service  |
|------|---------|----------|
| 22   | Open    | SSH      |
| 80   | Open    | HTTP     |
| 443  | Open    | HTTPS    |
| 3306 | Closed  | MySQL    |
| 8080 | Filtered | Unknown |

---

## 🎯 Future Improvements
- 🔹 Improve OS detection using machine learning models
- 🔹 Implement stealth scanning techniques
- 🔹 Add network topology mapping
- 🔹 Enhance UI with dark mode and customizable themes

---

## 🤝 Contributing
Contributions are welcome! Feel free to fork the repo and submit a pull request.

---

## 📜 License
This project is licensed under the **MIT License**.

---

## 📞 Contact
For issues or suggestions, reach out via:

- **GitHub Issues**
- **Email:** syntaxajju@gmail.com

Happy Scanning! 🚀🔍

---
