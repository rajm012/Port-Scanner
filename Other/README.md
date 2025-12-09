
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

---

## 🛠️ Generating the Executable

The final executable (`gui.exe`) is **90 MB** in size, which exceeds GitHub's file size limit of **25 MB**. To work around this, the executable has been split into smaller parts. Follow the steps below to rejoin the parts and generate the `.exe` file.

### Steps to Rejoin the Executable
1. Download all the split parts (e.g., `gui.exe.part1`, `gui.exe.part2`, etc.).
2. Use the following command to rejoin the parts:

   ```sh
   copy /b gui.exe.part1 + gui.exe.part2 + gui.exe.part3 gui.exe
   ```

   Replace `gui.exe.part1`, `gui.exe.part2`, etc., with the actual filenames of the split parts.

3. Once rejoined, you will have the complete `gui.exe` file.

OR

Use the script given in the `Split-Reassemble` file to rejoin the parts.

---

### If Rejoining Doesn't Work: Generate Your Own Executable
If the rejoined executable doesn't work or you prefer to generate your own, follow these steps:

1. Install **PyInstaller**:

   ```sh
   pip install pyinstaller
   ```

2. Navigate to the project directory:

   ```sh
   cd path\to\Port-Scanner
   ```

3. Generate the executable:

   ```sh
   pyinstaller --onefile --windowed main.py
   ```

   This will create a standalone executable in the `dist` folder.

4. Run the executable:

   ```sh
   dist\main.exe
   ```

---

## 🗑️ Cleaning Up After Build
After generating the executable, you can delete the following files/folders to save space:
- `build/` folder
- `main.spec` file
- Any intermediate files like `PYZ-00.pyz` or `main.pkg`

Keep only the `dist/main.exe` file for distribution.

---

Happy Scanning! 🚀🔍

---