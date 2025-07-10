# 🛡️ CyberShield - Threat Scanner

A powerful desktop-based malware and virus scanner built with Python and PyQt5.  
CyberShield scans executable files for suspicious patterns, malicious imports, and known threat signatures with a visually appealing dark UI and interactive charts.

---

## 🔥 Features

- 📁 **File Picker** – Select any file to scan
- 🧠 **Threat Detection** using:
  - File hash signature checks (SHA256 & MD5)
  - Suspicious string pattern scanning
  - PE header and import inspection (`pefile`)
  - Heuristic rules (e.g. very large/small file sizes)
- 📊 **Live Scan Progress**
- 📈 **Threat Pie Chart Visualization** using `PyQtChart`
- 🌙 **Modern Dark UI Theme** with Neon-style buttons
- 💬 **Tabbed Interface**: Results, File Info, and Threat Chart

---

## 🚀 Getting Started

### 🔧 Prerequisites

Make sure Python 3.x is installed.  
Install the required Python packages:

```bash
pip install pyqt5 pyqtchart pefile
