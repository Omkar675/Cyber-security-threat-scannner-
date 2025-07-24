import os
import hashlib
import pefile
import re
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QFileDialog,
                            QProgressBar, QTextEdit, QTabWidget, QFrame)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QPalette, QPainter
from PyQt5.QtWidgets import QGraphicsDropShadowEffect
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QPieSlice


class FileScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberShield - Advanced Threat Scanner")
        self.setGeometry(100, 100, 1000, 700)
        
        # Set default font
        self.default_font = QFont()
        self.default_font.setPointSize(10)
        
        # Modern dark theme
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(35, 38, 41))
        palette.setColor(QPalette.WindowText, QColor(240, 240, 240))
        palette.setColor(QPalette.Base, QColor(25, 28, 31))
        palette.setColor(QPalette.AlternateBase, QColor(35, 38, 41))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, QColor(240, 240, 240))
        palette.setColor(QPalette.Button, QColor(53, 57, 60))
        palette.setColor(QPalette.ButtonText, QColor(240, 240, 240))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
        
        # Main Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Header
        header = QLabel("CyberShield Threat Scanner")
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setStyleSheet("color: #42a2d8;")
        header.setAlignment(Qt.AlignCenter)
        header.setFixedHeight(40)
        main_layout.addWidget(header)
        
        # File Selection
        file_frame = QFrame()
        file_frame.setStyleSheet("""
            background: #2a2e32; 
            border-radius: 8px; 
            padding: 15px;
            border: 1px solid #3a3f44;
        """)
        file_layout = QVBoxLayout(file_frame)
        file_layout.setSpacing(10)
        
        file_label = QLabel("Select File to Scan:")
        file_label.setFont(self.default_font)
        file_label.setStyleSheet("color: #a0a0a0; font-weight: bold;")
        file_layout.addWidget(file_label)
        
        file_btn_layout = QHBoxLayout()
        self.select_btn = QPushButton("📁 Browse File")
        self.select_btn.setFont(self.default_font)
        self.select_btn.setStyleSheet("""
            QPushButton {
                background: #42a2d8; 
                color: white; 
                border: none; 
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover { background: #52b2e8; }
            QPushButton:pressed { background: #3282b8; }
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(8)
        shadow.setColor(QColor(66, 162, 216, 100))
        shadow.setOffset(0, 2)
        self.select_btn.setGraphicsEffect(shadow)
        self.select_btn.clicked.connect(self.select_file)
        
        self.path_label = QLabel("No file selected")
        self.path_label.setFont(self.default_font)
        self.path_label.setStyleSheet("color: #d0d0d0; font-size: 12px; padding: 5px;")
        
        file_btn_layout.addWidget(self.select_btn)
        file_btn_layout.addWidget(self.path_label, 1)
        file_layout.addLayout(file_btn_layout)
        
        # Scan Button
        self.scan_btn = QPushButton("🔍 Start Security Scan")
        self.scan_btn.setFont(self.default_font)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #27ae60;
                color: white;
                border: none;
                padding: 12px 25px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover { background: #2ecc71; }
            QPushButton:disabled { 
                background: #3a4a53; 
                color: #909090;
            }
        """)
        scan_shadow = QGraphicsDropShadowEffect()
        scan_shadow.setBlurRadius(12)
        scan_shadow.setColor(QColor(0, 255, 0, 60))
        scan_shadow.setOffset(0, 3)
        self.scan_btn.setGraphicsEffect(scan_shadow)
        self.scan_btn.clicked.connect(self.start_scan)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setFont(self.default_font)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3a3f44;
                border-radius: 5px;
                text-align: center;
                height: 28px;
                font-size: 13px;
                background: #25282c;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #42a2d8, stop:1 #2ecc71
                );
                border-radius: 4px;
            }
        """)
        
        # Results Tabs
        self.tabs = QTabWidget()
        self.tabs.setFont(self.default_font)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3a3f44;
                border-radius: 5px;
                background: #25282c;
            }
            QTabBar::tab {
                padding: 10px 15px;
                background: #2a2e32;
                color: #b0b0b0;
                font-size: 12px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                border: 1px solid #3a3f44;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #25282c;
                color: white;
                border-bottom: 2px solid #42a2d8;
            }
            QTabBar::tab:hover {
                background: #303439;
            }
        """)
        
        # Text displays
        text_font = QFont()
        text_font.setPointSize(11)
        
        # Scan Results Tab
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        results_layout.setContentsMargins(5, 5, 5, 5)
        
        self.results_view = QTextEdit()
        self.results_view.setFont(text_font)
        self.results_view.setStyleSheet("""
            background: #25282c; 
            color: #e0e0e0;
            border: none;
            border-radius: 5px;
            padding: 10px;
            font-size: 12px;
        """)
        self.results_view.setReadOnly(True)
        results_layout.addWidget(self.results_view)
        
        # File Details Tab
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        
        self.file_details = QTextEdit()
        self.file_details.setFont(text_font)
        self.file_details.setStyleSheet("""
            background: #25282c; 
            color: #e0e0e0;
            border: none;
            border-radius: 5px;
            padding: 10px;
            font-size: 12px;
        """)
        self.file_details.setReadOnly(True)
        details_layout.addWidget(self.file_details)
        
        # Threat Graph Tab
        graph_tab = QWidget()
        graph_layout = QVBoxLayout(graph_tab)
        graph_layout.setContentsMargins(10, 10, 10, 10)
        
        self.chart_view = QChartView()
        self.chart_view.setStyleSheet("background: transparent;")
        graph_layout.addWidget(self.chart_view)
        
        self.tabs.addTab(results_tab, "Scan Results")
        self.tabs.addTab(details_tab, "File Details")
        self.tabs.addTab(graph_tab, "Threat Analysis")
        
        # Assemble UI
        main_layout.addWidget(file_frame)
        main_layout.addWidget(self.scan_btn)
        main_layout.addWidget(self.progress)
        main_layout.addWidget(self.tabs, 1)
        
        # Initialize
        self.current_file = ""
        self.threat_count = 0
        self.threat_details = []
        
        # Enhanced threat database
        self.threat_db = {
            "hashes": {
                "6a4a8a9e3b3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e": "Test Threat",
                "098f6bcd4621d373cade4e832627b4f6": "Test MD5 Threat"
            },
            "strings": ["malicious", "virus", "exploit", "trojan", "backdoor"],
            "risky_commands": [
                "eval", "exec", "system", "shell_exec", "passthru",
                "base64_decode", "base64_encode", "gzinflate", 
                "str_rot13", "create_function", "assert",
                "wscript.shell", "cmd.exe", "powershell",
                "regsvr32", "certutil", "mshta", "rundll32"
            ],
            "evasion_patterns": [
                r"\{\s*\\[a-z0-9]+\s*[^\}]*\}",  # Obfuscated code patterns
                r"\b(?:chr|strrev|substr|rot13|pack)\s*\([^)]+\)",  # String manipulation
                r"\$_[A-Z]{2,}",  # Superglobal variables
                r"\beval\s*\(\s*base64_decode\s*\(",  # Nested evals
                r"\.CreateInstance\s*\("  # COM object creation
            ],
            "pe_imports": [
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc", 
                "LoadLibrary", "GetProcAddress", "SetWindowsHookEx",
                "URLDownloadToFile", "WinExec"
            ]
        }

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.current_file = file_path
            short_path = os.path.basename(file_path)[:40] + "..." if len(file_path) > 40 else os.path.basename(file_path)
            self.path_label.setText(f"Selected: {short_path}")
            self.display_file_info(file_path)

    def display_file_info(self, path):
        try:
            size = os.path.getsize(path)
            created = os.path.getctime(path)
            modified = os.path.getmtime(path)
            
            info = f"""=== File Information ===
Name: {os.path.basename(path)}
Size: {self.format_size(size)}
Created: {self.format_timestamp(created)}
Modified: {self.format_timestamp(modified)}
Path: {path}"""
            
            self.file_details.setText(info)
        except Exception as e:
            self.file_details.setText(f"Error: {str(e)}")

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def format_timestamp(self, timestamp):
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def start_scan(self):
        if not self.current_file:
            self.results_view.append("Error: No file selected!")
            return
            
        self.progress.setValue(0)
        self.results_view.clear()
        self.threat_count = 0
        self.threat_details = []
        self.scan_btn.setEnabled(False)
        self.results_view.append("🚀 Starting security scan...")
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_scan)
        self.timer.start(50)

    def update_scan(self):
        value = self.progress.value() + 5
        self.progress.setValue(value)
        
        if value == 25:
            self.check_signatures()
        elif value == 50:
            self.check_pe()
        elif value >= 100:
            self.timer.stop()
            self.scan_btn.setEnabled(True)
            self.results_view.append("\n✅ Scan completed!")
            self.display_detailed_threats()
            self.update_threat_chart()

    def check_signatures(self):
        try:
            with open(self.current_file, "rb") as f:
                content = f.read(4096)
                file_hash = hashlib.sha256(content).hexdigest()
                
                if file_hash in self.threat_db["hashes"]:
                    self.threat_count += 1
                    threat_info = {
                        "type": "Known Malware Signature",
                        "details": self.threat_db["hashes"][file_hash],
                        "location": "File header (SHA256 hash match)"
                    }
                    self.threat_details.append(threat_info)
                    self.results_view.append(f"\n🔴 CRITICAL: Known malware signature detected!")
                    self.results_view.append(f"   • Type: {threat_info['type']}")
                    self.results_view.append(f"   • Details: {threat_info['details']}")
                    self.results_view.append(f"   • Location: {threat_info['location']}")
                
                text_content = content.decode('utf-8', errors='ignore').lower()
                
                # Check for suspicious strings
                for pattern in self.threat_db["strings"]:
                    if pattern in text_content:
                        self.threat_count += 1
                        position = text_content.find(pattern)
                        threat_info = {
                            "type": "Suspicious String Pattern",
                            "details": pattern,
                            "location": f"Offset {position}-{position+len(pattern)} in first 4KB"
                        }
                        self.threat_details.append(threat_info)
                        self.results_view.append(f"\n⚠️ WARNING: Suspicious pattern found!")
                        self.results_view.append(f"   • Type: {threat_info['type']}")
                        self.results_view.append(f"   • Pattern: {threat_info['details']}")
                        self.results_view.append(f"   • Location: {threat_info['location']}")
                
                # Detect risky commands
                found_commands = set()
                for cmd in self.threat_db["risky_commands"]:
                    if cmd in text_content:
                        found_commands.add(cmd)
                
                if found_commands:
                    self.threat_count += len(found_commands)
                    command_list = ", ".join(sorted(found_commands))
                    threat_info = {
                        "type": "Risky Commands Detected",
                        "details": f"{len(found_commands)} dangerous commands: {command_list}",
                        "location": "First 4KB of file content"
                    }
                    self.threat_details.append(threat_info)
                    self.results_view.append(f"\n⚠️ WARNING: Risky commands detected!")
                    self.results_view.append(f"   • Type: {threat_info['type']}")
                    self.results_view.append(f"   • Commands: {command_list}")
                    self.results_view.append(f"   • Location: {threat_info['location']}")
                
                # Detect evasion techniques
                evasion_matches = []
                for pattern in self.threat_db["evasion_patterns"]:
                    if re.search(pattern, text_content, re.IGNORECASE):
                        evasion_matches.append(pattern)
                
                if evasion_matches:
                    self.threat_count += len(evasion_matches)
                    evasion_list = ", ".join([m[:20] + "..." for m in evasion_matches])
                    threat_info = {
                        "type": "Evasion Techniques",
                        "details": f"{len(evasion_matches)} evasion patterns: {evasion_list}",
                        "location": "First 4KB of file content"
                    }
                    self.threat_details.append(threat_info)
                    self.results_view.append(f"\n⚠️ WARNING: Evasion techniques detected!")
                    self.results_view.append(f"   • Type: {threat_info['type']}")
                    self.results_view.append(f"   • Patterns: {evasion_list}")
                    self.results_view.append(f"   • Location: {threat_info['location']}")
                        
        except Exception as e:
            self.results_view.append(f"\nError during signature check: {str(e)}")

    def check_pe(self):
        if not self.current_file.lower().endswith(('.exe', '.dll', '.sys')):
            return
            
        try:
            pe = pefile.PE(self.current_file)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in self.threat_db["pe_imports"]:
                        self.threat_count += 1
                        threat_info = {
                            "type": "Suspicious PE Import",
                            "details": imp.name.decode(),
                            "location": f"Imported from {dll_name} (address: {hex(imp.address)})"
                        }
                        self.threat_details.append(threat_info)
                        self.results_view.append(f"\n⚠️ WARNING: Suspicious import detected!")
                        self.results_view.append(f"   • Type: {threat_info['type']}")
                        self.results_view.append(f"   • Function: {threat_info['details']}")
                        self.results_view.append(f"   • Location: {threat_info['location']}")
            pe.close()
        except Exception as e:
            self.results_view.append(f"\nPE analysis error: {str(e)}")

    def display_detailed_threats(self):
        if self.threat_count > 0:
            self.results_view.append("\n\n🔍 === THREAT SUMMARY ===")
            self.results_view.append(f"Total threats detected: {self.threat_count}")
            
            # Count threat types
            threat_types = {}
            for threat in self.threat_details:
                if threat['type'] in threat_types:
                    threat_types[threat['type']] += 1
                else:
                    threat_types[threat['type']] = 1
            
            self.results_view.append("\nThreat Type Breakdown:")
            for ttype, count in threat_types.items():
                self.results_view.append(f"  - {ttype}: {count} instances")
            
            self.results_view.append("\n=== DETAILED THREAT LIST ===")
            for i, threat in enumerate(self.threat_details, 1):
                self.results_view.append(f"\nTHREAT #{i}:")
                self.results_view.append(f"Type: {threat['type']}")
                self.results_view.append(f"Details: {threat['details']}")
                self.results_view.append(f"Location: {threat['location']}")
                self.results_view.append("="*50)
        else:
            self.results_view.append("\n🟢 No threats detected! File appears safe.")

    def update_threat_chart(self):
        chart = QChart()
        chart.setBackgroundBrush(QColor(35, 38, 41))
        chart.setAnimationOptions(QChart.SeriesAnimations)
        
        title_font = QFont()
        title_font.setPointSize(12)
        chart.setTitleFont(title_font)
        
        if self.threat_count > 0:
            chart.setTitle(f"THREATS DETECTED: {self.threat_count} indicators")
            chart.setTitleBrush(QColor(231, 76, 60))  # Red title for threats
        else:
            chart.setTitle("No Threats Detected")
            chart.setTitleBrush(QColor(46, 204, 113))  # Green title for clean
        
        series = QPieSeries()
        
        if self.threat_count > 0:
            series.append(f"Threats ({self.threat_count})", self.threat_count)
            series.append("Clean", 1)  # Small slice for clean
        else:
            series.append("Clean", 1)
        
        # Style slices
        for slice in series.slices():
            if "Threats" in slice.label():
                slice.setColor(QColor(231, 76, 60))  # Red
                slice.setLabelVisible(True)
                slice.setLabelColor(Qt.white)
                slice.setLabelPosition(QPieSlice.LabelOutside)
                slice.setExploded(True)
                slice.setExplodeDistanceFactor(0.1)
                slice.setLabelArmLengthFactor(0.2)
            else:
                slice.setColor(QColor(46, 204, 113))  # Green
                slice.setLabelVisible(True)
                slice.setLabelColor(Qt.white)
                slice.setLabelPosition(QPieSlice.LabelOutside)
            
            label_font = QFont()
            label_font.setPointSize(10)
            slice.setLabelFont(label_font)
            
            percentage = 100 * slice.percentage()
            slice.setLabel(f"{slice.label()} - {percentage:.1f}%")
        
        chart.addSeries(series)
        
        legend_font = QFont()
        legend_font.setPointSize(10)
        chart.legend().setFont(legend_font)
        chart.legend().setVisible(True)
        chart.legend().setLabelColor(Qt.white)
        chart.legend().setAlignment(Qt.AlignBottom)
        
        self.chart_view.setChart(chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)


if __name__ == "__main__":
    # Fix for high DPI displays
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    window = FileScannerApp()
    window.show()
    sys.exit(app.exec_())