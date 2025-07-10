import os
import hashlib
import pefile
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
        self.setWindowTitle("CyberShield - Threat Scanner")
        self.setGeometry(100, 100, 1000, 700)
        
        # Set default font
        self.default_font = QFont()
        self.default_font.setPointSize(10)  # Increased from default 8/9
        
        # Dark theme
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        self.setPalette(palette)
        
        # Main Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # File Selection
        file_frame = QFrame()
        file_frame.setStyleSheet("background: rgba(40, 40, 40); border-radius: 8px; padding: 10px;")
        file_layout = QHBoxLayout(file_frame)
        
        self.select_btn = QPushButton("📁 Browse File")
        self.select_btn.setFont(self.default_font)
        self.select_btn.setStyleSheet("""
            QPushButton {
                background: #2a82da; 
                color: white; 
                border: none; 
                padding: 8px 15px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover { background: #3a92ea; }
        """)
        self.select_btn.clicked.connect(self.select_file)
        
        self.path_label = QLabel("No file selected")
        self.path_label.setFont(self.default_font)
        self.path_label.setStyleSheet("color: #aaa; font-size: 12px;")
        
        file_layout.addWidget(self.select_btn)
        file_layout.addWidget(self.path_label)
        
        # Scan Button
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setFont(self.default_font)
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover { background: #2ecc71; }
            QPushButton:disabled { background: #555; }
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 255, 0, 80))
        shadow.setOffset(0, 2)
        self.scan_btn.setGraphicsEffect(shadow)
        self.scan_btn.clicked.connect(self.start_scan)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setFont(self.default_font)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
                height: 25px;
                font-size: 12px;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ecc71, stop:1 #3498db
                );
                border-radius: 4px;
            }
        """)
        
        # Results Tabs
        self.tabs = QTabWidget()
        self.tabs.setFont(self.default_font)
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px;
                background: #333;
                color: #bbb;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #444;
                color: white;
            }
        """)
        
        # Larger font for text displays
        text_font = QFont()
        text_font.setPointSize(11)
        
        self.results_view = QTextEdit()
        self.results_view.setFont(text_font)
        self.results_view.setStyleSheet("""
            background: #252525; 
            color: #eee;
            font-size: 12px;
        """)
        
        self.file_details = QTextEdit()
        self.file_details.setFont(text_font)
        self.file_details.setStyleSheet("""
            background: #252525; 
            color: #eee;
            font-size: 12px;
        """)
        
        # Graph Tab
        self.graph_tab = QWidget()
        self.graph_layout = QVBoxLayout(self.graph_tab)
        self.chart_view = QChartView()
        self.chart_view.setStyleSheet("background: transparent;")
        self.graph_layout.addWidget(self.chart_view)
        
        self.tabs.addTab(self.results_view, "Scan Results")
        self.tabs.addTab(self.file_details, "File Details")
        self.tabs.addTab(self.graph_tab, "Threat Graph")
        
        # Assemble UI
        layout.addWidget(file_frame)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.progress)
        layout.addWidget(self.tabs)
        
        # Initialize
        self.current_file = ""
        self.threat_count = 0
        self.threat_details = []
        self.threat_db = {
            "hashes": {
                "6a4a8a9e3b3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e": "Test Threat",
                "098f6bcd4621d373cade4e832627b4f6": "Test MD5 Threat"
            },
            "strings": ["malicious", "virus", "exploit", "eval(base64_decode"],
            "pe_imports": ["CreateRemoteThread", "WriteProcessMemory"]
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
            info = f"""File: {os.path.basename(path)}
Size: {self.format_size(size)}
Path: {path[:60]}...""" if len(path) > 60 else path
            
            self.file_details.setText(info)
        except Exception as e:
            self.file_details.setText(f"Error: {str(e)}")

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def start_scan(self):
        if not self.current_file:
            self.results_view.append("Error: No file selected!")
            return
            
        self.progress.setValue(0)
        self.results_view.clear()
        self.threat_count = 0
        self.threat_details = []
        self.scan_btn.setEnabled(False)
        self.results_view.append("Starting scan...")
        
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
        elif value == 75:
            self.check_heuristics()
        elif value >= 100:
            self.timer.stop()
            self.scan_btn.setEnabled(True)
            self.results_view.append("\nScan completed!")
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
                    self.results_view.append(f"\n🚨 THREAT FOUND: Known malware signature detected!")
                    self.results_view.append(f"   • Type: {threat_info['type']}")
                    self.results_view.append(f"   • Details: {threat_info['details']}")
                    self.results_view.append(f"   • Location: {threat_info['location']}")
                
                text_content = content.decode('utf-8', errors='ignore')
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
                        self.results_view.append(f"\n⚠️ SUSPICIOUS PATTERN FOUND!")
                        self.results_view.append(f"   • Type: {threat_info['type']}")
                        self.results_view.append(f"   • Pattern: {threat_info['details']}")
                        self.results_view.append(f"   • Location: {threat_info['location']}")
                        
        except Exception as e:
            self.results_view.append(f"\nError during signature check: {str(e)}")

    def check_pe(self):
        if not self.current_file.lower().endswith(('.exe', '.dll')):
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
                        self.results_view.append(f"\n⚠️ SUSPICIOUS IMPORT DETECTED!")
                        self.results_view.append(f"   • Type: {threat_info['type']}")
                        self.results_view.append(f"   • Function: {threat_info['details']}")
                        self.results_view.append(f"   • Location: {threat_info['location']}")
            pe.close()
        except Exception as e:
            self.results_view.append(f"\nPE analysis error: {str(e)}")

    def check_heuristics(self):
        try:
            size = os.path.getsize(self.current_file)
            if size > 50 * 1024 * 1024:  # >50MB
                self.threat_count += 0.5
                threat_info = {
                    "type": "Heuristic - Large File Size",
                    "details": f"{self.format_size(size)}",
                    "location": "Entire file"
                }
                self.threat_details.append(threat_info)
                self.results_view.append(f"\n⚠️ HEURISTIC WARNING!")
                self.results_view.append(f"   • Type: {threat_info['type']}")
                self.results_view.append(f"   • Size: {threat_info['details']}")
                self.results_view.append(f"   • Location: {threat_info['location']}")
            elif size < 1024:  # <1KB
                self.threat_count += 0.5
                threat_info = {
                    "type": "Heuristic - Very Small File",
                    "details": f"{self.format_size(size)}",
                    "location": "Entire file"
                }
                self.threat_details.append(threat_info)
                self.results_view.append(f"\n⚠️ HEURISTIC WARNING!")
                self.results_view.append(f"   • Type: {threat_info['type']}")
                self.results_view.append(f"   • Size: {threat_info['details']}")
                self.results_view.append(f"   • Location: {threat_info['location']}")
        except Exception as e:
            self.results_view.append(f"\nHeuristic check error: {str(e)}")

    def display_detailed_threats(self):
        if self.threat_count > 0:
            self.results_view.append("\n\n=== THREAT DETAILS ===")
            for i, threat in enumerate(self.threat_details, 1):
                self.results_view.append(f"\nTHREAT #{i}:")
                self.results_view.append(f"Type: {threat['type']}")
                self.results_view.append(f"Details: {threat['details']}")
                self.results_view.append(f"Location: {threat['location']}")
                self.results_view.append("="*30)

    def update_threat_chart(self):
        chart = QChart()
        chart.setBackgroundBrush(QColor(53, 53, 53))
        chart.setAnimationOptions(QChart.SeriesAnimations)
        
        # Set chart title font
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
            
            # Set label font
            label_font = QFont()
            label_font.setPointSize(10)
            slice.setLabelFont(label_font)
            
            # Show percentage with 1 decimal place
            percentage = 100 * slice.percentage()
            slice.setLabel(f"{slice.label()} - {percentage:.1f}%")
        
        chart.addSeries(series)
        
        # Set legend font
        legend_font = QFont()
        legend_font.setPointSize(10)
        chart.legend().setFont(legend_font)
        chart.legend().setVisible(True)
        chart.legend().setLabelColor(Qt.white)
        chart.legend().setAlignment(Qt.AlignBottom)
        
        self.chart_view.setChart(chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)

if __name__ == "__main__":
    app = QApplication([])
    window = FileScannerApp()
    window.show()
    app.exec_()