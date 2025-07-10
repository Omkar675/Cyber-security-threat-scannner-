import os
import hashlib
import pefile
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QFileDialog,
                            QProgressBar, QTextEdit, QTabWidget, QFrame)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QPalette, QPainter  # ✅ QPainter added
from PyQt5.QtWidgets import QGraphicsDropShadowEffect
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QPieSlice


class FileScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberShield - Threat Scanner")
        self.setGeometry(100, 100, 1000, 700)
        
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
        self.select_btn.setStyleSheet("""
            QPushButton {
                background: #2a82da; 
                color: white; 
                border: none; 
                padding: 8px 15px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background: #3a92ea; }
        """)
        self.select_btn.clicked.connect(self.select_file)
        
        self.path_label = QLabel("No file selected")
        self.path_label.setStyleSheet("color: #aaa;")
        
        file_layout.addWidget(self.select_btn)
        file_layout.addWidget(self.path_label)
        
        # Scan Button
        self.scan_btn = QPushButton("🔍 Start Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background: #27ae60;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
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
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
                height: 20px;
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
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px;
                background: #333;
                color: #bbb;
            }
            QTabBar::tab:selected {
                background: #444;
                color: white;
            }
        """)
        
        self.results_view = QTextEdit()
        self.results_view.setStyleSheet("background: #252525; color: #eee;")
        self.file_details = QTextEdit()
        self.file_details.setStyleSheet("background: #252525; color: #eee;")
        
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
            self.update_threat_chart()

    def check_signatures(self):
        try:
            with open(self.current_file, "rb") as f:
                content = f.read(4096)
                file_hash = hashlib.sha256(content).hexdigest()
                
                if file_hash in self.threat_db["hashes"]:
                    self.threat_count += 1
                    self.results_view.append(f"\n🚨 Threat found: {self.threat_db['hashes'][file_hash]}")
                
                text_content = content.decode('utf-8', errors='ignore')
                for pattern in self.threat_db["strings"]:
                    if pattern in text_content:
                        self.threat_count += 1
                        self.results_view.append(f"\n⚠️ Suspicious pattern: {pattern}")
                        
        except Exception as e:
            self.results_view.append(f"\nError during signature check: {str(e)}")

    def check_pe(self):
        if not self.current_file.lower().endswith(('.exe', '.dll')):
            return
            
        try:
            pe = pefile.PE(self.current_file)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in self.threat_db["pe_imports"]:
                        self.threat_count += 1
                        self.results_view.append(f"\n⚠️ Suspicious import: {imp.name.decode()}")
            pe.close()
        except:
            pass

    def check_heuristics(self):
        try:
            with open(self.current_file, "rb") as f:
                size = os.path.getsize(self.current_file)
                if size > 50 * 1024 * 1024:  # >50MB
                    self.threat_count += 0.5  # Half weight for heuristic
                    self.results_view.append("\n⚠️ Large file size (possible packed executable)")
                elif size < 1024:  # <1KB
                    self.threat_count += 0.5
                    self.results_view.append("\n⚠️ Very small file (possible stub)")
        except:
            pass

    def update_threat_chart(self):
        chart = QChart()
        chart.setTitle("Threat Analysis")
        chart.setBackgroundBrush(QColor(53, 53, 53))
        chart.setTitleBrush(Qt.white)
        
        series = QPieSeries()
        series.append("Threats", self.threat_count)
        series.append("Clean", max(1, 10 - self.threat_count))  # Ensure we always have some slice
        
        # Style slices
        for slice in series.slices():
            if slice.label() == "Threats":
                slice.setColor(QColor(231, 76, 60))  # Red
                slice.setLabelVisible(True)
                slice.setLabelColor(Qt.white)
            else:
                slice.setColor(QColor(46, 204, 113))  # Green
                slice.setLabelVisible(True)
                slice.setLabelColor(Qt.white)
        
        chart.addSeries(series)
        chart.legend().setVisible(True)
        chart.legend().setLabelColor(Qt.white)
        
        self.chart_view.setChart(chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)

if __name__ == "__main__":
    app = QApplication([])
    window = FileScannerApp()
    window.show()
    app.exec_()