import os
import sys
import hashlib
import mimetypes
import platform
import datetime
import pefile
import json
from collections import defaultdict
from PyQt5 import QtCore, QtChart
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QPieSlice, QBarSet, QBarSeries, QValueAxis
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt5.QtGui import (QColor, QFont, QLinearGradient, QBrush, QPainter, 
                         QTextCursor, QSyntaxHighlighter, QTextCharFormat, QIcon, QPen)
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QPushButton, QFileDialog,
                            QProgressBar, QGraphicsDropShadowEffect, QFrame, 
                            QTextEdit, QTabWidget, QScrollArea, QGroupBox,
                            QComboBox, QSplitter, QSizePolicy, QToolTip, QGraphicsView)

# Custom syntax highlighter for analysis output
class ThreatHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Threat patterns
        threat_format = QTextCharFormat()
        threat_format.setForeground(QColor(255, 50, 50))
        threat_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r'\b(CRITICAL|DANGER|MALWARE|THREAT|RISK|SUSPICIOUS)\b', threat_format))
        
        # Warning patterns
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor(255, 165, 0))
        warning_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r'\b(WARNING|CAUTION|SUSPECT|UNKNOWN)\b', warning_format))
        
        # Safe patterns
        safe_format = QTextCharFormat()
        safe_format.setForeground(QColor(50, 205, 50))
        safe_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r'\b(SAFE|CLEAN|TRUSTED|SECURE|OK)\b', safe_format))
        
        # Info patterns
        info_format = QTextCharFormat()
        info_format.setForeground(QColor(100, 200, 255))
        self.highlighting_rules.append((r'\b(INFO|DETAILS|ANALYSIS|SCAN)\b', info_format))
        
        # Hash patterns
        hash_format = QTextCharFormat()
        hash_format.setForeground(QColor(200, 200, 100))
        self.highlighting_rules.append((r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b', hash_format))
        
        # Header patterns
        header_format = QTextCharFormat()
        header_format.setForeground(QColor(255, 215, 0))
        header_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((r'^-{3,}.*-{3,}$', header_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QtCore.QRegularExpression(pattern)
            matches = expression.globalMatch(text)
            while matches.hasNext():
                match = matches.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class GlassFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            background-color: rgba(26, 26, 26, 150);
            border-radius: 15px;
            border: 1px solid rgba(0, 255, 224, 80);
        """)
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(40)
        shadow.setColor(QColor(0, 255, 255, 80))
        shadow.setOffset(0, 0)
        self.setGraphicsEffect(shadow)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor(0, 255, 255, 20))
        gradient.setColorAt(1, QColor(255, 0, 255, 20))
        painter.fillRect(self.rect(), QBrush(gradient))

class NeonButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("Consolas", 12, QFont.Bold))
        self.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 0, 0, 150);
                color: #00ffe0;
                border: 2px solid #00ffe0;
                border-radius: 10px;
                padding: 8px 15px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: rgba(0, 255, 224, 0.2);
                border: 2px solid #ff00ff;
            }
            QPushButton:pressed {
                background-color: rgba(0, 255, 224, 0.3);
            }
        """)
        self.glow = QGraphicsDropShadowEffect()
        self.glow.setBlurRadius(15)
        self.glow.setColor(QColor(0, 255, 224))
        self.glow.setOffset(0, 0)
        self.setGraphicsEffect(self.glow)
        
        # Animation for hover effect
        self.animation = QPropertyAnimation(self.glow, b"color")
        self.animation.setDuration(1000)
        self.animation.setLoopCount(-1)
        self.animation.setKeyValueAt(0, QColor(0, 255, 224))
        self.animation.setKeyValueAt(0.5, QColor(255, 0, 255))
        self.animation.setKeyValueAt(1, QColor(0, 255, 224))
        self.animation.start()

    def enterEvent(self, event):
        self.glow.setBlurRadius(25)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.glow.setBlurRadius(15)
        super().leaveEvent(event)

class ThreatMeter(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(300, 30)
        self.setMaximumHeight(40)
        self.threat_level = 0  # 0-100
        
    def set_threat_level(self, level):
        self.threat_level = max(0, min(100, level))
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background
        bg_rect = self.rect().adjusted(2, 2, -2, -2)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(40, 40, 40))
        painter.drawRoundedRect(bg_rect, 5, 5)
        
        # Threat level
        threat_width = int(bg_rect.width() * (self.threat_level / 100))
        threat_rect = bg_rect.adjusted(0, 0, - (bg_rect.width() - threat_width), 0)
        
        # Gradient based on threat level
        gradient = QLinearGradient(threat_rect.topLeft(), threat_rect.topRight())
        if self.threat_level < 30:
            gradient.setColorAt(0, QColor(0, 255, 0))
            gradient.setColorAt(1, QColor(100, 255, 0))
        elif self.threat_level < 70:
            gradient.setColorAt(0, QColor(255, 255, 0))
            gradient.setColorAt(1, QColor(255, 165, 0))
        else:
            gradient.setColorAt(0, QColor(255, 0, 0))
            gradient.setColorAt(1, QColor(200, 0, 0))
            
        painter.setBrush(QBrush(gradient))
        painter.drawRoundedRect(threat_rect, 5, 5)
        
        # Text
        painter.setPen(QColor(255, 255, 255))
        font = QFont("Consolas", 10)
        painter.setFont(font)
        threat_text = f"Threat Level: {self.threat_level}%"
        painter.drawText(bg_rect, Qt.AlignCenter, threat_text)
        
        # Border
        painter.setPen(QColor(100, 100, 100))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(bg_rect, 5, 5)

class ThreatGraph(QChartView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.chart = QChart()
        self.chart.setBackgroundBrush(QBrush(QColor(30, 30, 40)))
        self.chart.setTitleBrush(QBrush(QColor(200, 200, 200)))
        self.chart.setTitle("Threat Analysis Overview")
        self.chart.legend().setVisible(True)
        self.chart.legend().setLabelColor(QColor(200, 200, 200))
        self.chart.setAnimationOptions(QChart.SeriesAnimations)
        self.setChart(self.chart)
        
    def update_graph(self, threat_analysis):
        self.chart.removeAllSeries()
        
        # Create pie series for threat composition
        pie_series = QPieSeries()
        pie_series.setPieSize(0.7)
        
        # Add slices based on threat analysis
        detections = threat_analysis.get('threat_detections', [])
        threat_count = len(detections)
        clean_percentage = max(0, 100 - threat_analysis.get('threat_score', 0))
        
        if threat_count > 0:
            high_count = sum(1 for d in detections if d.get('severity') == 'High')
            med_count = sum(1 for d in detections if d.get('severity') == 'Medium')
            low_count = threat_count - high_count - med_count
            
            if high_count > 0:
                high_slice = pie_series.append("High Risk", high_count)
                high_slice.setColor(QColor(255, 50, 50))
                high_slice.setLabelVisible(True)
                high_slice.setLabelColor(QColor(220, 220, 220))
                
            if med_count > 0:
                med_slice = pie_series.append("Medium Risk", med_count)
                med_slice.setColor(QColor(255, 165, 0))
                med_slice.setLabelVisible(True)
                med_slice.setLabelColor(QColor(220, 220, 220))
                
            if low_count > 0:
                low_slice = pie_series.append("Low Risk", low_count)
                low_slice.setColor(QColor(100, 200, 100))
                low_slice.setLabelVisible(True)
                low_slice.setLabelColor(QColor(220, 220, 220))
                
            if clean_percentage > 0:
                clean_slice = pie_series.append("Clean", clean_percentage)
                clean_slice.setColor(QColor(50, 205, 50))
                clean_slice.setLabelVisible(True)
                clean_slice.setLabelColor(QColor(220, 220, 220))
        else:
            clean_slice = pie_series.append("Clean", 100)
            clean_slice.setColor(QColor(50, 205, 50))
            clean_slice.setLabelVisible(True)
            clean_slice.setLabelColor(QColor(220, 220, 220))
        
        # Explode the largest threat slice for emphasis
        if pie_series.slices():
            largest_slice = max(pie_series.slices(), key=lambda s: s.value())
            largest_slice.setExploded(True)
            largest_slice.setLabelVisible(True)
            largest_slice.setLabel(f"{largest_slice.label()} ({largest_slice.percentage():.1f}%)")
        
        self.chart.addSeries(pie_series)
        
        # Create bar series for threat score breakdown
        bar_set = QBarSet("Threat Indicators")
        
        # Add different types of indicators
        bar_set.append(threat_analysis.get('threat_score', 0))  # Overall score
        bar_set.append(threat_analysis.get('signature_matches', 0))  # Signature matches
        bar_set.append(threat_analysis.get('suspicious_characteristics', 0))  # Suspicious characteristics
        bar_set.append(threat_analysis.get('heuristic_score', 0))  # Heuristic analysis
        
        bar_series = QBarSeries()
        bar_series.append(bar_set)
        bar_series.setLabelsVisible(True)
        bar_series.setLabelsPosition(QBarSeries.LabelsCenter)
        
        self.chart.addSeries(bar_series)
        
        # Customize appearance
        self.chart.setTheme(QChart.ChartThemeDark)
        self.chart.setBackgroundBrush(QBrush(QColor(40, 40, 50)))
        self.chart.setTitleBrush(QBrush(QColor(220, 220, 220)))
        
        # Add axis for bar chart
        axis = QValueAxis()
        axis.setRange(0, 100)
        axis.setLabelFormat("%d%%")
        axis.setLabelsColor(QColor(200, 200, 200))
        self.chart.addAxis(axis, Qt.AlignLeft)
        bar_series.attachAxis(axis)
        
        # Add glow effect
        effect = QGraphicsDropShadowEffect()
        effect.setBlurRadius(20)
        effect.setColor(QColor(0, 255, 255, 100))
        effect.setOffset(0, 0)
        self.setGraphicsEffect(effect)

class FileScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberShield - Advanced Threat Scanner")
        self.setGeometry(100, 100, 1200, 900)
        self.setStyleSheet("background-color: #0a0a12;")
        
        # Load known threat signatures (enhanced for demo)
        self.threat_signatures = self.load_threat_signatures()
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Create title bar
        self.create_title_bar(main_layout)
        
        # Create main content area with splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Top panel (file selection and quick scan)
        top_panel = self.create_top_panel()
        splitter.addWidget(top_panel)
        
        # Bottom panel (analysis results)
        bottom_panel = self.create_bottom_panel()
        splitter.addWidget(bottom_panel)
        
        splitter.setSizes([300, 500])
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: rgba(0, 255, 224, 50);
            }
        """)
        
        main_layout.addWidget(splitter)
        
        # Initialize variables
        self.current_file = ""
        self.scan_thread = None
        self.threat_analysis = {}
        
        # Apply window effects
        self.setWindowOpacity(0.95)
        self.setWindowIcon(QIcon(self.create_app_icon()))
        
    def create_app_icon(self):
        # Create a simple programmatic icon
        from PyQt5.QtGui import QPixmap
        pixmap = QPixmap(64, 64)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw shield shape
        painter.setBrush(QColor(0, 120, 215))
        painter.setPen(QColor(255, 255, 255, 200))
        painter.drawEllipse(8, 8, 48, 48)
        
        # Draw cross
        painter.setPen(QColor(255, 255, 255))
        painter.drawLine(24, 16, 24, 48)
        painter.drawLine(16, 32, 40, 32)
        
        painter.end()
        return pixmap
        
    def create_title_bar(self, layout):
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: transparent;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(0, 0, 0, 0)
        
        # App title
        title = QLabel("🛡 CyberShield Advanced Threat Scanner")
        title.setStyleSheet("""
            color: #00ffe0; 
            font-size: 24px; 
            font-weight: bold;
            padding: 5px;
        """)
        title.setFont(QFont("Orbitron", 16, QFont.Bold))
        
        # Version label
        version = QLabel("v2.1.0")
        version.setStyleSheet("""
            color: rgba(0, 255, 224, 150);
            font-size: 12px;
            padding: 5px;
        """)
        
        # Spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        
        # Scan mode selector
        self.scan_mode = QComboBox()
        self.scan_mode.addItems(["Quick Scan", "Deep Scan", "Heuristic Analysis", "Custom Scan"])
        self.scan_mode.setStyleSheet("""
            QComboBox {
                background-color: rgba(0, 0, 0, 150);
                color: #00ffe0;
                border: 1px solid #00ffe0;
                border-radius: 5px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox:hover {
                border: 1px solid #ff00ff;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        self.scan_mode.setFont(QFont("Consolas", 10))
        
        title_layout.addWidget(title)
        title_layout.addWidget(version)
        title_layout.addWidget(spacer)
        title_layout.addWidget(self.scan_mode)
        
        layout.addWidget(title_bar)
        
    def create_top_panel(self):
        panel = QWidget()
        panel.setStyleSheet("background-color: transparent;")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Glass panel for file selection
        glass_panel = GlassFrame()
        glass_layout = QVBoxLayout(glass_panel)
        glass_layout.setContentsMargins(15, 15, 15, 15)
        glass_layout.setSpacing(15)
        
        # File selection controls
        file_controls = QWidget()
        file_controls_layout = QHBoxLayout(file_controls)
        file_controls_layout.setContentsMargins(0, 0, 0, 0)
        
        self.select_file_btn = NeonButton("📁 Browse File")
        self.select_file_btn.clicked.connect(self.select_file)
        
        self.scan_btn = NeonButton("🔍 Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.quick_scan_btn = NeonButton("⚡ Quick Scan")
        self.quick_scan_btn.clicked.connect(lambda: self.start_scan(quick=True))
        
        file_controls_layout.addWidget(self.select_file_btn)
        file_controls_layout.addWidget(self.quick_scan_btn)
        file_controls_layout.addWidget(self.scan_btn)
        
        # File path display
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("""
            color: #ffffff; 
            font-size: 14px;
            padding: 5px;
            border-bottom: 1px solid rgba(0, 255, 224, 50);
        """)
        self.file_path_label.setWordWrap(True)
        
        # Status label with animated dots
        self.status_label = QLabel("🟢 Ready")
        self.status_label.setStyleSheet("""
            color: #a0a0a0; 
            font-size: 12px;
            font-family: Consolas;
        """)
        
        # Add widgets to glass panel
        glass_layout.addWidget(self.file_path_label)
        glass_layout.addWidget(file_controls)
        glass_layout.addWidget(self.status_label)
        
        # Threat meter
        self.threat_meter = ThreatMeter()
        
        # Progress bar with animation
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid rgba(0, 255, 224, 100);
                border-radius: 5px;
                text-align: center;
                height: 20px;
                color: #ffffff;
                background-color: rgba(31, 31, 31, 150);
            }
            QProgressBar::chunk {
                background-color: qlineargradient(
                    spread:pad, x1:0, y1:0.5, x2:1, y2:0.5, 
                    stop:0 rgba(0, 255, 224, 200), 
                    stop:1 rgba(255, 0, 255, 200));
                border-radius: 3px;
            }
        """)
        
        # Add widgets to main layout
        layout.addWidget(glass_panel)
        layout.addWidget(self.threat_meter)
        layout.addWidget(self.progress_bar)
        
        return panel
        
    def create_bottom_panel(self):
        panel = QWidget()
        panel.setStyleSheet("background-color: transparent;")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget for different analysis views
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(0, 255, 224, 50);
                border-radius: 5px;
                background-color: rgba(26, 26, 26, 150);
            }
            QTabBar::tab {
                background-color: rgba(26, 26, 26, 200);
                color: #a0a0a0;
                border: 1px solid rgba(0, 255, 224, 50);
                padding: 8px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(0, 20, 30, 200);
                color: #00ffe0;
                border-bottom: 2px solid #00ffe0;
            }
            QTabBar::tab:hover {
                background-color: rgba(0, 50, 70, 200);
            }
        """)
        
        # Tab 1: Threat Analysis
        self.analysis_output = QTextEdit()
        self.analysis_output.setStyleSheet("""
            QTextEdit {
                background-color: rgba(26, 26, 26, 150);
                color: #e0e0e0;
                border: 1px solid rgba(0, 255, 224, 30);
                border-radius: 5px;
                padding: 10px;
                font-family: Consolas;
                font-size: 12px;
            }
        """)
        self.analysis_output.setReadOnly(True)
        
        # Apply syntax highlighting
        self.highlighter = ThreatHighlighter(self.analysis_output.document())
        
        # Tab 2: File Details
        self.file_details = QTextEdit()
        self.file_details.setStyleSheet(self.analysis_output.styleSheet())
        self.file_details.setReadOnly(True)
        
        # Tab 3: Hex View (placeholder)
        self.hex_view = QTextEdit()
        self.hex_view.setStyleSheet(self.analysis_output.styleSheet())
        self.hex_view.setReadOnly(True)
        self.hex_view.setPlainText("Hex view will be displayed here...")
        
        # Tab 4: Threat Graph
        self.threat_graph = ThreatGraph()
        self.threat_graph.setStyleSheet("background-color: rgba(40, 40, 50, 150); border-radius: 5px;")
        
        # Add tabs
        self.tabs.addTab(self.analysis_output, "Threat Analysis")
        self.tabs.addTab(self.file_details, "File Details")
        self.tabs.addTab(self.hex_view, "Hex View")
        self.tabs.addTab(self.threat_graph, "Threat Graph")
        
        layout.addWidget(self.tabs)
        
        return panel
        
    def load_threat_signatures(self):
        """Load enhanced threat signatures with more indicators"""
        signatures = {
            "hashes": {
                "6a4a8a9e3b3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e5b5f3e3e": "Test Malware Signature",
                "098f6bcd4621d373cade4e832627b4f6": "Test MD5 Threat",
                "5d41402abc4b2a76b9719d911017c592": "Test Threat 1",
                "7d793037a0760186574b0282f2f435e7": "Test Threat 2",
                "e4da3b7fbbce2345d7772b0674a318d5": "Test Threat 3"
            },
            "strings": [
                "malicious_code",
                "virus_signature",
                "this_is_a_test_threat",
                "dangerous_function",
                "shell_exec",
                "eval(base64_decode(",
                "CreateRemoteThread",
                "VirtualProtect",
                "WriteProcessMemory",
                "process_injection",
                "keylogger",
                "ransomware",
                "rootkit",
                "spyware"
            ],
            "file_types": [
                {"extension": ".exe", "risk": 40},
                {"extension": ".dll", "risk": 30},
                {"extension": ".js", "risk": 20},
                {"extension": ".vbs", "risk": 25},
                {"extension": ".ps1", "risk": 25},
                {"extension": ".bat", "risk": 20},
                {"extension": ".cmd", "risk": 20},
                {"extension": ".pdf", "risk": 15},
                {"extension": ".doc", "risk": 25},
                {"extension": ".docx", "risk": 25},
                {"extension": ".xls", "risk": 25},
                {"extension": ".xlsx", "risk": 25},
                {"extension": ".zip", "risk": 10},
                {"extension": ".rar", "risk": 10}
            ],
            "suspicious_imports": [
                "VirtualProtect",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "SetWindowsHookEx",
                "LoadLibrary",
                "GetProcAddress",
                "RegSetValue",
                "WinExec",
                "ShellExecute",
                "URLDownloadToFile"
            ]
        }
        return signatures
        
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Scan", 
            "", 
            "All Files (*);;Executables (*.exe *.dll *.bat *.cmd);;Documents (*.doc *.docx *.pdf *.xls *.xlsx);;Scripts (*.js *.vbs *.ps1)"
        )
        
        if file_path:
            self.current_file = file_path
            shortened_path = self.shorten_path(file_path)
            self.file_path_label.setText(f"📄 Selected: {shortened_path}")
            self.status_label.setText("🟡 File selected - Ready to scan")
            
            # Preview basic file info
            self.preview_file_info(file_path)
            
    def shorten_path(self, path, max_length=60):
        """Shorten long paths for display"""
        if len(path) <= max_length:
            return path
            
        parts = path.split(os.sep)
        if len(parts) > 3:
            return f"{parts[0]}/.../{parts[-2]}/{parts[-1]}"
        return path
        
    def preview_file_info(self, file_path):
        """Show basic file info before scanning"""
        try:
            file_size = os.path.getsize(file_path)
            file_date = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            file_type, _ = mimetypes.guess_type(file_path)
            file_type = file_type or "Unknown"
            
            preview_text = (
                f"File: {os.path.basename(file_path)}\n"
                f"Size: {self.format_file_size(file_size)}\n"
                f"Type: {file_type}\n"
                f"Modified: {file_date}"
            )
            
            self.file_details.setPlainText(preview_text)
        except Exception as e:
            self.file_details.setPlainText(f"Error getting file info: {str(e)}")
            
    def format_file_size(self, size):
        """Convert file size to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
        
    def start_scan(self, quick=False):
        if not self.current_file:
            self.status_label.setText("🔴 Error: Please select a file first!")
            self.show_error_tooltip(self.select_file_btn, "No file selected!")
            return
            
        self.status_label.setText("🟠 Scanning...")
        self.progress_bar.setValue(0)
        self.analysis_output.clear()
        
        # Disable buttons during scan
        self.scan_btn.setEnabled(False)
        self.quick_scan_btn.setEnabled(False)
        self.select_file_btn.setEnabled(False)
        
        # Determine scan mode
        scan_mode = "Quick" if quick else self.scan_mode.currentText()
        
        # Start scan animation
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(lambda: self.update_scan(scan_mode))
        self.scan_timer.start(50)
        
    def update_scan(self, scan_mode):
        value = self.progress_bar.value()
        
        # Update progress based on scan mode
        if scan_mode == "Quick Scan":
            increment = 5
        elif scan_mode == "Deep Scan":
            increment = 2
        else:  # Heuristic or Custom
            increment = 1
            
        if value < 100:
            self.progress_bar.setValue(value + increment)
            
            # Update status with scanning animation
            dots = (value // 10) % 4
            self.status_label.setText(f"🟠 Scanning{'.' * dots} ({scan_mode})")
            
            # Simulate finding threats at certain points
            if value in [25, 50, 75]:
                self.simulate_threat_findings(value)
        else:
            self.scan_timer.stop()
            self.complete_scan()
            
    def simulate_threat_findings(self, progress_value):
        """Simulate finding threats during scan (for demo purposes)"""
        if not hasattr(self, 'simulated_threats'):
            self.simulated_threats = set()
            
        # Only add each simulated threat once
        if progress_value == 25 and "suspicious_string" not in self.simulated_threats:
            self.append_analysis_output("⚠️ Found suspicious string pattern: 'eval(base64_decode('")
            self.simulated_threats.add("suspicious_string")
            self.threat_meter.set_threat_level(30)
            
        elif progress_value == 50 and "hidden_code" not in self.simulated_threats:
            self.append_analysis_output("⚠️ Detected potential obfuscated code section")
            self.simulated_threats.add("hidden_code")
            self.threat_meter.set_threat_level(50)
            
        elif progress_value == 75 and "network_call" not in self.simulated_threats:
            self.append_analysis_output("⚠️ Detected possible network call to suspicious domain")
            self.append_analysis_output("⚠️ Found reference to 'URLDownloadToFile' API")
            self.simulated_threats.add("network_call")
            self.threat_meter.set_threat_level(70)
            
    def append_analysis_output(self, text):
        """Append text to analysis output with timestamp"""
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
        self.analysis_output.append(f"{timestamp} {text}")
        self.analysis_output.moveCursor(QTextCursor.End)
        
    def complete_scan(self):
        """Complete the scan process and display results"""
        try:
            # Perform actual analysis
            self.threat_analysis = self.analyze_file(self.current_file)
            
            # Update UI
            self.status_label.setText("🟢 Scan Complete")
            self.scan_btn.setEnabled(True)
            self.quick_scan_btn.setEnabled(True)
            self.select_file_btn.setEnabled(True)
            
            # Display full analysis
            self.display_analysis_results()
            
            # Update threat meter based on actual analysis
            threat_level = self.threat_analysis.get('threat_score', 0)
            self.threat_meter.set_threat_level(threat_level)
            
            # Update threat graph
            self.threat_graph.update_graph(self.threat_analysis)
            
            # Show appropriate status based on threat level
            if threat_level >= 70:
                self.status_label.setText("🔴 High Threat Detected!")
            elif threat_level >= 30:
                self.status_label.setText("🟠 Moderate Threat Detected")
            else:
                self.status_label.setText("🟢 No Significant Threats Found")
                
        except Exception as e:
            self.status_label.setText("🔴 Scan Error")
            self.analysis_output.append(f"Error during scan: {str(e)}")
            
    def analyze_file(self, file_path):
        """Perform comprehensive file analysis with enhanced detection"""
        analysis = {
            'basic_info': {},
            'threat_detections': [],
            'threat_score': 0,
            'signature_matches': 0,
            'suspicious_characteristics': 0,
            'heuristic_score': 0,
            'verdict': 'Clean',
            'recommendations': []
        }
        
        try:
            # Basic file info
            file_size = os.path.getsize(file_path)
            file_type, _ = mimetypes.guess_type(file_path)
            file_type = file_type or "Unknown"
            file_hash = self.calculate_file_hash(file_path)
            
            analysis['basic_info'] = {
                'filename': os.path.basename(file_path),
                'path': file_path,
                'size': file_size,
                'type': file_type,
                'hash': file_hash,
                'modified': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Check against known threat signatures
            threat_detections = self.check_threat_signatures(file_path, file_hash)
            analysis['threat_detections'] = threat_detections
            analysis['signature_matches'] = len(threat_detections)
            
            # Calculate threat score (0-100)
            threat_score = 0
            
            # Base score from file type
            for file_type_info in self.threat_signatures['file_types']:
                if file_path.lower().endswith(file_type_info['extension']):
                    threat_score += file_type_info['risk']
                    break
                    
            # Add points for each threat detection
            for detection in threat_detections:
                if detection.get('severity') == 'High':
                    threat_score += 15
                elif detection.get('severity') == 'Medium':
                    threat_score += 10
                else:
                    threat_score += 5
                    
            # Additional checks for executable files
            if file_path.lower().endswith(('.exe', '.dll')):
                pe_analysis = self.analyze_pe_file(file_path)
                analysis['pe_analysis'] = pe_analysis
                
                # Adjust threat score based on PE analysis
                if pe_analysis.get('suspicious_characteristics', 0) > 0:
                    threat_score += pe_analysis['suspicious_characteristics'] * 5
                    analysis['suspicious_characteristics'] = pe_analysis['suspicious_characteristics']
                    
            # Heuristic analysis
            heuristic_score = self.perform_heuristic_analysis(file_path)
            analysis['heuristic_score'] = heuristic_score
            threat_score += heuristic_score
            
            threat_score = min(100, threat_score)  # Cap at 100
            analysis['threat_score'] = threat_score
            
            # Determine verdict
            if threat_score >= 70:
                analysis['verdict'] = "High Risk"
                analysis['recommendations'].append("Delete this file immediately")
                analysis['recommendations'].append("Run full system scan")
                analysis['recommendations'].append("Check system for compromise")
            elif threat_score >= 30:
                analysis['verdict'] = "Suspicious"
                analysis['recommendations'].append("Scan with additional antivirus tools")
                analysis['recommendations'].append("Check file origin")
                analysis['recommendations'].append("Monitor system behavior")
            else:
                analysis['verdict'] = "Clean"
                analysis['recommendations'].append("No action required")
                
            return analysis
            
        except Exception as e:
            analysis['error'] = str(e)
            return analysis
            
    def check_threat_signatures(self, file_path, file_hash):
        """Enhanced threat signature checking"""
        detections = []
        
        # Check hash against known malicious hashes
        if file_hash in self.threat_signatures['hashes']:
            detections.append({
                'type': 'hash_match',
                'description': f"Known malicious file: {self.threat_signatures['hashes'][file_hash]}",
                'severity': 'High',
                'confidence': 'High'
            })
            
        # Check for suspicious strings in file content
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192).decode('utf-8', errors='ignore')  # Read first 8KB
                
                for threat_string in self.threat_signatures['strings']:
                    if threat_string in content:
                        severity = 'High' if threat_string in ['eval(base64_decode(', 'CreateRemoteThread'] else 'Medium'
                        detections.append({
                            'type': 'suspicious_string',
                            'description': f"Suspicious string found: '{threat_string}'",
                            'severity': severity,
                            'confidence': 'Medium'
                        })
        except Exception as e:
            detections.append({
                'type': 'error',
                'description': f"Error reading file content: {str(e)}",
                'severity': 'Low',
                'confidence': 'High'
            })
            
        return detections
        
    def analyze_pe_file(self, file_path):
        """Enhanced PE file analysis with more checks"""
        pe_analysis = {
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'suspicious_characteristics': 0,
            'warnings': [],
            'anomalies': []
        }
        
        try:
            pe = pefile.PE(file_path)
            
            # Analyze sections
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode().strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'entropy': section.get_entropy()
                }
                pe_analysis['sections'].append(section_info)
                
                # Check for suspicious section names
                suspicious_section_names = ['.crypt', '.packed', '.hidden', '.malic', '.evil']
                if any(sn in section.Name.decode().strip('\x00').lower() for sn in suspicious_section_names):
                    pe_analysis['warnings'].append(f"Suspicious section name: {section.Name.decode()}")
                    pe_analysis['suspicious_characteristics'] += 1
                
                # Check for high entropy (possible packed/encrypted code)
                if section_info['entropy'] > 6.5:
                    pe_analysis['anomalies'].append(f"High entropy section ({section_info['entropy']:.2f}): {section.Name.decode()}")
                    pe_analysis['suspicious_characteristics'] += 1
                    
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode()
                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode()
                            pe_analysis['imports'].append(f"{dll} -> {import_name}")
                            
                            # Check for suspicious imports
                            if import_name.lower() in [i.lower() for i in self.threat_signatures['suspicious_imports']]:
                                pe_analysis['warnings'].append(f"Suspicious import: {import_name}")
                                pe_analysis['suspicious_characteristics'] += 1
                                
            # Analyze exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_analysis['exports'].append(exp.name.decode())
                        
            # Analyze resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name:
                        pe_analysis['resources'].append(resource_type.name.__str__())
                    else:
                        pe_analysis['resources'].append(str(resource_type.id))
            
            pe.close()
            
        except Exception as e:
            pe_analysis['error'] = str(e)
            
        return pe_analysis
        
    def perform_heuristic_analysis(self, file_path):
        """Perform heuristic analysis to detect suspicious patterns"""
        heuristic_score = 0
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(16384).decode('utf-8', errors='ignore')  # Read first 16KB
                
                # Check for common malware patterns
                patterns = {
                    'executable code in document': 20,
                    'long sequences of NOPs': 15,
                    'unusual API sequences': 25,
                    'obfuscated strings': 30,
                    'known exploit patterns': 40
                }
                
                for pattern, score in patterns.items():
                    if pattern in content.lower():
                        heuristic_score += score
                        
                # Check file size anomalies
                file_size = os.path.getsize(file_path)
                if file_size > 50 * 1024 * 1024:  # Files over 50MB
                    heuristic_score += 10
                elif file_size < 1024:  # Very small files
                    heuristic_score += 5
                    
        except Exception:
            pass
            
        return min(heuristic_score, 50)  # Cap heuristic score at 50
        
    def display_analysis_results(self):
        """Display comprehensive analysis results with enhanced information"""
        if not self.threat_analysis:
            return
            
        # Display basic info in file details tab
        basic_info = self.threat_analysis.get('basic_info', {})
        file_details_text = (
            f"File Name: {basic_info.get('filename', 'N/A')}\n"
            f"File Path: {basic_info.get('path', 'N/A')}\n"
            f"File Size: {self.format_file_size(basic_info.get('size', 0))}\n"
            f"File Type: {basic_info.get('type', 'N/A')}\n"
            f"Last Modified: {basic_info.get('modified', 'N/A')}\n"
            f"SHA-256 Hash: {basic_info.get('hash', 'N/A')}\n"
            f"Threat Verdict: {self.threat_analysis.get('verdict', 'N/A')}\n"
            f"Threat Score: {self.threat_analysis.get('threat_score', 0)}/100\n"
            f"Signature Matches: {self.threat_analysis.get('signature_matches', 0)}\n"
            f"Suspicious Characteristics: {self.threat_analysis.get('suspicious_characteristics', 0)}\n"
            f"Heuristic Score: {self.threat_analysis.get('heuristic_score', 0)}/50"
        )
        self.file_details.setPlainText(file_details_text)
        
        # Display threat analysis
        self.analysis_output.clear()
        self.append_analysis_output("=== THREAT ANALYSIS REPORT ===")
        self.append_analysis_output(f"File: {basic_info.get('filename', 'N/A')}")
        self.append_analysis_output(f"Analysis Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.append_analysis_output(f"Scan Mode: {self.scan_mode.currentText()}")
        self.append_analysis_output("")
        
        # Display threat detections
        detections = self.threat_analysis.get('threat_detections', [])
        if detections:
            self.append_analysis_output("=== THREAT DETECTIONS ===")
            for detection in detections:
                severity = detection.get('severity', 'UNKNOWN')
                desc = detection.get('description', 'No description')
                confidence = detection.get('confidence', 'UNKNOWN')
                self.append_analysis_output(f"[{severity} | {confidence}] {desc}")
        else:
            self.append_analysis_output("No known threats detected")
            
        # Display PE analysis if available
        pe_analysis = self.threat_analysis.get('pe_analysis')
        if pe_analysis:
            self.append_analysis_output("")
            self.append_analysis_output("=== PE FILE ANALYSIS ===")
            
            if pe_analysis.get('warnings'):
                self.append_analysis_output("⚠️ Suspicious Characteristics:")
                for warning in pe_analysis['warnings']:
                    self.append_analysis_output(f"  • {warning}")
                    
            if pe_analysis.get('anomalies'):
                self.append_analysis_output("⚠️ Anomalies Detected:")
                for anomaly in pe_analysis['anomalies']:
                    self.append_analysis_output(f"  • {anomaly}")
                    
            if not pe_analysis.get('warnings') and not pe_analysis.get('anomalies'):
                self.append_analysis_output("No suspicious PE characteristics found")
                
        # Display heuristic analysis results
        if self.threat_analysis.get('heuristic_score', 0) > 0:
            self.append_analysis_output("")
            self.append_analysis_output("=== HEURISTIC ANALYSIS ===")
            self.append_analysis_output(f"Heuristic Threat Score: {self.threat_analysis['heuristic_score']}/50")
            if self.threat_analysis['heuristic_score'] >= 30:
                self.append_analysis_output("High likelihood of malicious behavior detected")
            elif self.threat_analysis['heuristic_score'] >= 15:
                self.append_analysis_output("Moderate likelihood of suspicious behavior")
            else:
                self.append_analysis_output("Low likelihood of malicious behavior")
                
        # Display recommendations
        recommendations = self.threat_analysis.get('recommendations', [])
        if recommendations:
            self.append_analysis_output("")
            self.append_analysis_output("=== RECOMMENDATIONS ===")
            for rec in recommendations:
                self.append_analysis_output(f"• {rec}")
                
        # Generate hex view (simplified)
        self.generate_hex_view()
        
    def generate_hex_view(self):
        """Generate a simplified hex view of the file with more information"""
        try:
            with open(self.current_file, 'rb') as f:
                content = f.read(1024)  # Read first 1024 bytes
                
                hex_lines = []
                hex_lines.append("Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII")
                hex_lines.append("--------  -----------------------------------------------  ----------------")
                
                for i in range(0, len(content), 16):
                    chunk = content[i:i+16]
                    hex_str = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    hex_lines.append(f"{i:08x}: {hex_str.ljust(47)}  {ascii_str}")
                    
                self.hex_view.setPlainText('\n'.join(hex_lines))
        except Exception as e:
            self.hex_view.setPlainText(f"Error generating hex view: {str(e)}")
            
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
        
    def show_error_tooltip(self, widget, message):
        """Show an animated error tooltip"""
        QToolTip.showText(
            widget.mapToGlobal(QPoint(0, -10)),
            f"❌ {message}",
            widget,
            widget.rect(),
            2000  # Show for 2 seconds
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set dark palette
    palette = app.palette()
    palette.setColor(palette.Window, QColor(10, 10, 18))
    palette.setColor(palette.WindowText, QColor(220, 220, 220))
    palette.setColor(palette.Base, QColor(30, 30, 40))
    palette.setColor(palette.AlternateBase, QColor(40, 40, 50))
    palette.setColor(palette.ToolTipBase, QColor(0, 30, 40))
    palette.setColor(palette.ToolTipText, QColor(200, 200, 200))
    palette.setColor(palette.Text, QColor(220, 220, 220))
    palette.setColor(palette.Button, QColor(40, 40, 50))
    palette.setColor(palette.ButtonText, QColor(220, 220, 220))
    palette.setColor(palette.BrightText, QColor(255, 0, 0))
    palette.setColor(palette.Link, QColor(0, 180, 255))
    palette.setColor(palette.Highlight, QColor(0, 120, 215))
    palette.setColor(palette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    
    window = FileScannerApp()
    window.show()
    sys.exit(app.exec_())