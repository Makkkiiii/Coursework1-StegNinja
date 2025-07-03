#!/usr/bin/env python3
"""
Test file for colorful UI design - StegNinja
This is a preview of enhanced aesthetic design with colorful theme
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QSplitter, QTextEdit, QLabel, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QStatusBar, QGroupBox, QFormLayout,
    QLineEdit, QCheckBox, QComboBox, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QPixmap, QFont, QIcon

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from src.core.image_stego import ImageSteganography
from src.core.text_stego import TextSteganography
from src.utils.crypto import CryptoManager


class TestColorfulWindow(QMainWindow):
    """Test window with colorful design."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the test UI."""
        self.setWindowTitle("StegNinja - Enhanced UI Test Preview")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout()
        
        # Enhanced title
        title_label = QLabel("StegNinja - Advanced Steganography Toolkit (Enhanced Test)")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter) # type: ignore
        title_label.setStyleSheet("""
            padding: 15px; 
            color: white;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #007bff, stop: 0.5 #0056b3, stop: 1 #007bff);
            border-radius: 8px;
            margin: 5px;
            border: 1px solid #0056b3;
        """)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Test tabs
        self.test_tab1 = self._create_test_tab("Text Steganography Test")
        self.tab_widget.addTab(self.test_tab1, "Text Steganography")
        
        self.test_tab2 = self._create_test_tab2("Image Steganography Test")
        self.tab_widget.addTab(self.test_tab2, "Image Steganography")
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.tab_widget)
        
        central_widget.setLayout(layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Enhanced UI Test Mode - Ready!")
        
        # Apply the colorful styles
        self.apply_colorful_styles()
    
    def _create_test_tab(self, title: str) -> QWidget:
        """Create a test tab with sample controls."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Sample group box
        test_group = QGroupBox("Sample Controls")
        test_layout = QFormLayout()
        
        # Sample text edit
        test_text = QTextEdit()
        test_text.setPlaceholderText("Enter some test text here...")
        test_text.setMaximumHeight(100)
        
        # Sample line edit
        test_input = QLineEdit()
        test_input.setPlaceholderText("Test input field...")
        
        # Sample combo box
        test_combo = QComboBox()
        test_combo.addItems(["Option 1", "Option 2", "Option 3"])
        
        # Sample checkbox
        test_checkbox = QCheckBox("Enable test feature")
        
        test_layout.addRow("Text Area:", test_text)
        test_layout.addRow("Input Field:", test_input)
        test_layout.addRow("Dropdown:", test_combo)
        test_layout.addRow("Checkbox:", test_checkbox)
        test_group.setLayout(test_layout)
        
        # Sample buttons
        button_layout = QHBoxLayout()
        
        primary_btn = QPushButton("Primary Action")
        primary_btn.clicked.connect(lambda: self.test_action("Primary"))
        
        secondary_btn = QPushButton("Secondary Action")
        secondary_btn.setProperty("class", "secondary")
        secondary_btn.clicked.connect(lambda: self.test_action("Secondary"))
        
        button_layout.addWidget(primary_btn)
        button_layout.addWidget(secondary_btn)
        
        # Results area
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(150)
        self.results_text.append('<span style="color: #28a745; font-weight: bold;">✓ Enhanced UI test initialized!</span>')
        self.results_text.append('<span style="color: #dc3545; font-weight: bold;">🔍 EXTRACTED MESSAGE: This is a test red message!</span>')
        self.results_text.append('<span style="color: #007bff; font-weight: bold;">📋 Test status message</span>')
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        
        # Progress bar
        progress = QProgressBar()
        progress.setValue(75)
        
        layout.addWidget(test_group)
        layout.addLayout(button_layout)
        layout.addWidget(results_group)
        layout.addWidget(progress)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _create_test_tab2(self, title: str) -> QWidget:
        """Create another test tab."""
        widget = QWidget()
        layout = QHBoxLayout()
        
        # Left panel
        left_group = QGroupBox("Left Panel Test")
        left_layout = QVBoxLayout()
        
        test_text2 = QTextEdit()
        test_text2.setPlaceholderText("Another test area...")
        test_text2.setMaximumHeight(200)
        
        test_btn = QPushButton("Test Button")
        test_btn.clicked.connect(lambda: self.test_action("Test"))
        
        left_layout.addWidget(test_text2)
        left_layout.addWidget(test_btn)
        left_group.setLayout(left_layout)
        
        # Right panel
        right_group = QGroupBox("Right Panel Test")
        right_layout = QVBoxLayout()
        
        info_layout = QFormLayout()
        info_layout.addRow("Status:", QLabel("Active"))
        info_layout.addRow("Mode:", QLabel("Test"))
        info_layout.addRow("Theme:", QLabel("Colorful"))
        
        right_layout.addLayout(info_layout)
        right_group.setLayout(right_layout)
        
        layout.addWidget(left_group)
        layout.addWidget(right_group)
        
        widget.setLayout(layout)
        return widget
    
    def test_action(self, action_type: str):
        """Test action handler."""
        self.results_text.append(f'<span style="color: #ffaa3e; font-weight: bold;">🎯 {action_type} button clicked!</span>')
        self.status_bar.showMessage(f"Last action: {action_type} at {QTimer().remainingTime()}")
    
    def apply_colorful_styles(self):
        """Apply subtle enhancements to the clean design."""
        style = """
        QMainWindow {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 #f8f9fa, stop: 1 #e9ecef);
        }
        
        QTabWidget::pane {
            border: 2px solid #007bff;
            border-radius: 8px;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 #ffffff, stop: 1 #f8f9fa);
        }
        
        QTabWidget::tab-bar {
            alignment: center;
        }
        
        QTabBar::tab {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #e9ecef, stop: 1 #dee2e6);
            border: 2px solid #007bff;
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            padding: 12px 20px;
            margin-right: 3px;
            color: #495057;
            font-weight: bold;
            font-size: 11px;
        }
        
        QTabBar::tab:selected {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #007bff, stop: 1 #0056b3);
            border-bottom: 2px solid #007bff;
            color: white;
        }
        
        QTabBar::tab:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #f8f9fa, stop: 1 #e9ecef);
            border-color: #0056b3;
        }
        
        QGroupBox {
            font-weight: bold;
            border: 2px solid #007bff;
            border-radius: 8px;
            margin: 8px 2px;
            padding-top: 15px;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 rgba(255, 255, 255, 250), stop: 1 rgba(248, 249, 250, 250));
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 8px 0 8px;
            color: #007bff;
            font-size: 12px;
            font-weight: bold;
        }
        
        QPushButton {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #007bff, stop: 1 #0056b3);
            border: 2px solid #007bff;
            color: white;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 11px;
        }
        
        QPushButton:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #0056b3, stop: 1 #004085);
            border-color: #0056b3;
            transform: translateY(-1px);
        }
        
        QPushButton:pressed {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #004085, stop: 1 #002752);
            border-color: #004085;
        }
        
        QPushButton:disabled {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #6c757d, stop: 1 #5a6268);
            border-color: #6c757d;
            color: #adb5bd;
        }
        
        /* Secondary Buttons */
        QPushButton[class="secondary"] {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #6c757d, stop: 1 #5a6268);
            border: 2px solid #6c757d;
        }
        
        QPushButton[class="secondary"]:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, 
                stop: 0 #5a6268, stop: 1 #495057);
            border-color: #5a6268;
        }
        
        QTextEdit, QLineEdit {
            border: 2px solid #007bff;
            border-radius: 6px;
            padding: 10px;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 rgba(255, 255, 255, 250), stop: 1 rgba(248, 249, 250, 250));
            color: #495057;
            selection-background-color: #007bff;
            font-size: 11px;
        }
        
        QTextEdit:focus, QLineEdit:focus {
            border-color: #0056b3;
            background: white;
            box-shadow: 0 0 5px rgba(0, 123, 255, 0.3);
        }
        
        QComboBox {
            border: 2px solid #007bff;
            border-radius: 6px;
            padding: 8px 12px;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 rgba(255, 255, 255, 250), stop: 1 rgba(248, 249, 250, 250));
            color: #495057;
            font-size: 11px;
        }
        
        QComboBox:focus {
            border-color: #0056b3;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 25px;
        }
        
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 8px solid #007bff;
            margin-right: 8px;
        }
        
        QCheckBox {
            color: #495057;
            font-weight: bold;
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border: 2px solid #007bff;
            border-radius: 4px;
            background-color: white;
        }
        
        QCheckBox::indicator:checked {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 #007bff, stop: 1 #0056b3);
            border-color: #007bff;
        }
        
        QCheckBox::indicator:checked::after {
            content: "✓";
            color: white;
            font-weight: bold;
        }
        
        QProgressBar {
            border: 2px solid #007bff;
            border-radius: 6px;
            text-align: center;
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1, 
                stop: 0 rgba(255, 255, 255, 250), stop: 1 rgba(248, 249, 250, 250));
            color: #495057;
            font-weight: bold;
        }
        
        QProgressBar::chunk {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #007bff, stop: 1 #0056b3);
            border-radius: 4px;
        }
        
        QLabel {
            color: #495057;
        }
        
        QStatusBar {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #007bff, stop: 1 #0056b3);
            color: white;
            border-top: 2px solid #0056b3;
            font-weight: bold;
        }
        
        QSplitter::handle {
            background: #007bff;
            width: 3px;
            height: 3px;
        }
        
        QSplitter::handle:hover {
            background: #0056b3;
        }
        
        QScrollBar:vertical {
            background: rgba(233, 236, 239, 150);
            width: 12px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:vertical {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #007bff, stop: 1 #0056b3);
            border-radius: 6px;
            min-height: 20px;
        }
        
        QScrollBar::handle:vertical:hover {
            background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, 
                stop: 0 #0056b3, stop: 1 #004085);
        }
        """
        
        self.setStyleSheet(style)


def main():
    """Main function to run the colorful UI test."""
    app = QApplication(sys.argv)
    window = TestColorfulWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
