#!/usr/bin/env python3
"""
Debug script to check GUI file info display
"""

import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QLabel, QPushButton
from PyQt5.QtCore import Qt
from src.core.file_stego import FileSteganography

def debug_gui_display():
    """Debug GUI display issue"""
    
    app = QApplication(sys.argv)
    
    # Create test file
    test_file = "debug_test.txt"
    with open(test_file, "w") as f:
        f.write("This is a debug test file.")
    
    try:
        # Test backend
        file_stego = FileSteganography()
        info = file_stego.get_file_info(test_file)
        
        print("=== DEBUG INFO ===")
        print(f"Backend hash: {info.get('hash', 'NO HASH')}")
        print(f"Backend hash length: {len(info.get('hash', ''))}")
        
        # Create GUI widget
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Test display - exact same as GUI
        file_info_display = QTextEdit()
        file_info_display.setReadOnly(True)
        file_info_display.setMaximumHeight(200)
        file_info_display.setLineWrapMode(QTextEdit.NoWrap)
        file_info_display.setStyleSheet("font-family: monospace; font-size: 9pt;")
        
        # Same formatting as GUI
        info_text = f"""File Information:

Name: {info.get('name', 'Unknown')}
Format: {info.get('format', 'Unknown')}
Size: {info.get('size', 0):,} bytes
Supported: {'Yes' if info.get('is_supported', False) else 'No'}

Hash:
{info.get('hash', 'Unknown')}

Modified: {info.get('modification_time', 0)}
        """
        
        file_info_display.setPlainText(info_text)
        
        def print_debug():
            content = file_info_display.toPlainText()
            print("=== GUI CONTENT ===")
            print(repr(content))
            print("=== GUI CONTENT (DISPLAY) ===")
            print(content)
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'hash' in line.lower() or len(line) > 50:
                    print(f"Line {i}: '{line}' (length: {len(line)})")
        
        debug_btn = QPushButton("Print Debug Info")
        debug_btn.clicked.connect(print_debug)
        
        layout.addWidget(QLabel("Debug File Info Display:"))
        layout.addWidget(file_info_display)
        layout.addWidget(debug_btn)
        
        widget.setWindowTitle("Debug GUI Display")
        widget.resize(600, 400)
        widget.show()
        
        print("GUI opened - click Debug button to see content")
        
        app.exec_()
        
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    debug_gui_display()
