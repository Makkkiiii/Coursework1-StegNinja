"""
Test to verify the quality display widget sizing and multi-line support
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QFormLayout
from PyQt5.QtCore import Qt

def test_quality_display():
    """Test the quality display widget"""
    
    app = QApplication([])
    
    # Create a test widget
    widget = QWidget()
    layout = QVBoxLayout()
    
    # Create a label similar to info_quality
    quality_label = QLabel("")
    quality_label.setWordWrap(True)
    quality_label.setMinimumHeight(80)
    quality_label.setAlignment(Qt.AlignTop)
    
    # Test with our multi-line quality description
    test_quality = """🟡 VERY GOOD - Barely noticeable
Hidden data causes minimal visual changes

Technical Metrics: MSE: 1.23 | PSNR: 42.56 dB | SSIM: 0.987"""
    
    quality_label.setText(test_quality)
    quality_label.setStyleSheet("color: #28a745; font-weight: bold; padding: 5px; border-radius: 3px; border: 1px solid #ccc;")
    
    form_layout = QFormLayout()
    form_layout.addRow("Steganography Quality:", quality_label)
    
    layout.addLayout(form_layout)
    widget.setLayout(layout)
    
    # Show the widget
    widget.setWindowTitle("Quality Display Test")
    widget.resize(400, 200)
    widget.show()
    
    print("🎯 Quality Display Test")
    print("=" * 30)
    print("Widget created and displayed.")
    print("Check the window to see if multi-line quality display is working.")
    print("Expected: 4 lines of text with proper formatting")
    print("- Quality level with emoji")
    print("- Description line") 
    print("- Empty line")
    print("- Technical metrics line")
    
    # Don't start the event loop, just show the setup worked
    app.processEvents()
    
    print("✅ Test widget created successfully!")
    print("The quality label should now properly display multi-line content.")
    
    return True

if __name__ == "__main__":
    test_quality_display()
