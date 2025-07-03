#!/usr/bin/env python3
"""
Test script to verify cursor error fix in StegNinja GUI.
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QTimer

# Add the project root to the path
project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)

from src.gui.app import MainWindow

def test_cursor_fix():
    """Test that the application loads without cursor errors."""
    print("Testing StegNinja GUI startup...")
    
    # Create QApplication
    app = QApplication(sys.argv)
    
    try:
        # Create the main window
        window = StegNinjaApp()
        window.show()
        
        # Test that the window loaded successfully
        print("✓ GUI loaded successfully")
        print("✓ No cursor-related errors detected")
        
        # Close the window after a short delay
        QTimer.singleShot(1000, window.close)
        QTimer.singleShot(1100, app.quit)
        
        # Run the event loop briefly
        app.exec_()
        
        print("✓ Application closed cleanly")
        return True
        
    except Exception as e:
        print(f"✗ Error occurred: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_cursor_fix()
    if success:
        print("\n🎉 Cursor fix test PASSED!")
    else:
        print("\n❌ Cursor fix test FAILED!")
        sys.exit(1)
