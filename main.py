#!/usr/bin/env python3
"""
StegNinja - Advanced Steganography Toolkit
Professional steganography tool for security research and red team operations

Author: Denish Maharjan
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

def main():
    """Main application entry point"""
    try:
        from PyQt5.QtWidgets import QApplication
        from src.gui.app import MainWindow # type: ignore
        
        # Create and run application
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        return app.exec_()
        
    except ImportError as e:
        print(f"Import Error: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Application Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
