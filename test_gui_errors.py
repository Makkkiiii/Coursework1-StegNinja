#!/usr/bin/env python3
"""
Test script to verify GUI error messages via the worker thread functionality
"""

import os
import tempfile
import sys
from PIL import Image
import numpy as np

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

from src.gui.app import WorkerThread

def test_gui_error_messages():
    """Test that GUI worker thread properly propagates error messages"""
    print("=== Testing GUI Error Messages ===")
    
    # Create test image
    test_image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(test_image)
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_cover:
        img.save(tmp_cover.name)
        cover_path = tmp_cover.name
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_stego:
        stego_path = tmp_stego.name
    
    # Create worker thread for embedding
    embed_worker = WorkerThread("embed_image", 
                               cover_path=cover_path,
                               message="Secret message",
                               output_path=stego_path,
                               password="test123",
                               bits_per_channel=1)
    
    # Run embed operation
    embed_worker.run()
    
    # Test extraction with wrong password
    print("1. Testing extraction with wrong password...")
    extract_worker = WorkerThread("extract_image",
                                 image_path=stego_path,
                                 password="wrong_password")
    
    # Capture the signal emission
    messages = []
    def capture_finished(success, message):
        messages.append((success, message))
    
    extract_worker.finished.connect(capture_finished)
    extract_worker.run()
    
    if messages:
        success, message = messages[0]
        print(f"   Success: {success}")
        print(f"   Message: {message}")
        if "Invalid password" in message:
            print("   ✅ Correct password error message")
        else:
            print("   ❌ Wrong password error message")
    
    # Test extraction without password
    print("2. Testing extraction without password...")
    messages.clear()
    extract_worker2 = WorkerThread("extract_image",
                                  image_path=stego_path)
    
    extract_worker2.finished.connect(capture_finished)
    extract_worker2.run()
    
    if messages:
        success, message = messages[0]
        print(f"   Success: {success}")
        print(f"   Message: {message}")
        if "encrypted but no password provided" in message:
            print("   ✅ Correct missing password error message")
        else:
            print("   ❌ Wrong missing password error message")
    
    # Test text steganography
    print("3. Testing text steganography with wrong password...")
    messages.clear()
    
    # First embed with password
    cover_text = "This is a test sentence for steganography. It has multiple sentences for testing. Another sentence here."
    embed_text_worker = WorkerThread("embed_text",
                                    cover_text=cover_text,
                                    message="Secret message",
                                    method="unicode",
                                    password="test123")
    
    embed_text_worker.run()
    
    # Now extract with wrong password
    extract_text_worker = WorkerThread("extract_text",
                                      stego_text=cover_text,  # This will be wrong, but for testing
                                      method="unicode",
                                      password="wrong_password")
    
    extract_text_worker.finished.connect(capture_finished)
    extract_text_worker.run()
    
    if messages:
        success, message = messages[0]
        print(f"   Success: {success}")
        print(f"   Message: {message}")
        if "Invalid password" in message or "No hidden message found" in message:
            print("   ✅ Text steganography error handling working")
        else:
            print("   ❌ Text steganography error handling not working")
    
    # Cleanup
    try:
        os.unlink(cover_path)
        os.unlink(stego_path)
    except:
        pass

if __name__ == "__main__":
    test_gui_error_messages()
