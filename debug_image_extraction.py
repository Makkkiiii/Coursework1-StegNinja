#!/usr/bin/env python3
"""
Debug script to check what image steganography extracted data looks like
"""

import os
import tempfile
import sys
from PIL import Image
import numpy as np

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

from src.core.image_stego import ImageSteganography

def debug_image_extraction():
    """Debug what the extracted data looks like"""
    print("=== Debug Image Extraction ===")
    
    # Create test image
    test_image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(test_image)
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_cover:
        img.save(tmp_cover.name)
        cover_path = tmp_cover.name
    
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_stego:
        stego_path = tmp_stego.name
    
    try:
        image_stego = ImageSteganography()
        
        # Embed with password
        print("1. Embedding with password...")
        result = image_stego.embed(cover_path, "Secret message", stego_path, password="test123")
        print(f"   Embed result: {result}")
        
        # Extract raw data (not text)
        print("2. Extracting raw data without password...")
        raw_data = image_stego.extract(stego_path)
        print(f"   Raw data type: {type(raw_data)}")
        print(f"   Raw data length: {len(raw_data) if raw_data else 0}")
        
        if raw_data:
            # Try to decode as UTF-8
            print("3. Attempting UTF-8 decode...")
            try:
                decoded = raw_data.decode('utf-8')
                print(f"   Decoded: {decoded}")
            except UnicodeDecodeError as e:
                print(f"   UTF-8 decode failed: {e}")
                
                # Try to decode with errors='ignore'
                decoded_ignore = raw_data.decode('utf-8', errors='ignore')
                print(f"   Decoded with ignore: {decoded_ignore[:100]}...")
                
                # Check if it starts with Fernet token pattern
                if decoded_ignore.startswith(('gAAAAA', 'gAAAAAB')):
                    print("   ✓ Detected as encrypted data (Fernet token)")
                else:
                    print("   ✗ Does not look like Fernet token")
        
        # Extract with correct password
        print("4. Extracting with correct password...")
        try:
            extracted = image_stego.extract_text(stego_path, password="test123")
            print(f"   Extracted: {extracted}")
        except Exception as e:
            print(f"   Error: {e}")
        
    finally:
        # Cleanup
        try:
            os.unlink(cover_path)
            os.unlink(stego_path)
        except:
            pass

if __name__ == "__main__":
    debug_image_extraction()
