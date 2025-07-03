#!/usr/bin/env python3
"""
Test script to verify password-based encryption/decryption is working properly
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from src.core.image_stego import ImageSteganography
from PIL import Image
import numpy as np

def create_test_image(path="test_image.png"):
    """Create a simple test image"""
    # Create a simple 100x100 RGB image
    img_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(img_array)
    img.save(path)
    return path

def test_password_extraction():
    """Test password-based encryption and decryption"""
    print("🔧 Testing password-based steganography...")
    
    # Create test image
    test_img = create_test_image()
    stego_img = "test_stego.png"
    
    # Test message and password
    secret_message = "This is a secret message with password protection!"
    password = "test_password_123"
    
    try:
        # Test embedding with password
        print(f"📝 Embedding message with password...")
        stego = ImageSteganography()
        embed_result = stego.embed(test_img, secret_message, stego_img, password=password)
        
        if embed_result:
            print("✅ Embedding successful!")
            
            # Test extraction with correct password
            print(f"🔍 Extracting with correct password...")
            extracted_message = stego.extract_text(stego_img, password=password)
            
            if extracted_message == secret_message:
                print("✅ Password extraction successful!")
                print(f"Original:  {secret_message}")
                print(f"Extracted: {extracted_message}")
            else:
                print("❌ Password extraction failed!")
                print(f"Expected: {secret_message}")
                print(f"Got:      {extracted_message}")
            
            # Test extraction with wrong password
            print(f"🔍 Testing with wrong password...")
            try:
                wrong_extracted = stego.extract_text(stego_img, password="wrong_password")
                if wrong_extracted:
                    print("❌ Wrong password should have failed!")
                else:
                    print("✅ Wrong password correctly rejected!")
            except Exception as e:
                print(f"✅ Wrong password correctly rejected: {e}")
                
        else:
            print("❌ Embedding failed!")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        for file in [test_img, stego_img]:
            if os.path.exists(file):
                os.remove(file)

if __name__ == "__main__":
    test_password_extraction()
