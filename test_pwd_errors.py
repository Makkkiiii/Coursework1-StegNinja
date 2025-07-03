#!/usr/bin/env python3
"""
Test password error messages specifically
"""

import sys
import os
from pathlib import Path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from src.core.image_stego import ImageSteganography
from PIL import Image
import numpy as np

def test_password_errors():
    """Test password error handling"""
    print("🔧 Testing password error messages...")
    
    # Create test image
    img_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(img_array)
    test_img = "test_pwd.png"
    img.save(test_img)
    
    stego_img = "test_pwd_stego.png"
    secret_message = "Password test message"
    password = "correct_password"
    wrong_password = "wrong_password"
    
    try:
        # Embed with password
        print("📝 Embedding with password...")
        stego = ImageSteganography()
        result = stego.embed(test_img, secret_message, stego_img, password=password)
        
        if result:
            print("✅ Embedding successful!")
            
            # Test 1: Extract with correct password
            print("🔍 Test 1: Extract with correct password...")
            try:
                extracted = stego.extract_text(stego_img, password=password)
                print(f"✅ Success: {extracted}")
            except Exception as e:
                print(f"❌ Failed: {e}")
            
            # Test 2: Extract with wrong password
            print("🔍 Test 2: Extract with wrong password...")
            try:
                extracted = stego.extract_text(stego_img, password=wrong_password)
                print(f"❌ Should have failed but got: {extracted}")
            except ValueError as e:
                print(f"✅ Correctly caught ValueError: {e}")
            except Exception as e:
                print(f"⚠️ Caught other exception ({type(e).__name__}): {e}")
            
            # Test 3: Extract without password (should fail when encrypted)
            print("🔍 Test 3: Extract without password...")
            try:
                extracted = stego.extract_text(stego_img)
                if extracted and len(extracted) > 40:  # Long base64-like string
                    print(f"❌ Got encrypted data instead of error: {extracted[:50]}...")
                elif extracted:
                    print(f"❌ Should have failed but got: {extracted}")
                else:
                    print("❌ Got None instead of proper error")
            except ValueError as e:
                print(f"✅ Correctly caught ValueError: {e}")
            except Exception as e:
                print(f"⚠️ Caught other exception ({type(e).__name__}): {e}")
                
        else:
            print("❌ Embedding failed!")
    
    except Exception as e:
        print(f"❌ Test setup failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        for file in [test_img, stego_img]:
            if os.path.exists(file):
                os.remove(file)

if __name__ == "__main__":
    test_password_errors()
