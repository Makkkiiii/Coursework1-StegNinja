#!/usr/bin/env python3
"""
Test the complete functionality after removing metadata and updating UI
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
from src.core.text_stego import TextSteganography
from src.core.file_stego import FileSteganography

def test_complete_functionality():
    """Test all steganography methods with password errors and file integrity"""
    print("=== Testing Complete Steganography Functionality ===")
    
    # Test 1: Image steganography with password errors
    print("\n1. Testing Image Steganography Password Errors...")
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
        result = image_stego.embed(cover_path, "Secret message", stego_path, password="test123")
        print(f"   Image embed result: {result}")
        
        # Extract with wrong password
        try:
            extracted = image_stego.extract_text(stego_path, password="wrong")
            print(f"   Wrong password extracted: {extracted}")
        except ValueError as e:
            print(f"   ✓ Wrong password error: {e}")
        
        # Extract with correct password
        try:
            extracted = image_stego.extract_text(stego_path, password="test123")
            print(f"   ✓ Correct password extracted: {extracted}")
        except Exception as e:
            print(f"   Error: {e}")
        
    finally:
        try:
            os.unlink(cover_path)
            os.unlink(stego_path)
        except:
            pass
    
    # Test 2: Text steganography with password errors
    print("\n2. Testing Text Steganography Password Errors...")
    text_stego = TextSteganography()
    cover_text = "This is a test sentence for steganography. It has multiple sentences for testing purposes."
    
    try:
        # Embed with password
        stego_text = text_stego.embed_unicode(cover_text, "Secret message", password="test123")
        print(f"   Text embed result: Success")
        
        # Extract with wrong password
        try:
            extracted = text_stego.extract_unicode(stego_text, password="wrong")
            print(f"   Wrong password extracted: {extracted}")
        except ValueError as e:
            print(f"   ✓ Wrong password error: {e}")
        
        # Extract with correct password
        try:
            extracted = text_stego.extract_unicode(stego_text, password="test123")
            print(f"   ✓ Correct password extracted: {extracted}")
        except Exception as e:
            print(f"   Error: {e}")
        
    except Exception as e:
        print(f"   Text steganography error: {e}")
    
    # Test 3: File steganography and integrity checking
    print("\n3. Testing File Steganography and Integrity...")
    
    # Create test PDF file
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
        # Create a minimal PDF content
        pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
>>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<<
/Size 4
/Root 1 0 R
>>
startxref
189
%%EOF"""
        tmp_pdf.write(pdf_content)
        original_pdf = tmp_pdf.name
    
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_stego_pdf:
        stego_pdf = tmp_stego_pdf.name
    
    try:
        file_stego = FileSteganography()
        
        # Get original file info
        original_info = file_stego.get_file_info(original_pdf)
        print(f"   Original file hash: {original_info.get('hash', 'N/A')}")
        
        # Embed in PDF
        result = file_stego.embed(original_pdf, "Secret file message", stego_pdf, password="filepass")
        print(f"   File embed result: {result}")
        
        if result:
            # Get modified file info
            modified_info = file_stego.get_file_info(stego_pdf)
            print(f"   Modified file hash: {modified_info.get('hash', 'N/A')}")
            
            # Check integrity
            integrity = file_stego.check_file_integrity(original_pdf, stego_pdf)
            print(f"   Size changed: {integrity.get('size_changed', 'N/A')}")
            print(f"   Hash changed: {integrity.get('hash_changed', 'N/A')}")
            print(f"   Likely modified: {integrity.get('likely_modified', 'N/A')}")
            
            # Extract with wrong password
            try:
                extracted = file_stego.extract_text(stego_pdf, password="wrong")
                print(f"   Wrong password extracted: {extracted}")
            except ValueError as e:
                print(f"   ✓ Wrong password error: {e}")
            
            # Extract with correct password
            try:
                extracted = file_stego.extract_text(stego_pdf, password="filepass")
                print(f"   ✓ Correct password extracted: {extracted}")
            except Exception as e:
                print(f"   Error: {e}")
        
    finally:
        try:
            os.unlink(original_pdf)
            os.unlink(stego_pdf)
        except:
            pass
    
    print("\n=== All tests completed ===")

if __name__ == "__main__":
    test_complete_functionality()
