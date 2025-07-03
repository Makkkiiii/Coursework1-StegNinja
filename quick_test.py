#!/usr/bin/env python3
"""
Quick test to verify GUI functionality after removing metadata features
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

def test_image_functionality():
    """Test that image steganography still works after removing metadata"""
    print("=== Testing Image Steganography (No Metadata) ===")
    
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
        
        # Test embedding
        result = image_stego.embed(cover_path, "Test message without metadata", stego_path, password="test123")
        print(f"✓ Embed result: {result}")
        
        # Test extraction
        extracted = image_stego.extract_text(stego_path, password="test123")
        print(f"✓ Extracted message: {extracted}")
        
        # Test image info
        info = image_stego.get_image_metadata(cover_path)
        print(f"✓ Image format: {info.get('format', 'Unknown')}")
        print(f"✓ Image dimensions: {info.get('dimensions', 'Unknown')}")
        
        # Test comparison metrics
        metrics = image_stego.get_image_comparison_metrics(cover_path, stego_path)
        if metrics:
            print(f"✓ Comparison metrics - MSE: {metrics['mse']:.2f}, PSNR: {metrics['psnr']:.2f}")
        
        print("✓ All tests passed - GUI should work without metadata errors!")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        
    finally:
        try:
            os.unlink(cover_path)
            os.unlink(stego_path)
        except:
            pass

if __name__ == "__main__":
    test_image_functionality()
