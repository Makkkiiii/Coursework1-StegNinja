#!/usr/bin/env python3
"""
Test script for clean steganographic text handling
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

from src.core.text_stego import TextSteganography

def test_clean_output():
    """Test that steganographic text output is clean"""
    print("Testing clean steganographic text output...")
    
    # Create test data
    cover_text = "This is a test message."
    secret_message = "hidden"
    
    # Create steganography instance
    text_stego = TextSteganography()
    
    # Embed message
    stego_text = text_stego.embed(cover_text, secret_message, method='unicode')
    
    print(f"Original: {cover_text}")
    print(f"Secret: {secret_message}")
    print(f"Steganographic text: {repr(stego_text)}")
    
    # Save to file
    test_file = Path("test_stego_output.txt")
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(stego_text)
    
    print(f"Saved to: {test_file}")
    
    # Read back from file
    with open(test_file, 'r', encoding='utf-8') as f:
        loaded_text = f.read()
    
    print(f"Loaded text: {repr(loaded_text)}")
    
    # Extract message
    extracted = text_stego.extract(loaded_text, method='unicode')
    print(f"Extracted: {extracted}")
    
    # Verify
    if extracted == secret_message:
        print("✓ SUCCESS: Clean save/load works correctly!")
    else:
        print("✗ FAILED: Message extraction failed")
    
    # Clean up
    test_file.unlink()

if __name__ == "__main__":
    test_clean_output()
