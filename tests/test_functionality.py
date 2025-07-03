#!/usr/bin/env python3
"""
Test script to verify password and unicode functionality
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

from core.text_stego import TextSteganography

def test_unicode_without_password():
    """Test unicode method without password"""
    print("Testing Unicode method without password...")
    
    text_stego = TextSteganography()
    cover_text = "This is a sample text. It has multiple sentences. Each sentence can hide data."
    secret_message = "Hidden message"
    
    # Embed
    stego_text = text_stego.embed(cover_text, secret_message, method='unicode')
    print(f"Original: {cover_text}")
    print(f"Stego: {stego_text}")
    print(f"Same as original: {stego_text == cover_text}")
    
    # Extract
    extracted = text_stego.extract(stego_text, method='unicode')
    print(f"Extracted: {extracted}")
    print(f"Success: {extracted == secret_message}")
    print()

def test_unicode_with_password():
    """Test unicode method with password"""
    print("Testing Unicode method with password...")
    
    text_stego = TextSteganography()
    cover_text = "This is a sample text. It has multiple sentences. Each sentence can hide data."
    secret_message = "Hidden encrypted message"
    password = "test123"
    
    # Embed
    stego_text = text_stego.embed(cover_text, secret_message, method='unicode', password=password)
    print(f"Original: {cover_text}")
    print(f"Stego: {stego_text}")
    print(f"Same as original: {stego_text == cover_text}")
    
    # Extract with correct password
    extracted = text_stego.extract(stego_text, method='unicode', password=password)
    print(f"Extracted with correct password: {extracted}")
    print(f"Success: {extracted == secret_message}")
    
    # Extract with wrong password
    try:
        extracted_wrong = text_stego.extract(stego_text, method='unicode', password="wrong")
        print(f"Extracted with wrong password: {extracted_wrong}")
    except:
        print("Failed to extract with wrong password (expected)")
    print()

def test_whitespace_without_password():
    """Test whitespace method without password"""
    print("Testing Whitespace method without password...")
    
    text_stego = TextSteganography()
    cover_text = """This is line one.
This is line two.
This is line three.
This is line four."""
    secret_message = "Secret"
    
    # Embed
    stego_text = text_stego.embed(cover_text, secret_message, method='whitespace')
    print(f"Original: {repr(cover_text)}")
    print(f"Stego: {repr(stego_text)}")
    print(f"Same as original: {stego_text == cover_text}")
    
    # Extract
    extracted = text_stego.extract(stego_text, method='whitespace')
    print(f"Extracted: {extracted}")
    print(f"Success: {extracted == secret_message}")
    print()

if __name__ == "__main__":
    test_unicode_without_password()
    test_unicode_with_password()
    test_whitespace_without_password()
    print("All tests completed!")
