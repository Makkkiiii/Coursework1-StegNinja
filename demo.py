#!/usr/bin/env python3
"""
Demo script for the StegNinja Advanced Steganography Toolkit.
Shows basic usage of image and text steganography features.
"""

import os
import tempfile
from PIL import Image

# Add the project root to the path
import sys
project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)

from src.core.image_stego import ImageSteganography
from src.core.text_stego import TextSteganography
from src.utils.crypto import CryptoManager


def demo_image_steganography():
    """Demonstrate image steganography functionality."""
    print("=== Image Steganography Demo ===")
    
    # Create a sample image
    image = Image.new('RGB', (300, 300), color='red')
    temp_image = tempfile.mktemp(suffix='.png')
    temp_output = tempfile.mktemp(suffix='.png')
    image.save(temp_image)
    
    try:
        # Initialize image steganography
        img_stego = ImageSteganography()
        
        # Test message
        secret_message = "This is a secret message hidden in the image!"
        print(f"Original message: {secret_message}")
        
        # Embed without encryption
        print("\n1. Embedding message (no encryption)...")
        success = img_stego.embed(temp_image, secret_message, temp_output)
        print(f"   Embedding successful: {success}")
        
        if success:
            # Extract without encryption
            print("2. Extracting message (no encryption)...")
            extracted = img_stego.extract_text(temp_output)
            print(f"   Extracted message: {extracted}")
            print(f"   Match: {extracted == secret_message}")
        
        # Test with encryption
        print("\n3. Testing with encryption...")
        password = "demo_password_123"
        crypto = CryptoManager()
        crypto.set_password(password)
        img_stego.set_crypto_manager(crypto)
        
        temp_encrypted = tempfile.mktemp(suffix='.png')
        success = img_stego.embed(temp_image, secret_message, temp_encrypted)
        print(f"   Encrypted embedding successful: {success}")
        
        if success:
            extracted = img_stego.extract_text(temp_encrypted)
            print(f"   Extracted encrypted message: {extracted}")
            print(f"   Match: {extracted == secret_message}")
        
        # Analyze capacity
        print("\n4. Capacity analysis...")
        analysis = img_stego.analyze_capacity(temp_image)
        print(f"   Max payload size: {analysis.get('max_payload_size', 0)} bits")
        print(f"   Image dimensions: {analysis.get('dimensions', 'N/A')}")
        
    finally:
        # Clean up
        for file_path in [temp_image, temp_output, temp_encrypted]:
            if os.path.exists(file_path):
                os.remove(file_path)


def demo_text_steganography():
    """Demonstrate text steganography functionality."""
    print("\n=== Text Steganography Demo ===")
    
    # Sample cover text
    cover_text = """This is a sample document that will be used for demonstrating steganography. 
The text contains multiple sentences and paragraphs. Each sentence provides an opportunity 
to hide secret information. The steganography algorithm can embed data invisibly. 
Modern techniques use Unicode characters or whitespace manipulation. Security researchers 
often use these methods for covert communication. The embedded data remains hidden from 
casual observation. Advanced detection requires specialized tools and analysis."""
    
    # Multiline cover text for whitespace method
    cover_multiline = "\n".join([
        f"Line {i}: This is sample line {i} for whitespace steganography demonstration."
        for i in range(1, 11)
    ])
    
    secret_message = "Hidden message!"
    print(f"Original secret: {secret_message}")
    
    # Initialize text steganography
    text_stego = TextSteganography()
    
    # Test Unicode method
    print("\n1. Unicode steganography...")
    stego_unicode = text_stego.embed_unicode(cover_text, secret_message)
    print(f"   Embedding successful: {stego_unicode is not None}")
    print(f"   Length difference: {len(stego_unicode) - len(cover_text)} characters")
    
    extracted_unicode = text_stego.extract_unicode(stego_unicode)
    print(f"   Extracted: {extracted_unicode}")
    print(f"   Match: {extracted_unicode == secret_message}")
    
    # Test Whitespace method
    print("\n2. Whitespace steganography...")
    stego_whitespace = text_stego.embed_whitespace(cover_multiline, secret_message)
    print(f"   Embedding successful: {stego_whitespace is not None}")
    
    extracted_whitespace = text_stego.extract_whitespace(stego_whitespace)
    print(f"   Extracted: {extracted_whitespace}")
    print(f"   Match: {extracted_whitespace == secret_message}")
    
    # Test with encryption
    print("\n3. Encrypted text steganography...")
    password = "text_demo_password"
    crypto = CryptoManager()
    crypto.set_password(password)
    text_stego.set_crypto_manager(crypto)
    
    stego_encrypted = text_stego.embed_unicode(cover_text, secret_message)
    extracted_encrypted = text_stego.extract_unicode(stego_encrypted)
    print(f"   Encrypted extraction: {extracted_encrypted}")
    print(f"   Match: {extracted_encrypted == secret_message}")
    
    # Analyze text capacity
    print("\n4. Text capacity analysis...")
    analysis = text_stego.analyze_text(cover_text)
    print(f"   Sentences: {analysis.get('sentences', 0)}")
    print(f"   Unicode capacity: {analysis.get('unicode_capacity', 0)} bytes")
    print(f"   Whitespace capacity: {analysis.get('whitespace_capacity', 0)} bytes")


def demo_crypto_functionality():
    """Demonstrate crypto manager functionality."""
    print("\n=== Cryptographic Demo ===")
    
    # Initialize crypto manager
    crypto = CryptoManager()
    password = "demo_encryption_password_456"
    
    # Set password and generate key
    print("1. Setting up encryption...")
    salt = crypto.set_password(password)
    print(f"   Password set with salt: {len(salt)} bytes")
    print(f"   Key is set: {crypto.is_key_set()}")
    
    # Test data encryption
    test_data = b"This is sensitive data that needs to be encrypted!"
    print(f"\n2. Original data: {test_data}")
    
    # Encrypt
    encrypted = crypto.encrypt(test_data)
    print(f"   Encrypted length: {len(encrypted)} bytes")
    print(f"   Data is encrypted: {encrypted != test_data}")
    
    # Decrypt
    decrypted = crypto.decrypt(encrypted)
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {decrypted == test_data}")
    
    # Test string encryption
    print("\n3. String encryption...")
    test_string = "Secret text message!"
    encrypted_string = crypto.encrypt_string(test_string)
    decrypted_string = crypto.decrypt_string(encrypted_string)
    print(f"   Original: {test_string}")
    print(f"   Decrypted: {decrypted_string}")
    print(f"   Match: {decrypted_string == test_string}")


def main():
    """Run all demonstrations."""
    print("StegNinja - Advanced Steganography Toolkit - Demonstration")
    print("=" * 50)
    
    try:
        demo_crypto_functionality()
        demo_image_steganography()
        demo_text_steganography()
        
        print("\n" + "=" * 50)
        print("All demonstrations completed successfully!")
        print("\nTo use the GUI application, run: python main.py")
        
    except Exception as e:
        print(f"\nError during demonstration: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
