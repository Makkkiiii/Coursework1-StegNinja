"""
Basic tests for the StegNinja steganography toolkit.
"""

import unittest
import tempfile
import os
from PIL import Image
import numpy as np

# Add the project root to the path
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.core.image_stego import ImageSteganography
from src.core.text_stego import TextSteganography
from src.utils.crypto import CryptoManager


class TestImageSteganography(unittest.TestCase):
    """Test image steganography functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.image_stego = ImageSteganography()
        self.test_message = "This is a test message for steganography!"
        
        # Create a test image
        self.test_image = Image.new('RGB', (200, 200), color='red')
        self.test_image_path = tempfile.mktemp(suffix='.png')
        self.test_image.save(self.test_image_path)
        
        self.output_path = tempfile.mktemp(suffix='.png')
    
    def tearDown(self):
        """Clean up test files."""
        for path in [self.test_image_path, self.output_path]:
            if os.path.exists(path):
                os.remove(path)
    
    def test_embed_and_extract_basic(self):
        """Test basic embed and extract functionality."""
        # Test embedding
        result = self.image_stego.embed(
            self.test_image_path,
            self.test_message,
            self.output_path
        )
        self.assertTrue(result, "Embedding should succeed")
        self.assertTrue(os.path.exists(self.output_path), "Output file should exist")
        
        # Test extraction (as text)
        extracted = self.image_stego.extract_text(self.output_path)
        self.assertEqual(extracted, self.test_message, "Extracted message should match original")
    
    def test_embed_with_encryption(self):
        """Test embedding with encryption."""
        password = "test_password_123"
        
        # Set up crypto manager
        crypto = CryptoManager()
        crypto.set_password(password)
        self.image_stego.set_crypto_manager(crypto)
        
        # Test embedding
        result = self.image_stego.embed(
            self.test_image_path,
            self.test_message,
            self.output_path
        )
        self.assertTrue(result, "Encrypted embedding should succeed")
        
        # Test extraction with correct password (as text)
        extracted = self.image_stego.extract_text(self.output_path, password=password)
        self.assertEqual(extracted, self.test_message, "Extracted encrypted message should match")
    
    def test_capacity_analysis(self):
        """Test capacity analysis functionality."""
        analysis = self.image_stego.analyze_capacity(self.test_image_path)
        
        self.assertIn('max_payload_size', analysis)
        self.assertIn('efficiency', analysis)
        self.assertGreater(analysis['max_payload_size'], 0)


class TestTextSteganography(unittest.TestCase):
    """Test text steganography functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.text_stego = TextSteganography()
        self.cover_text = "This is a sample cover text that will be used for testing steganography. " * 10
        self.cover_text_multiline = "\n".join([f"Line {i}: This is a test line for whitespace steganography." for i in range(1, 21)])
        self.secret_message = "Secret message for testing!"
    
    def test_unicode_embed_and_extract(self):
        """Test Unicode method embed and extract."""
        # Test embedding
        stego_text = self.text_stego.embed_unicode(self.cover_text, self.secret_message)
        self.assertIsNotNone(stego_text, "Unicode embedding should succeed")
        self.assertNotEqual(stego_text, self.cover_text, "Stego text should be different from cover")
        
        # Test extraction
        extracted = self.text_stego.extract_unicode(stego_text)
        self.assertEqual(extracted, self.secret_message, "Extracted message should match original")
    
    def test_whitespace_embed_and_extract(self):
        """Test whitespace method embed and extract."""
        # Test embedding
        stego_text = self.text_stego.embed_whitespace(self.cover_text_multiline, self.secret_message)
        self.assertIsNotNone(stego_text, "Whitespace embedding should succeed")
        
        # Test extraction
        extracted = self.text_stego.extract_whitespace(stego_text)
        self.assertEqual(extracted, self.secret_message, "Extracted message should match original")
    
    def test_text_with_encryption(self):
        """Test text steganography with encryption."""
        password = "test_password_456"
        
        # Set up crypto manager
        crypto = CryptoManager()
        crypto.set_password(password)
        self.text_stego.set_crypto_manager(crypto)
        
        # Test embedding and extraction
        stego_text = self.text_stego.embed_unicode(self.cover_text, self.secret_message)
        self.assertIsNotNone(stego_text, "Encrypted text embedding should succeed")
        
        extracted = self.text_stego.extract_unicode(stego_text)
        self.assertEqual(extracted, self.secret_message, "Extracted encrypted text should match")


class TestCryptoManager(unittest.TestCase):
    """Test cryptographic functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.crypto = CryptoManager()
        self.test_data = b"This is test data for encryption!"
        self.test_string = "This is a test string for encryption!"
        self.password = "strong_test_password_789"
    
    def test_basic_encryption_decryption(self):
        """Test basic encryption and decryption."""
        # Set password
        salt = self.crypto.set_password(self.password)
        self.assertIsInstance(salt, bytes, "Salt should be bytes")
        
        # Test bytes encryption/decryption
        encrypted = self.crypto.encrypt(self.test_data)
        self.assertNotEqual(encrypted, self.test_data, "Encrypted data should be different")
        
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(decrypted, self.test_data, "Decrypted data should match original")
    
    def test_string_encryption_decryption(self):
        """Test string encryption and decryption."""
        self.crypto.set_password(self.password)
        
        # Test string encryption/decryption
        encrypted = self.crypto.encrypt_string(self.test_string)
        self.assertIsInstance(encrypted, bytes, "Encrypted string should return bytes")
        
        decrypted = self.crypto.decrypt_string(encrypted)
        self.assertEqual(decrypted, self.test_string, "Decrypted string should match original")
    
    def test_deterministic_key_derivation(self):
        """Test that the same password produces the same key."""
        salt1 = self.crypto.set_password(self.password)
        encrypted1 = self.crypto.encrypt(self.test_data)
        
        # Reset and use same password with same salt
        self.crypto.clear_key()
        self.crypto.set_password(self.password, salt1)
        encrypted2 = self.crypto.encrypt(self.test_data)
        
        # Should be able to decrypt both with the same key
        decrypted1 = self.crypto.decrypt(encrypted1)
        decrypted2 = self.crypto.decrypt(encrypted2)
        
        self.assertEqual(decrypted1, self.test_data)
        self.assertEqual(decrypted2, self.test_data)


if __name__ == '__main__':
    # Create a test suite using the modern approach
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(loader.loadTestsFromTestCase(TestCryptoManager))
    suite.addTest(loader.loadTestsFromTestCase(TestImageSteganography))
    suite.addTest(loader.loadTestsFromTestCase(TestTextSteganography))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
