"""
Cryptographic utilities for the steganography toolkit.
Provides secure encryption and decryption capabilities.
"""

from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


class CryptoManager:
    """Handles encryption and decryption operations."""
    
    def __init__(self):
        self._key: Optional[bytes] = None
        self._fernet: Optional[Fernet] = None
    
    def set_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Set encryption password and generate key.
        
        Args:
            password: The password string
            salt: Optional salt bytes. If None, generates random salt
            
        Returns:
            The salt used for key derivation
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._key = key
        self._fernet = Fernet(key)
        return salt
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using the current key.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
            
        Raises:
            ValueError: If no key is set
        """
        if self._fernet is None:
            raise ValueError("No encryption key set. Call set_password() first.")
        
        return self._fernet.encrypt(data)
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using the current key.
        
        Args:
            encrypted_data: Data to decrypt
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If no key is set or decryption fails
        """
        if self._fernet is None:
            raise ValueError("No encryption key set. Call set_password() first.")
        
        try:
            return self._fernet.decrypt(encrypted_data)
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def encrypt_string(self, text: str) -> bytes:
        """
        Encrypt a string.
        
        Args:
            text: String to encrypt
            
        Returns:
            Encrypted data as bytes
        """
        return self.encrypt(text.encode('utf-8'))
    
    def decrypt_string(self, encrypted_data: bytes) -> str:
        """
        Decrypt data to string.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted string
        """
        decrypted_bytes = self.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    
    def is_key_set(self) -> bool:
        """Check if encryption key is set."""
        return self._fernet is not None
    
    def clear_key(self) -> None:
        """Clear the current encryption key."""
        self._key = None
        self._fernet = None


def generate_key() -> bytes:
    """Generate a random Fernet key."""
    return Fernet.generate_key()


def encode_for_storage(data: bytes) -> str:
    """Encode binary data for safe storage/transmission."""
    return base64.b64encode(data).decode('ascii')


def decode_from_storage(encoded_data: str) -> bytes:
    """Decode data from storage format."""
    return base64.b64decode(encoded_data.encode('ascii'))
