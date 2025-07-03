"""
Core steganography functionality module
Provides base classes and common utilities
"""

from abc import ABC, abstractmethod
from typing import Union, Optional, Dict, Any
import logging

class SteganographyBase(ABC):
    """Base class for all steganography operations"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.crypto_manager = None
        
    def set_crypto_manager(self, crypto_manager):
        """Set the crypto manager for encryption/decryption."""
        self.crypto_manager = crypto_manager
        
    @abstractmethod
    def embed(self, cover_data: Any, payload: Union[str, bytes], **kwargs) -> Any:
        """Embed payload into cover data"""
        pass
        
    @abstractmethod
    def extract(self, stego_data: Any, **kwargs) -> Optional[bytes]:
        """Extract payload from steganographic data"""
        pass
        
    @abstractmethod
    def get_capacity(self, cover_data: Any, **kwargs) -> int:
        """Calculate maximum payload capacity"""
        pass
        
    def validate_inputs(self, **kwargs) -> bool:
        """Validate input parameters"""
        return True
