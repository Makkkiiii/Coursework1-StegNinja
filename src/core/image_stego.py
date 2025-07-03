"""
Image steganography module using LSB techniques
"""

import numpy as np
from PIL import Image
import cv2
import struct
from typing import Union, Optional, Tuple, Dict, Any
from . import SteganographyBase

class ImageSteganography(SteganographyBase):
    """Professional image steganography using LSB embedding"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['.png', '.bmp', '.tiff']
        
    def embed(self, cover_path: str, payload: Union[str, bytes], 
              output_path: str, bits_per_channel: int = 1, 
              password: Optional[str] = None) -> bool:
        """
        Embed data using LSB method
        
        Args:
            cover_path: Path to cover image
            payload: Data to embed
            output_path: Output path for stego image
            bits_per_channel: Number of LSB bits to use (1-4)
            password: Optional encryption password
            
        Returns:
            Success status
        """
        try:
            # Load and validate image
            image = Image.open(cover_path).convert('RGB')
            width, height = image.size
            
            # Prepare payload
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
                
            # Encrypt if password provided or crypto manager set
            if password and not self.crypto_manager:
                from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                payload = crypto.encrypt(payload)
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload = self.crypto_manager.encrypt(payload)
            
            # Create payload with length header
            payload_with_header = struct.pack('>I', len(payload)) + payload # type: ignore
            
            # Convert to binary string
            binary_data = ''.join(format(byte, '08b') for byte in payload_with_header)
            
            # Check capacity
            capacity = self.get_capacity_for_image(image, bits_per_channel)
            if len(binary_data) > capacity:
                raise ValueError(f"Payload too large. Maximum: {capacity} bits")
            
            # Embed data
            img_array = np.array(image)
            flat_array = img_array.flatten()
            
            data_index = 0
            for i in range(len(flat_array)):
                if data_index < len(binary_data):
                    # Clear LSB bits
                    mask = (0xFF << bits_per_channel) & 0xFF
                    flat_array[i] = int(flat_array[i]) & mask
                    
                    # Get bits to embed
                    bits = binary_data[data_index:data_index + bits_per_channel]
                    if len(bits) < bits_per_channel:
                        bits = bits.ljust(bits_per_channel, '0')
                    
                    # Set new LSB bits
                    new_bits = int(bits, 2)
                    flat_array[i] = (int(flat_array[i]) | new_bits) & 0xFF
                    data_index += bits_per_channel
                else:
                    break
            
            # Reshape and save
            result_array = flat_array.reshape(img_array.shape)
            result_image = Image.fromarray(result_array.astype('uint8'))
            result_image.save(output_path, 'PNG')
            
            self.logger.info(f"Successfully embedded {len(payload)} bytes")
            return True
            
        except Exception as e:
            self.logger.error(f"Embedding failed: {e}")
            return False
    
    def extract(self, stego_path: str, bits_per_channel: int = 1,
                password: Optional[str] = None) -> Optional[bytes]:
        """
        Extract data using LSB method
        
        Args:
            stego_path: Path to steganographic image
            bits_per_channel: Number of LSB bits used
            password: Decryption password
            
        Returns:
            Extracted data or None if failed
        """
        try:
            # Load image
            image = Image.open(stego_path).convert('RGB')
            img_array = np.array(image)
            flat_array = img_array.flatten()
            
            # Extract length header (32 bits)
            binary_length = ''
            for i in range(32 // bits_per_channel):
                if i < len(flat_array):
                    pixel_value = flat_array[i]
                    bits = format(pixel_value & ((1 << bits_per_channel) - 1), 
                                f'0{bits_per_channel}b')
                    binary_length += bits
            
            # Get payload length
            if len(binary_length) >= 32:
                payload_length = struct.unpack('>I', 
                    int(binary_length[:32], 2).to_bytes(4, 'big'))[0]
            else:
                return None
            
            # Extract payload
            total_bits = 32 + (payload_length * 8)
            binary_data = ''
            
            for i in range(total_bits // bits_per_channel):
                if i < len(flat_array):
                    pixel_value = flat_array[i]
                    bits = format(pixel_value & ((1 << bits_per_channel) - 1), 
                                f'0{bits_per_channel}b')
                    binary_data += bits
            
            # Convert to bytes (skip header)
            payload_binary = binary_data[32:32 + (payload_length * 8)]
            payload_bytes = bytes(int(payload_binary[i:i+8], 2) 
                                for i in range(0, len(payload_binary), 8))
            
            # Decrypt if password provided or crypto manager set
            if password and not self.crypto_manager:
                from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                payload_bytes = crypto.decrypt(payload_bytes)
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload_bytes = self.crypto_manager.decrypt(payload_bytes)
            
            self.logger.info(f"Successfully extracted {len(payload_bytes)} bytes")
            return payload_bytes
            
        except Exception as e:
            self.logger.error(f"Extraction failed: {e}")
            return None
    
    def extract_text(self, stego_path: str, bits_per_channel: int = 1,
                     password: Optional[str] = None) -> Optional[str]:
        """
        Extract text data using LSB method.
        
        Args:
            stego_path: Path to steganographic image
            bits_per_channel: Number of LSB bits used
            password: Decryption password
            
        Returns:
            Extracted text or None if failed
        """
        try:
            data = self.extract(stego_path, bits_per_channel, password)
            if data:
                return data.decode('utf-8')
            return None
        except Exception as e:
            self.logger.error(f"Text extraction failed: {e}")
            return None

    def get_capacity(self, cover_path: str, bits_per_channel: int = 1) -> int:
        """Calculate capacity for given image"""
        try:
            image = Image.open(cover_path)
            return self.get_capacity_for_image(image, bits_per_channel)
        except:
            return 0
    
    def get_capacity_for_image(self, image: Image.Image, bits_per_channel: int) -> int:
        """Calculate capacity for image object"""
        width, height = image.size
        channels = len(image.getbands())
        total_bits = width * height * channels * bits_per_channel
        return total_bits - 32  # Subtract header bits
    
    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """Analyze image for steganographic potential"""
        try:
            image = Image.open(image_path)
            width, height = image.size
            channels = len(image.getbands())
            
            return {
                'width': width,
                'height': height,
                'channels': channels,
                'format': image.format,
                'mode': image.mode,
                'capacity_1bit': self.get_capacity_for_image(image, 1),
                'capacity_2bit': self.get_capacity_for_image(image, 2),
                'capacity_4bit': self.get_capacity_for_image(image, 4),
                'file_size': len(open(image_path, 'rb').read())
            }
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {}
        
    def analyze_capacity(self, image_path: str) -> Dict[str, Any]:
        """
        Analyze the steganographic capacity of an image.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary with capacity analysis results
        """
        try:
            analysis = self.analyze_image(image_path)
            max_capacity = analysis.get('capacity_1bit', 0)
            
            return {
                'max_payload_size': max_capacity,
                'efficiency': max_capacity / analysis.get('file_size', 1) if analysis.get('file_size') else 0,
                'dimensions': f"{analysis.get('width', 0)}x{analysis.get('height', 0)}",
                'format': analysis.get('format', 'Unknown'),
                'channels': analysis.get('channels', 0)
            }
        except Exception as e:
            self.logger.error(f"Capacity analysis failed: {e}")
            return {'max_payload_size': 0, 'efficiency': 0}
