"""
Image steganography module using LSB techniques
"""

import numpy as np
from PIL import Image
import cv2
import struct
import zlib
import os
from typing import Union, Optional, Tuple, Dict, Any

# Handle both relative and absolute imports
try:
    from . import SteganographyBase
except ImportError:
    # If running directly, try absolute import
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core import SteganographyBase

class ImageSteganography(SteganographyBase):
    """Professional image steganography using LSB embedding"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['.png', '.bmp', '.tiff', '.jpg', '.jpeg']
        
    def embed(self, cover_path: str, payload: Union[str, bytes], 
              output_path: str, bits_per_channel: int = 1, 
              password: Optional[str] = None, strip_metadata: bool = False,
              preserve_timestamps: bool = True) -> bool:
        """
        Embed data using LSB method
        
        Args:
            cover_path: Path to cover image
            payload: Data to embed
            output_path: Output path for stego image
            bits_per_channel: Number of LSB bits to use (1-4)
            password: Optional encryption password
            strip_metadata: Whether to strip EXIF metadata (default: False - disabled)
            preserve_timestamps: Whether to preserve original timestamps (default: True)
            
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
            
            # Compress payload for better space efficiency
            compressed_payload = zlib.compress(payload)
            self.logger.info(f"Compressed payload: {len(payload)} -> {len(compressed_payload)} bytes")
            
            # Use compressed payload
            payload = compressed_payload
                
            # Encrypt if password provided or crypto manager set
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
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
            
            # Strip metadata for security (if requested)
            #if strip_metadata:
                #self.strip_metadata(result_image)
            
            # Save with format detection
            if output_path.lower().endswith(('.jpg', '.jpeg')):
                result_image.save(output_path, 'JPEG', quality=95, optimize=True)
            else:
                result_image.save(output_path, 'PNG')
            
            # Preserve original timestamps for stealth (if requested)
            if preserve_timestamps:
                self.preserve_timestamps(cover_path, output_path)
            
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
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                try:
                    payload_bytes = crypto.decrypt(payload_bytes)
                except Exception as e:
                    self.logger.error(f"Password decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted data")
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                try:
                    payload_bytes = self.crypto_manager.decrypt(payload_bytes)
                except Exception as e:
                    self.logger.error(f"Decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted data")
            
            # Decompress payload
            try:
                decompressed_payload = zlib.decompress(payload_bytes)
                self.logger.info(f"Decompressed payload: {len(payload_bytes)} -> {len(decompressed_payload)} bytes")
                payload_bytes = decompressed_payload
            except zlib.error:
                # If decompression fails, check if it looks like encrypted data
                try:
                    # Check if it looks like base64 encoded data (typical for Fernet)
                    test_string = payload_bytes.decode('utf-8', errors='ignore')
                    if (len(test_string) > 20 and 
                        all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_' for c in test_string) and
                        test_string.startswith(('gAAAAA', 'gAAAAAB'))):  # Fernet tokens start with these
                        # This looks like encrypted data
                        if not password and not (self.crypto_manager and self.crypto_manager.is_key_set()):
                            raise ValueError("Data appears to be encrypted but no password provided")
                        # If we have a password but failed decryption above, it's wrong password
                        elif password or (self.crypto_manager and self.crypto_manager.is_key_set()):
                            raise ValueError("Invalid password or corrupted data")
                except:
                    pass
                # If not encrypted, use as-is (backward compatibility)
                self.logger.info("Payload not compressed or decompression failed, using as-is")
            
            self.logger.info(f"Successfully extracted {len(payload_bytes)} bytes")
            return payload_bytes
            
        except ValueError as e:
            # Re-raise password-related errors
            if "Invalid password" in str(e) or "encrypted but no password" in str(e):
                raise e
            self.logger.error(f"Extraction failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Extraction failed: {e}")
            return None
    
    def extract_text(self, stego_path: str, bits_per_channel: int = 1,
                     password: Optional[str] = None) -> Optional[str]:
        """Extract text data using LSB method."""
        try:
            data = self.extract(stego_path, bits_per_channel, password)
            if data:
                try:
                    decoded_text = data.decode('utf-8')
                    # Check if decoded text looks like encrypted data
                    if (len(decoded_text) > 20 and 
                        decoded_text.startswith(('gAAAAA', 'gAAAAAB')) and
                        not password and not (hasattr(self, 'crypto_manager') and self.crypto_manager and self.crypto_manager.is_key_set())):
                        raise ValueError("Data appears to be encrypted but no password provided")
                    return decoded_text
                except UnicodeDecodeError:
                    if password or (hasattr(self, 'crypto_manager') and self.crypto_manager and self.crypto_manager.is_key_set()):
                        raise ValueError("Invalid password or corrupted data")
                    else:
                        raise ValueError("Extracted data is not valid text - may be corrupted or encrypted")
            return None
        except ValueError as e:
            if "Invalid password" in str(e) or "encrypted but no password" in str(e):
                raise e
            self.logger.error(f"Text extraction failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Text extraction failed: {e}")
            return None

    def get_capacity(self, cover_path: str, bits_per_channel: int = 1) -> int:
        """Calculate capacity for given image"""
        try:
            return self.get_capacity_for_image(Image.open(cover_path), bits_per_channel)
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
    
 
    def preserve_timestamps(self, source_path: str, target_path: str):
        """Preserve original file timestamps for stealth"""
        try:
            source_stat = os.stat(source_path)
            os.utime(target_path, (source_stat.st_atime, source_stat.st_mtime))
        except Exception as e:
            self.logger.warning(f"Failed to preserve timestamps: {e}")
    
    def get_image_comparison_metrics(self, original_path: str, stego_path: str) -> Dict[str, float]:
        """Calculate image comparison metrics for before/after analysis"""
        try:
            original = cv2.imread(original_path)
            stego = cv2.imread(stego_path)
            
            if original is None or stego is None:
                return {}
            
            # Ensure same dimensions
            if original.shape != stego.shape:
                stego = cv2.resize(stego, (original.shape[1], original.shape[0]))
            
            # Calculate MSE
            mse = np.mean((original - stego) ** 2) # type: ignore
            
            # Calculate PSNR
            if mse == 0:
                psnr = float('inf')
            else:
                max_pixel = 255.0
                psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
            
            # Calculate SSIM using simple correlation
            original_gray = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY)
            stego_gray = cv2.cvtColor(stego, cv2.COLOR_BGR2GRAY)
            
            # Simple SSIM approximation
            mean_orig = np.mean(original_gray) # type: ignore
            mean_stego = np.mean(stego_gray) # type: ignore
            var_orig = np.var(original_gray) # type: ignore
            var_stego = np.var(stego_gray) # type: ignore
            covar = np.mean((original_gray - mean_orig) * (stego_gray - mean_stego))
            
            c1 = 0.01 ** 2
            c2 = 0.03 ** 2
            
            ssim = ((2 * mean_orig * mean_stego + c1) * (2 * covar + c2)) / \
                   ((mean_orig ** 2 + mean_stego ** 2 + c1) * (var_orig + var_stego + c2))
            
            return {
                'mse': float(mse),
                'psnr': float(psnr),
                'ssim': float(ssim)
            }
        
        except Exception as e:
            self.logger.error(f"Failed to calculate comparison metrics: {e}")
            return {}

    def detect_steganography(self, image_path: str, bits_per_channel: int = 1) -> bool:
        """
        Detect if an image contains LSB steganography
        
        Args:
            image_path: Path to image to analyze
            bits_per_channel: Number of LSB bits to check (1-4)
            
        Returns:
            True if steganography detected
        """
        try:
            # Load image
            image = Image.open(image_path).convert('RGB')
            image_array = np.array(image)
            
            # Extract potential data from LSBs
            height, width, channels = image_array.shape
            
            # Extract LSBs more systematically
            lsb_bits = []
            for y in range(height):
                for x in range(width):
                    for c in range(channels):
                        pixel_value = image_array[y, x, c]
                        # Extract the specified number of LSBs
                        for bit_pos in range(bits_per_channel):
                            lsb_bits.append((pixel_value >> bit_pos) & 1)
            
            # Check if we have enough bits for a header
            if len(lsb_bits) < 64:  # Need at least 8 bytes
                return False
            
            # Convert first bits to bytes to check for data patterns
            byte_data = []
            for i in range(0, min(len(lsb_bits), 512), 8):  # Check first 64 bytes worth
                if i + 8 <= len(lsb_bits):
                    byte_val = 0
                    for j in range(8):
                        byte_val |= (lsb_bits[i + j] << j)
                    byte_data.append(byte_val)
            
            if len(byte_data) < 8:
                return False
            
            # Method 1: Look for length header (our embedding method uses this)
            try:
                # First 4 bytes might be data length
                length = struct.unpack('<I', bytes(byte_data[:4]))[0]
                # Check if length is reasonable
                max_capacity = (height * width * channels * bits_per_channel) // 8
                if 0 < length < max_capacity and length < 1000000:  # Reasonable size
                    # Look for compressed data patterns after length header
                    data_start = byte_data[4:8]
                    # Check for zlib magic numbers or other compression signatures
                    if (len(data_start) >= 2 and 
                        ((data_start[0] == 0x78 and data_start[1] in [0x9c, 0xda, 0x01, 0x5e]) or
                         (data_start[0] in [0x1f, 0x78, 0x42, 0x50] and data_start[1] != 0x00))):
                        return True
            except (struct.error, IndexError):
                pass
            
            # Method 2: Statistical analysis for non-random patterns
            if len(byte_data) >= 16:
                # Check byte distribution - real data has certain characteristics
                unique_bytes = len(set(byte_data[:16]))
                zeros_count = byte_data[:16].count(0)
                
                # Real steganographic data tends to have:
                # - Good variety of byte values (not too many repeats)
                # - Not too many zeros (real data is usually compressed)
                if unique_bytes > 8 and zeros_count < 4:
                    return True
            
            # Method 3: Look for our specific embedding patterns
            # Check if the pattern matches what our embed method would create
            try:
                # Try to find a sequence that might be our data
                for start_idx in range(min(16, len(byte_data) - 8)):
                    chunk = bytes(byte_data[start_idx:start_idx + 8])
                    # Look for patterns that suggest structured data
                    if len(chunk) == 8:
                        # Check if it could be length + compressed data
                        potential_length = struct.unpack('<I', chunk[:4])[0]
                        if 1 <= potential_length <= 10000:  # Reasonable message size
                            return True
            except (struct.error, IndexError):
                pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Steganography detection failed: {e}")
            return False

    def auto_detect_type(self, image_path: str) -> tuple[str, str]:
        """
        Automatically detect steganography type (detection only, no extraction)
        
        Args:
            image_path: Path to image to analyze
            
        Returns:
            Tuple of (detection_type, detection_message)
            detection_type: 'lsb', 'none', 'error'
            detection_message: Human-readable detection result
        """
        try:
            # Check different bit depths
            for bits in [1, 2, 3, 4]:
                if self.detect_steganography(image_path, bits):
                    return ('lsb', f'LSB steganography detected (likely {bits}-bit)')
            
            # No steganography detected
            return ('none', 'No steganographic content detected')
            
        except Exception as e:
            return ('error', f'Error during detection: {str(e)}')

def test_module():
    """Quick test to verify module functionality"""
    print("🎯 ImageSteganography Module Test")
    print("=" * 40)
    
    try:
        stego = ImageSteganography()
        print("✅ ImageSteganography module initialized successfully")
        print(f"📁 Supported formats: {stego.supported_formats}")
        
        # Test basic functionality
        test_image = Image.new('RGB', (100, 100), color='red')
        capacity = stego.get_capacity_for_image(test_image, 1)
        print(f"📊 Test image capacity (100x100 RGB): {capacity} bits")
        
        print("\n✅ Module test completed successfully!")
        
    except Exception as e:
        print(f"❌ Failed to initialize ImageSteganography: {e}")

if __name__ == "__main__":
    test_module()