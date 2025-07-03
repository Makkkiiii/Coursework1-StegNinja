"""
Text steganography module using Unicode and whitespace techniques
"""

import re
import base64
import zlib
from typing import Optional, Dict, Any, Union
from . import SteganographyBase

class TextSteganography(SteganographyBase):
    """Professional text steganography implementation"""
    
    def __init__(self):
        super().__init__()
        
        # Zero-width Unicode characters for steganography
        self.zw_chars = {
            '0': '\u200b',  # Zero width space
            '1': '\u200c',  # Zero width non-joiner
        }
        
        # Reverse mapping
        self.char_to_bit = {v: k for k, v in self.zw_chars.items()}
        
        # Whitespace patterns
        self.ws_chars = {
            '0': ' ',       # Single space
            '1': '\t',      # Tab character
        }

    def embed_unicode(self, cover_text: str, payload: Union[str, bytes], 
                     password: Optional[str] = None) -> str:
        """
        Embed data using zero-width Unicode characters
        
        Args:
            cover_text: Cover text to hide data in
            payload: Secret message to embed
            password: Optional encryption password
            
        Returns:
            Text with embedded data
        """
        try:
            # Prepare payload
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
                
            salt = None
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                salt = crypto.set_password(password)
                encrypted_payload = crypto.encrypt(payload)
                # Prepend salt to encrypted data for later retrieval
                payload = salt + encrypted_payload
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload = self.crypto_manager.encrypt(payload)
                
            # Encode payload as base64 for text handling
            b64_payload = base64.b64encode(payload).decode('ascii') # type: ignore
            
            # Convert to binary
            binary_data = ''.join(format(ord(char), '08b') for char in b64_payload)
            
            # Add end marker
            binary_data += '1111111111111110'  # 16-bit end marker
            
            # Convert binary to zero-width characters
            zw_sequence = ''.join(self.zw_chars[bit] for bit in binary_data)
            
            # Insert into text between sentences
            sentences = re.split(r'([.!?]\s+)', cover_text)
            result_parts = []
            zw_index = 0
            
            for i, part in enumerate(sentences):
                result_parts.append(part)
                
                # Insert zero-width chars after sentence endings
                if i % 2 == 1 and zw_index < len(zw_sequence):  # Sentence ending
                    # Calculate how much data we need to distribute
                    remaining_sentence_endings = sum(1 for j in range(i+2, len(sentences), 2))
                    remaining_data = len(zw_sequence) - zw_index
                    
                    if remaining_sentence_endings == 0:
                        # This is the last sentence ending, embed all remaining data
                        chunk_size = remaining_data
                    else:
                        # Distribute data evenly across remaining sentence endings
                        chunk_size = min(remaining_data, (remaining_data + remaining_sentence_endings - 1) // remaining_sentence_endings)
                    
                    result_parts.append(zw_sequence[zw_index:zw_index + chunk_size])
                    zw_index += chunk_size
            
            # If there's still data left, append it at the end
            if zw_index < len(zw_sequence):
                result_parts.append(zw_sequence[zw_index:])
            
            return ''.join(result_parts)
            
        except Exception as e:
            self.logger.error(f"Unicode embedding failed: {e}")
            return cover_text
    
    def extract_unicode(self, stego_text: str, 
                       password: Optional[str] = None) -> Optional[str]:
        """
        Extract data from zero-width Unicode characters
        
        Args:
            stego_text: Text containing hidden data
            password: Decryption password
            
        Returns:
            Extracted message or None if failed
        """
        try:
            # Extract zero-width characters
            binary_data = ''
            for char in stego_text:
                if char in self.char_to_bit:
                    binary_data += self.char_to_bit[char]
            
            if not binary_data:
                return None
            
            # Find end marker
            end_marker = '1111111111111110'
            end_pos = binary_data.find(end_marker)
            
            if end_pos == -1:
                return None
            
            # Extract payload binary
            payload_binary = binary_data[:end_pos]
            
            # Convert binary to text
            b64_payload = ''
            for i in range(0, len(payload_binary), 8):
                byte_str = payload_binary[i:i+8]
                if len(byte_str) == 8:
                    b64_payload += chr(int(byte_str, 2))
            
            # Decode base64
            payload = base64.b64decode(b64_payload.encode('ascii'))
            
            # Decrypt if needed
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                if len(payload) >= 16:  # Salt is 16 bytes
                    salt = payload[:16]
                    encrypted_data = payload[16:]
                    crypto = CryptoManager()
                    crypto.set_password(password, salt)
                    try:
                        payload = crypto.decrypt(encrypted_data)
                    except Exception as e:
                        self.logger.error(f"Decryption failed: {e}")
                        raise ValueError("Invalid password or corrupted data")
                else:
                    # Check if data looks encrypted but no proper encryption format
                    if len(payload) > 20:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.startswith(('gAAAAA', 'gAAAAAB')):
                            raise ValueError("Data appears to be encrypted but no password provided")
                    return None
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                try:
                    payload = self.crypto_manager.decrypt(payload)
                except Exception as e:
                    self.logger.error(f"Decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted data")
            
            # Check if we have encrypted data but no password
            if not password and not (self.crypto_manager and self.crypto_manager.is_key_set()):
                try:
                    # Try to detect if payload looks like encrypted base64 data
                    if len(payload) > 20:
                        # Check if it's base64-like encrypted data
                        try:
                            test_decode = payload.decode('utf-8')
                            if test_decode.startswith(('gAAAAA', 'gAAAAAB')) and len(test_decode) > 40:
                                raise ValueError("Data appears to be encrypted but no password provided")
                        except UnicodeDecodeError:
                            pass
                except:
                    pass
            
            try:
                return payload.decode('utf-8')
            except UnicodeDecodeError:
                # If UTF-8 decode fails, it might be encrypted data
                if not password and not (self.crypto_manager and self.crypto_manager.is_key_set()):
                    raise ValueError("Data appears to be encrypted but no password provided")
                else:
                    raise ValueError("Invalid password or corrupted data")
            
        except ValueError as e:
            # Re-raise password-related errors
            if "Invalid password" in str(e) or "encrypted but no password" in str(e):
                raise e
            self.logger.error(f"Unicode extraction failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unicode extraction failed: {e}")
            return None
    
    def embed_whitespace(self, cover_text: str, payload: Union[str, bytes],
                        password: Optional[str] = None) -> str:
        """
        Embed data using whitespace manipulation
        
        Args:
            cover_text: Cover text to hide data in
            payload: Secret message to embed
            password: Optional encryption password
            
        Returns:
            Text with embedded data
        """
        try:
            # Prepare payload (same as Unicode method)
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
                
            salt = None
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                salt = crypto.set_password(password)
                encrypted_payload = crypto.encrypt(payload)
                # Prepend salt to encrypted data for later retrieval
                payload = salt + encrypted_payload
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload = self.crypto_manager.encrypt(payload)
                
            b64_payload = base64.b64encode(payload).decode('ascii') # type: ignore
            binary_data = ''.join(format(ord(char), '08b') for char in b64_payload)
            binary_data += '1111111111111110'  # End marker
            
            # Split into lines and add trailing whitespace
            lines = cover_text.split('\n')
            result_lines = []
            bit_index = 0
            
            for line in lines:
                if bit_index < len(binary_data):
                    # Calculate how many bits to put on this line
                    remaining_lines = len(lines) - len(result_lines)
                    remaining_bits = len(binary_data) - bit_index
                    
                    if remaining_lines == 1:
                        # Last line, put all remaining bits
                        bits_this_line = remaining_bits
                    else:
                        # Distribute bits evenly
                        bits_this_line = min(32, (remaining_bits + remaining_lines - 1) // remaining_lines)
                    
                    # Add trailing whitespace based on binary data
                    trailing = ''
                    for _ in range(bits_this_line):
                        if bit_index < len(binary_data):
                            bit = binary_data[bit_index]
                            trailing += self.ws_chars[bit]
                            bit_index += 1
                    
                    result_lines.append(line + trailing)
                else:
                    result_lines.append(line)
            
            return '\n'.join(result_lines)
            
        except Exception as e:
            self.logger.error(f"Whitespace embedding failed: {e}")
            return cover_text
    
    def extract_whitespace(self, stego_text: str,
                          password: Optional[str] = None) -> Optional[str]:
        """
        Extract data from whitespace patterns
        
        Args:
            stego_text: Text containing hidden data
            password: Decryption password
            
        Returns:
            Extracted message or None if failed
        """
        try:
            # Extract whitespace patterns
            binary_data = ''
            lines = stego_text.split('\n')
            
            for line in lines:
                # Get trailing whitespace
                trailing = line[len(line.rstrip()):]
                
                # Convert to binary
                for char in trailing:
                    if char == ' ':
                        binary_data += '0'
                    elif char == '\t':
                        binary_data += '1'
            
            if not binary_data:
                return None
            
            # Find end marker and extract (same as Unicode method)
            end_marker = '1111111111111110'
            end_pos = binary_data.find(end_marker)
            
            if end_pos == -1:
                return None
            
            payload_binary = binary_data[:end_pos]
            
            # Convert to text
            b64_payload = ''
            for i in range(0, len(payload_binary), 8):
                byte_str = payload_binary[i:i+8]
                if len(byte_str) == 8:
                    b64_payload += chr(int(byte_str, 2))
            
            payload = base64.b64decode(b64_payload.encode('ascii'))
            
            # Decrypt if needed
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                if len(payload) >= 16:  # Salt is 16 bytes
                    salt = payload[:16]
                    encrypted_data = payload[16:]
                    crypto = CryptoManager()
                    crypto.set_password(password, salt)
                    try:
                        payload = crypto.decrypt(encrypted_data)
                    except Exception as e:
                        self.logger.error(f"Decryption failed: {e}")
                        raise ValueError("Invalid password or corrupted data")
                else:
                    # Check if data looks encrypted but no proper encryption format
                    if len(payload) > 20:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.startswith(('gAAAAA', 'gAAAAAB')):
                            raise ValueError("Data appears to be encrypted but no password provided")
                    return None
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                try:
                    payload = self.crypto_manager.decrypt(payload)
                except Exception as e:
                    self.logger.error(f"Decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted data")
            
            # Check if we have encrypted data but no password
            if not password and not (self.crypto_manager and self.crypto_manager.is_key_set()):
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if len(payload_str) > 20 and payload_str.startswith(('gAAAAA', 'gAAAAAB')):
                        raise ValueError("Data appears to be encrypted but no password provided")
                except:
                    pass
            
            return payload.decode('utf-8')
            
        except ValueError as e:
            # Re-raise password-related errors
            if "Invalid password" in str(e) or "encrypted but no password" in str(e):
                raise e
            self.logger.error(f"Whitespace extraction failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Whitespace extraction failed: {e}")
            return None

    def embed(self, cover_data: str, payload: Union[str, bytes], 
              method: str = 'unicode', **kwargs) -> str:
        """Unified embed method"""
        if method == 'unicode':
            return self.embed_unicode(cover_data, payload, **kwargs)
        elif method == 'whitespace':
            return self.embed_whitespace(cover_data, payload, **kwargs)
        else:
            raise ValueError(f"Unknown method: {method}")

    def extract(self, stego_data: str, method: str = 'unicode', **kwargs) -> Optional[str]:
        """Unified extract method"""
        if method == 'unicode':
            return self.extract_unicode(stego_data, **kwargs)
        elif method == 'whitespace':
            return self.extract_whitespace(stego_data, **kwargs)
        else:
            raise ValueError(f"Unknown method: {method}")

    def get_capacity(self, cover_data: str, method: str = 'unicode', **kwargs) -> int:
        """Calculate capacity for text steganography"""
        if method == 'unicode':
            return len(re.split(r'[.!?]\s+', cover_data)) * 2  # 16 bits per sentence -> 2 bytes
        elif method == 'whitespace':
            return len(cover_data.split('\n'))  # 8 bits per line -> 1 byte
        else:
            return 0
