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
                    char_code = int(byte_str, 2)
                    # Ensure character is in valid range
                    if 0 <= char_code <= 255:
                        b64_payload += chr(char_code)
                    else:
                        self.logger.warning(f"Invalid character code: {char_code}")
                        return None
            
            # Decode base64
            try:
                # Fix base64 padding if needed
                padding_needed = 4 - (len(b64_payload) % 4)
                if padding_needed != 4:  # Only add padding if needed
                    b64_payload += '=' * padding_needed
                
                payload = base64.b64decode(b64_payload.encode('latin-1'))  # Use latin-1 instead of ascii
            except Exception as e:
                self.logger.error(f"Base64 decode failed: {e}")
                return None
            
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
        Embed data using whitespace manipulation - SIMPLE RELIABLE VERSION
        
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
                payload = salt + encrypted_payload
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload = self.crypto_manager.encrypt(payload)
            
            # Use base64 encoding for reliability
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            encoded_payload = base64.b64encode(payload).decode('ascii')
            
            # Convert to binary using simple character mapping
            binary_data = ''
            for char in encoded_payload:
                # Convert each character to 8-bit binary
                binary_data += format(ord(char), '08b')
            
            # Add unique end marker (pattern very unlikely to appear in base64)
            end_marker = '1111000011110000111100001111'  # 28-bit unique pattern
            binary_data += end_marker
            
            print(f"[DEBUG] Whitespace embed: payload_len={len(payload)}, encoded_len={len(encoded_payload)}, binary_len={len(binary_data)}")
            
            # Split into lines and add trailing whitespace
            lines = cover_text.split('\n')
            result_lines = []
            bit_index = 0
            
            for line in lines:
                whitespace = ''
                # Add up to 32 bits per line
                for _ in range(32):
                    if bit_index < len(binary_data):
                        bit = binary_data[bit_index]
                        whitespace += ' ' if bit == '0' else '\t'
                        bit_index += 1
                    else:
                        break
                
                result_lines.append(line + whitespace)
                
                if bit_index >= len(binary_data):
                    break
            
            # Add empty lines if we need more space
            while bit_index < len(binary_data):
                whitespace = ''
                for _ in range(32):
                    if bit_index < len(binary_data):
                        bit = binary_data[bit_index]
                        whitespace += ' ' if bit == '0' else '\t'
                        bit_index += 1
                    else:
                        break
                result_lines.append(whitespace)
            
            # Add remaining lines without changes
            if len(lines) > len(result_lines):
                result_lines.extend(lines[len(result_lines):])
            
            result = '\n'.join(result_lines)
            print(f"[DEBUG] Whitespace embed complete: {len(result)} chars, {len(result_lines)} lines, {bit_index} bits embedded")
            return result
            
        except Exception as e:
            self.logger.error(f"Whitespace embedding failed: {e}")
            return cover_text
    
    def extract_whitespace(self, stego_text: str,
                          password: Optional[str] = None) -> Optional[str]:
        """
        Extract data from whitespace patterns - ROBUST VERSION FOR GUI COMPATIBILITY
        
        Args:
            stego_text: Text containing hidden data
            password: Decryption password
            
        Returns:
            Extracted message or None if failed
        """
        try:
            # Extract binary data from trailing whitespace
            lines = stego_text.split('\n')
            
            # First, let's analyze the whitespace patterns line by line
            line_patterns = []
            for i, line in enumerate(lines):
                content = line.rstrip()
                trailing = line[len(content):]
                
                if trailing:
                    # Convert whitespace to binary
                    pattern = ''
                    for char in trailing:
                        if char == ' ':
                            pattern += '0'
                        elif char == '\t':
                            pattern += '1'
                    line_patterns.append((i+1, len(pattern), pattern))
                    print(f"[DEBUG] Line {i+1}: {len(pattern)} whitespace chars")
            
            # Combine all patterns
            binary_data = ''.join(pattern for _, _, pattern in line_patterns)
            print(f"[DEBUG] Whitespace extract: found {len(binary_data)} bits from {len(lines)} lines")
            
            if not binary_data:
                print("[DEBUG] No whitespace data found")
                return None
            
            # Look for end marker - but first check for common GUI corruption
            end_marker = '1111000011110000111100001111'
            
            # Strategy 1: Check if first line has 33 bits instead of 32 (most common GUI issue)
            # Do this FIRST before trying normal extraction
            if line_patterns and line_patterns[0][1] == 33:
                print("[DEBUG] Detected first line has 33 bits (GUI corruption), trying to fix...")
                
                # Remove the LAST bit from first line (GUI adds at end, not beginning)
                corrected_patterns = []
                for i, (line_num, length, pattern) in enumerate(line_patterns):
                    if i == 0:  # First line
                        corrected_patterns.append(pattern[:-1])  # Remove LAST bit, not first
                    else:
                        corrected_patterns.append(pattern)
                
                corrected_binary = ''.join(corrected_patterns)
                end_pos = corrected_binary.find(end_marker)
                
                if end_pos != -1:
                    payload_binary = corrected_binary[:end_pos]
                    if len(payload_binary) % 8 == 0:
                        print(f"[DEBUG] Fixed by removing last bit from first line")
                        return self._decode_payload(payload_binary, password)
                    else:
                        print(f"[DEBUG] Payload length still not divisible by 8 after first-line fix: {len(payload_binary)}")
                
                # If removing last bit didn't work, try removing first bit as fallback
                corrected_patterns = []
                for i, (line_num, length, pattern) in enumerate(line_patterns):
                    if i == 0:  # First line
                        corrected_patterns.append(pattern[1:])  # Remove first bit
                    else:
                        corrected_patterns.append(pattern)
                
                corrected_binary = ''.join(corrected_patterns)
                end_pos = corrected_binary.find(end_marker)
                
                if end_pos != -1:
                    payload_binary = corrected_binary[:end_pos]
                    if len(payload_binary) % 8 == 0:
                        print(f"[DEBUG] Fixed by removing first bit from first line (fallback)")
                        return self._decode_payload(payload_binary, password)
            
            # Normal case - try finding end marker in original data
            end_pos = binary_data.find(end_marker)
            
            if end_pos != -1:
                payload_binary = binary_data[:end_pos]
                if len(payload_binary) % 8 == 0:
                    print(f"[DEBUG] Payload binary length: {len(payload_binary)} bits")
                    return self._decode_payload(payload_binary, password)
                else:
                    print(f"[DEBUG] Normal extraction: payload length not divisible by 8: {len(payload_binary)}")
            
            # End marker not found or payload length wrong - try more correction strategies
            print(f"[DEBUG] End marker not found directly or payload corrupted")
            
            # Strategy 2: Try removing bits from the beginning (first line corruption)
            for remove_from_start in range(1, 11):
                if len(binary_data) > remove_from_start:
                    truncated_data = binary_data[remove_from_start:]
                    end_pos = truncated_data.find(end_marker)
                    if end_pos != -1:
                        payload_binary = truncated_data[:end_pos]
                        if len(payload_binary) % 8 == 0:
                            print(f"[DEBUG] Found marker by removing {remove_from_start} bits from start")
                            return self._decode_payload(payload_binary, password)
            
            # Strategy 3: Try removing bits from the end (last line corruption)
            for remove_from_end in range(1, 11):
                if len(binary_data) > remove_from_end:
                    truncated_data = binary_data[:-remove_from_end]
                    end_pos = truncated_data.find(end_marker)
                    if end_pos != -1:
                        payload_binary = truncated_data[:end_pos]
                        if len(payload_binary) % 8 == 0:
                            print(f"[DEBUG] Found marker by removing {remove_from_end} bits from end")
                            return self._decode_payload(payload_binary, password)
            
            print("[DEBUG] End marker not found even with error correction")
            return None
            
        except Exception as e:
            self.logger.error(f"Whitespace extraction failed: {e}")
            return None
    
    def _decode_payload(self, payload_binary: str, password: Optional[str] = None) -> Optional[str]:
        """
        Decode binary payload to message
        
        Args:
            payload_binary: Binary string representing the payload
            password: Optional decryption password
            
        Returns:
            Decoded message or None if failed
        """
        try:
            # Ensure payload length is divisible by 8
            if len(payload_binary) % 8 != 0:
                remainder = len(payload_binary) % 8
                print(f"[DEBUG] Binary length not divisible by 8, remainder: {remainder}")
                return None
            
            # Convert binary back to characters (8 bits each)
            encoded_payload = ''
            for i in range(0, len(payload_binary), 8):
                byte_bits = payload_binary[i:i+8]
                char_code = int(byte_bits, 2)
                # Ensure character is valid ASCII range for base64
                if 0 <= char_code <= 127:
                    encoded_payload += chr(char_code)
                else:
                    print(f"[DEBUG] Invalid character code: {char_code} at position {i//8}")
                    return None
            
            print(f"[DEBUG] Reconstructed base64: {encoded_payload[:50]}...")
            
            # Decode from base64
            try:
                payload = base64.b64decode(encoded_payload.encode('ascii'))
            except Exception as e:
                print(f"[DEBUG] Base64 decode failed: {e}")
                return None
            
            # Decrypt if needed
            if password and not self.crypto_manager:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                if len(payload) >= 16:
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
                    return None
            elif self.crypto_manager and self.crypto_manager.is_key_set():
                payload = self.crypto_manager.decrypt(payload)
            
            try:
                result = payload.decode('utf-8')
                print(f"[DEBUG] Final decoded result: {repr(result)}")
                return result
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
            print(f"[DEBUG] Payload decode error: {e}")
            return None
        except Exception as e:
            print(f"[DEBUG] Payload decode error: {e}")
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

    def detect_unicode_steganography(self, text: str) -> bool:
        """
        Detect if text contains Unicode steganography (zero-width characters)
        
        Args:
            text: Text to analyze
            
        Returns:
            True if Unicode steganography detected
        """
        try:
            # Check for zero-width characters
            for char in text:
                if char in self.char_to_bit:
                    return True
            return False
        except Exception:
            return False

    def detect_whitespace_steganography(self, text: str) -> bool:
        """
        Detect if text contains whitespace steganography (trailing whitespace patterns)
        
        Args:
            text: Text to analyze
            
        Returns:
            True if whitespace steganography detected
        """
        try:
            lines = text.split('\n')
            
            # Check if any lines have trailing whitespace
            for line in lines:
                content = line.rstrip()
                trailing = line[len(content):]
                
                if trailing:  # Found trailing whitespace
                    # Check if it contains a pattern (space/tab combination)
                    has_space = ' ' in trailing
                    has_tab = '\t' in trailing
                    
                    # If it has both space and tab, or just tabs, it's likely steganographic
                    if has_tab or (has_space and len(trailing) > 1):
                        return True
            
            return False
        except Exception:
            return False

    def auto_detect_type(self, text: str) -> tuple[str, str]:
        """
        Automatically detect steganography type (detection only, no extraction)
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (detection_type, detection_message)
            detection_type: 'unicode', 'whitespace', 'none', 'error'
            detection_message: Human-readable detection result
        """
        try:
            # Check for Unicode steganography first
            if self.detect_unicode_steganography(text):
                return ('unicode', 'Unicode steganography detected')
            
            # Check for whitespace steganography
            if self.detect_whitespace_steganography(text):
                return ('whitespace', 'Whitespace steganography detected')
            
            # No steganography detected
            return ('none', 'No steganographic content detected')
            
        except Exception as e:
            return ('error', f'Error during detection: {str(e)}')
