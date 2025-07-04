"""
File steganography module for embedding data in various file formats
"""

import os
import hashlib
import shutil
import tempfile
import zipfile
from typing import Optional, Union, Tuple, Dict, Any
from pathlib import Path
import logging
from . import SteganographyBase

class FileSteganography(SteganographyBase):
    """Professional file steganography for various file formats"""
    
    def __init__(self):
        super().__init__()
        self.supported_formats = ['.pdf', '.docx', '.xlsx', '.pptx', '.zip', '.png', '.jpg', '.jpeg']
        
    def get_file_hash(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file for integrity checking
        
        Args:
            file_path: Path to the file
            
        Returns:
            Hex string of the file hash
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
    
    def check_file_integrity(self, original_path: str, modified_path: str) -> Dict[str, Any]:
        """
        Check if a file has been modified by comparing hashes and metadata
        
        Args:
            original_path: Path to original file
            modified_path: Path to potentially modified file
            
        Returns:
            Dictionary with integrity check results
        """
        try:
            result = {
                'files_exist': False,
                'size_changed': False,
                'hash_changed': False,
                'modification_time_changed': False,
                'original_hash': '',
                'modified_hash': '',
                'original_size': 0,
                'modified_size': 0,
                'original_mtime': 0,
                'modified_mtime': 0,
                'likely_modified': False
            }
            
            # Check if files exist
            if not os.path.exists(original_path) or not os.path.exists(modified_path):
                return result
            
            result['files_exist'] = True
            
            # Get file stats
            original_stat = os.stat(original_path)
            modified_stat = os.stat(modified_path)
            
            result['original_size'] = original_stat.st_size
            result['modified_size'] = modified_stat.st_size
            result['original_mtime'] = original_stat.st_mtime
            result['modified_mtime'] = modified_stat.st_mtime
            
            # Check size change
            result['size_changed'] = original_stat.st_size != modified_stat.st_size
            
            # Check modification time change
            result['modification_time_changed'] = original_stat.st_mtime != modified_stat.st_mtime
            
            # Calculate and compare hashes
            result['original_hash'] = self.get_file_hash(original_path)
            result['modified_hash'] = self.get_file_hash(modified_path)
            result['hash_changed'] = result['original_hash'] != result['modified_hash']
            
            # Determine if likely modified
            result['likely_modified'] = result['hash_changed'] or result['size_changed']
            
            return result
            
        except Exception as e:
            self.logger.error(f"File integrity check failed: {e}")
            return result
    
    def embed_in_zip_structure(self, cover_path: str, payload: Union[str, bytes], 
                              output_path: str, password: Optional[str] = None) -> bool:
        """
        Embed data in ZIP-based file formats (DOCX, XLSX, PPTX)
        
        Args:
            cover_path: Path to cover file
            payload: Data to embed
            output_path: Output path for stego file
            password: Optional encryption password
            
        Returns:
            Success status
        """
        try:
            # Prepare payload
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            
            # Encrypt if password provided
            if password:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                payload = crypto.encrypt(payload)
            
            # Create temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract original file
                extract_dir = os.path.join(temp_dir, "extracted")
                os.makedirs(extract_dir)
                
                with zipfile.ZipFile(cover_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                
                # Create hidden payload file
                payload_file = os.path.join(extract_dir, ".stegdata")
                with open(payload_file, 'wb') as f:
                    f.write(payload)
                
                # Recreate the file with hidden data
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_ref:
                    for root, dirs, files in os.walk(extract_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arc_path = os.path.relpath(file_path, extract_dir)
                            zip_ref.write(file_path, arc_path)
                
                self.logger.info(f"Successfully embedded {len(payload)} bytes in ZIP structure")
                return True
                
        except Exception as e:
            self.logger.error(f"ZIP embedding failed: {e}")
            return False
    
    def extract_from_zip_structure(self, stego_path: str, password: Optional[str] = None) -> Optional[bytes]:
        """
        Extract data from ZIP-based file formats
        
        Args:
            stego_path: Path to stego file
            password: Decryption password
            
        Returns:
            Extracted data or None if failed
        """
        try:
            with zipfile.ZipFile(stego_path, 'r') as zip_ref:
                # Check if hidden data file exists
                if ".stegdata" not in zip_ref.namelist():
                    return None
                
                # Extract hidden data
                payload = zip_ref.read(".stegdata")
                
                # Decrypt if password provided
                if password:
                    try:
                        from utils.crypto import CryptoManager
                    except ImportError:
                        from ..utils.crypto import CryptoManager
                    crypto = CryptoManager()
                    crypto.set_password(password)
                    try:
                        payload = crypto.decrypt(payload)
                    except Exception as e:
                        self.logger.error(f"Decryption failed: {e}")
                        raise ValueError("Invalid password or corrupted data")
                
                self.logger.info(f"Successfully extracted {len(payload)} bytes from ZIP structure")
                return payload
                
        except ValueError:
            # Re-raise password errors
            raise
        except Exception as e:
            self.logger.error(f"ZIP extraction failed: {e}")
            return None
    
    def embed_in_pdf(self, cover_path: str, payload: Union[str, bytes], 
                     output_path: str, password: Optional[str] = None) -> bool:
        """
        Embed data in PDF files using metadata/annotation approach
        
        Args:
            cover_path: Path to cover PDF
            payload: Data to embed
            output_path: Output path for stego PDF
            password: Optional encryption password
            
        Returns:
            Success status
        """
        try:
            # For now, use a simple approach - append data to end of PDF
            # This is a basic implementation that can be enhanced
            
            # Prepare payload
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            
            # Encrypt if password provided
            if password:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                payload = crypto.encrypt(payload)
            
            # Copy original PDF
            shutil.copy2(cover_path, output_path)
            
            # Append hidden data with marker
            marker = b"%%STEGDATA%%"
            with open(output_path, 'ab') as f:
                f.write(marker)
                f.write(len(payload).to_bytes(4, 'big'))
                f.write(payload)
                f.write(marker)
            
            self.logger.info(f"Successfully embedded {len(payload)} bytes in PDF")
            return True
            
        except Exception as e:
            self.logger.error(f"PDF embedding failed: {e}")
            return False
    
    def extract_from_pdf(self, stego_path: str, password: Optional[str] = None) -> Optional[bytes]:
        """
        Extract data from PDF files
        
        Args:
            stego_path: Path to stego PDF
            password: Decryption password
            
        Returns:
            Extracted data or None if failed
        """
        try:
            marker = b"%%STEGDATA%%"
            
            with open(stego_path, 'rb') as f:
                content = f.read()
            
            # Find the last occurrence of marker
            last_marker_pos = content.rfind(marker)
            if last_marker_pos == -1:
                return None
            
            # Find the first occurrence of marker (should be before payload)
            first_marker_pos = content.find(marker, last_marker_pos - 1000)  # Search in last 1000 bytes
            if first_marker_pos == -1:
                return None
            
            # Extract payload length and data
            length_pos = first_marker_pos + len(marker)
            payload_length = int.from_bytes(content[length_pos:length_pos + 4], 'big')
            
            payload_start = length_pos + 4
            payload_end = payload_start + payload_length
            payload = content[payload_start:payload_end]
            
            # Decrypt if password provided
            if password:
                try:
                    from utils.crypto import CryptoManager
                except ImportError:
                    from ..utils.crypto import CryptoManager
                crypto = CryptoManager()
                crypto.set_password(password)
                try:
                    payload = crypto.decrypt(payload)
                except Exception as e:
                    self.logger.error(f"Decryption failed: {e}")
                    raise ValueError("Invalid password or corrupted data")
            
            self.logger.info(f"Successfully extracted {len(payload)} bytes from PDF")
            return payload
            
        except ValueError:
            # Re-raise password errors
            raise
        except Exception as e:
            self.logger.error(f"PDF extraction failed: {e}")
            return None
    
    def embed(self, cover_path: str, payload: Union[str, bytes], 
              output_path: str, password: Optional[str] = None) -> bool:
        """
        Unified embed method for different file formats
        
        Args:
            cover_path: Path to cover file
            payload: Data to embed
            output_path: Output path for stego file
            password: Optional encryption password
            
        Returns:
            Success status
        """
        file_ext = Path(cover_path).suffix.lower()
        
        if file_ext == '.pdf':
            return self.embed_in_pdf(cover_path, payload, output_path, password)
        elif file_ext in ['.docx', '.xlsx', '.pptx', '.zip']:
            return self.embed_in_zip_structure(cover_path, payload, output_path, password)
        else:
            self.logger.error(f"Unsupported file format: {file_ext}")
            return False
    
    def extract(self, stego_path: str, password: Optional[str] = None) -> Optional[bytes]:
        """
        Unified extract method for different file formats
        
        Args:
            stego_path: Path to stego file
            password: Decryption password
            
        Returns:
            Extracted data or None if failed
        """
        file_ext = Path(stego_path).suffix.lower()
        
        if file_ext == '.pdf':
            return self.extract_from_pdf(stego_path, password)
        elif file_ext in ['.docx', '.xlsx', '.pptx', '.zip']:
            return self.extract_from_zip_structure(stego_path, password)
        else:
            self.logger.error(f"Unsupported file format: {file_ext}")
            return None
    
    def extract_text(self, stego_path: str, password: Optional[str] = None) -> Optional[str]:
        """
        Extract text data from file
        
        Args:
            stego_path: Path to stego file
            password: Decryption password
            
        Returns:
            Extracted text or None if failed
        """
        try:
            data = self.extract(stego_path, password)
            if data:
                return data.decode('utf-8')
            return None
        except ValueError:
            # Re-raise password errors
            raise
        except Exception as e:
            self.logger.error(f"Text extraction failed: {e}")
            return None
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get comprehensive file information
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with file information
        """
        try:
            stat = os.stat(file_path)
            path_obj = Path(file_path)
            
            return {
                'name': path_obj.name,
                'size': stat.st_size,
                'format': path_obj.suffix.upper()[1:] if path_obj.suffix else 'Unknown',
                'hash': self.get_file_hash(file_path),
                'creation_time': stat.st_ctime,
                'modification_time': stat.st_mtime,
                'access_time': stat.st_atime,
                'is_supported': path_obj.suffix.lower() in self.supported_formats
            }
        except Exception as e:
            self.logger.error(f"Failed to get file info for {file_path}: {e}")
            return {}

    def get_capacity(self, cover_path: str, **kwargs) -> int:
        """
        Get capacity for file steganography
        
        Args:
            cover_path: Path to cover file
            **kwargs: Additional parameters
            
        Returns:
            Estimated capacity in bytes
        """
        try:
            file_ext = Path(cover_path).suffix.lower()
            file_size = os.path.getsize(cover_path)
            
            if file_ext == '.pdf':
                return file_size // 100  # Conservative estimate
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.zip']:
                return file_size // 50   # More generous estimate
            else:
                return 0
        except Exception as e:
            self.logger.error(f"Failed to calculate capacity for {cover_path}: {e}")
            return 0

    def detect_steganography(self, file_path: str) -> bool:
        """
        Detect if a file contains steganographic data
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            True if steganography detected
        """
        try:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.pdf':
                return self._detect_pdf_steganography(file_path)
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.zip']:
                return self._detect_zip_steganography(file_path)
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Steganography detection failed for {file_path}: {e}")
            return False

    def _detect_pdf_steganography(self, file_path: str) -> bool:
        """Detect steganography in PDF files"""
        try:
            marker = b"%%STEGDATA%%"
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Look for our steganography marker
            return marker in content
            
        except Exception:
            return False

    def _detect_zip_steganography(self, file_path: str) -> bool:
        """Detect steganography in ZIP-based files"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Check if hidden data file exists
                return ".stegdata" in zip_ref.namelist()
                
        except Exception:
            return False

    def auto_detect_type(self, file_path: str) -> tuple[str, str]:
        """
        Automatically detect steganography type (detection only, no extraction)
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Tuple of (detection_type, detection_message)
            detection_type: 'pdf', 'zip', 'none', 'unsupported', 'error'
            detection_message: Human-readable detection result
        """
        try:
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext not in self.supported_formats:
                return ('unsupported', f'Unsupported file format: {file_ext}')
            
            if self.detect_steganography(file_path):
                if file_ext == '.pdf':
                    return ('pdf', 'PDF steganography detected')
                elif file_ext in ['.docx', '.xlsx', '.pptx', '.zip']:
                    return ('zip', f'{file_ext.upper()} steganography detected')
            
            # No steganography detected
            return ('none', 'No steganographic content detected')
            
        except Exception as e:
            return ('error', f'Error during detection: {str(e)}')



