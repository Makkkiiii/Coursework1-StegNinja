"""
Main GUI application for the RedTeam Steganography Toolkit.
"""

import sys
import os
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QSplitter, QTextEdit, QLabel, QPushButton, QFileDialog,
    QMessageBox, QProgressBar, QStatusBar, QGroupBox, QFormLayout,
    QLineEdit, QCheckBox, QComboBox, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QPixmap, QFont, QIcon

# Add the project root to the path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from src.core.image_stego import ImageSteganography
from src.core.text_stego import TextSteganography
from src.core.file_stego import FileSteganography
from src.utils.crypto import CryptoManager


class WorkerThread(QThread):
    """Background worker thread for steganography operations."""
    
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, operation: str, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        """Execute the steganography operation."""
        try:
            if self.operation == "embed_image":
                self._embed_image()
            elif self.operation == "extract_image":
                self._extract_image()
            elif self.operation == "embed_text":
                self._embed_text()
            elif self.operation == "extract_text":
                self._extract_text()
            elif self.operation == "embed_file":
                self._embed_file()
            elif self.operation == "extract_file":
                self._extract_file()
            elif self.operation == "check_integrity":
                self._check_integrity()
            elif self.operation == "analyze":
                self._analyze() # type: ignore
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _embed_image(self):
        image_stego = ImageSteganography()
        crypto = self.kwargs.get('crypto')
        password = self.kwargs.get('password')
        # strip_metadata = self.kwargs.get('strip_metadata', True)  # Removed - not working properly
        preserve_timestamps = self.kwargs.get('preserve_timestamps', True)
        
        if crypto and crypto.is_key_set():
            image_stego.set_crypto_manager(crypto)
        
        result = image_stego.embed(
            self.kwargs['image_path'],
            self.kwargs['message'],
            self.kwargs['output_path'],
            password=password,
            # strip_metadata=strip_metadata,  # Removed
            preserve_timestamps=preserve_timestamps
        )
        
        if result:
            # Include output path in success message for comparison display
            output_path = self.kwargs['output_path']
            self.finished.emit(True, f"EMBED_SUCCESS:{output_path}")
        else:
            self.finished.emit(False, "Failed to embed message.")
    
    def _extract_image(self):
        image_stego = ImageSteganography()
        crypto = self.kwargs.get('crypto')
        password = self.kwargs.get('password')
        
        try:
            # If we have a password, use it directly instead of crypto manager
            if password:
                message = image_stego.extract_text(self.kwargs['image_path'], password=password)
            elif crypto and crypto.is_key_set():
                image_stego.set_crypto_manager(crypto)
                message = image_stego.extract_text(self.kwargs['image_path'])
            else:
                message = image_stego.extract_text(self.kwargs['image_path'])
            
            if message:
                self.finished.emit(True, f"Extracted message: {message}")
            else:
                self.finished.emit(False, "No message found or extraction failed.")
        except ValueError as e:
            if "Invalid password" in str(e):
                self.finished.emit(False, "Invalid password or corrupted data")
            elif "no password provided" in str(e):
                self.finished.emit(False, "Data appears to be encrypted but no password provided")
            else:
                self.finished.emit(False, f"Extraction failed: {str(e)}")
        except Exception as e:
            self.finished.emit(False, f"Extraction failed: {str(e)}")
    
    def _embed_text(self):
        text_stego = TextSteganography()
        crypto = self.kwargs.get('crypto')
        method = self.kwargs.get('method', 'unicode')
        
        # Extract password from crypto manager if available
        password = None
        if crypto and crypto.is_key_set():
            # For text stego, we pass the password directly, not the crypto manager
            password = self.kwargs.get('password')
        
        result = text_stego.embed(
            self.kwargs['cover_text'],
            self.kwargs['secret_message'],
            method=method,
            password=password
        )
        
        if result and result != self.kwargs['cover_text']:
            self.finished.emit(True, f"STEGO_TEXT:{result}")
        else:
            self.finished.emit(False, "Failed to embed message in text.")
    
    def _extract_text(self):
        text_stego = TextSteganography()
        crypto = self.kwargs.get('crypto')
        method = self.kwargs.get('method', 'unicode')
        
        # Extract password from crypto manager if available
        password = None
        if crypto and crypto.is_key_set():
            # For text stego, we pass the password directly, not the crypto manager
            password = self.kwargs.get('password')
        
        try:
            message = text_stego.extract(self.kwargs['stego_text'], method=method, password=password)
            
            if message:
                self.finished.emit(True, f"Extracted message: {message}")
            else:
                self.finished.emit(False, "No hidden message found.")
        except ValueError as e:
            if "Invalid password" in str(e):
                self.finished.emit(False, "Invalid password or corrupted data")
            elif "no password provided" in str(e):
                self.finished.emit(False, "Data appears to be encrypted but no password provided")
            else:
                self.finished.emit(False, f"Extraction failed: {str(e)}")
        except Exception as e:
            self.finished.emit(False, f"Extraction failed: {str(e)}")
    
    def _embed_file(self):
        """Embed data in file using file steganography"""
        file_stego = FileSteganography()
        password = self.kwargs.get('password')
        
        result = file_stego.embed(
            self.kwargs['cover_path'],
            self.kwargs['payload'],
            self.kwargs['output_path'],
            password=password
        )
        
        if result:
            self.finished.emit(True, f"Successfully embedded data in file: {self.kwargs['output_path']}")
        else:
            self.finished.emit(False, "Failed to embed data in file.")
    
    def _extract_file(self):
        """Extract data from file using file steganography"""
        file_stego = FileSteganography()
        password = self.kwargs.get('password')
        
        try:
            message = file_stego.extract_text(self.kwargs['file_path'], password=password)
            
            if message:
                self.finished.emit(True, f"Extracted message: {message}")
            else:
                self.finished.emit(False, "No hidden message found.")
        except ValueError as e:
            if "Invalid password" in str(e):
                self.finished.emit(False, "Invalid password or corrupted data")
            elif "no password provided" in str(e):
                self.finished.emit(False, "Data appears to be encrypted but no password provided")
            else:
                self.finished.emit(False, f"Extraction failed: {str(e)}")
        except Exception as e:
            self.finished.emit(False, f"Extraction failed: {str(e)}")
    
    def _check_integrity(self):
        """Check file integrity between two files"""
        file_stego = FileSteganography()
        
        try:
            result = file_stego.check_file_integrity(
                self.kwargs['original_path'],
                self.kwargs['modified_path']
            )
            
            if result['files_exist']:
                integrity_info = {
                    'size_changed': result['size_changed'],
                    'hash_changed': result['hash_changed'],
                    'modification_time_changed': result['modification_time_changed'],
                    'likely_modified': result['likely_modified'],
                    'original_size': result['original_size'],
                    'modified_size': result['modified_size'],
                    'original_hash': result['original_hash'],  # Show complete hash
                    'modified_hash': result['modified_hash']   # Show complete hash
                }
                self.finished.emit(True, f"INTEGRITY_CHECK:{integrity_info}")
            else:
                self.finished.emit(False, "One or both files do not exist.")
        except Exception as e:
            self.finished.emit(False, f"Integrity check failed: {str(e)}")

class ImageSteganographyTab(QWidget):
    """Tab for image steganography operations."""
    
    def __init__(self, crypto_manager: CryptoManager):
        super().__init__()
        self.crypto_manager = crypto_manager
        self.current_image_path = ""
        self.worker_thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI for image steganography."""
        layout = QVBoxLayout()
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal) # type: ignore
        
        # Left panel - Controls
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Image preview
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def _create_left_panel(self) -> QWidget:
        """Create the left control panel."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("Image Selection")
        file_layout = QFormLayout()
        
        self.image_path_label = QLabel("No image selected")
        self.image_path_label.setWordWrap(True)
        
        select_btn = QPushButton("Select Image")
        select_btn.clicked.connect(self.select_image)
        
        file_layout.addRow("Current Image:", self.image_path_label)
        file_layout.addRow("", select_btn)
        file_group.setLayout(file_layout)
        
        # Message input
        message_group = QGroupBox("Message")
        message_layout = QVBoxLayout()
        
        self.message_text = QTextEdit()
        self.message_text.setMaximumHeight(150)
        self.message_text.setPlaceholderText("Enter your secret message here...")
        
        message_layout.addWidget(self.message_text)
        message_group.setLayout(message_layout)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QFormLayout()
        
        self.use_encryption = QCheckBox("Use Encryption")
        self.use_encryption.stateChanged.connect(self.toggle_encryption)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setEnabled(False)
        self.password_input.setPlaceholderText("Enter encryption password")
        
        # Metadata options (removed - metadata extraction not working properly)
        # self.strip_metadata = QCheckBox("Strip EXIF Metadata")
        # self.strip_metadata.setChecked(True)
        # self.strip_metadata.setToolTip("Remove EXIF metadata from output image for security")
        
        self.preserve_timestamps = QCheckBox("Preserve Timestamps")
        self.preserve_timestamps.setChecked(True)
        self.preserve_timestamps.setToolTip("Keep original file timestamps for stealth")
        
        options_layout.addRow("Security:", self.use_encryption)
        options_layout.addRow("Password:", self.password_input)
        # options_layout.addRow("Metadata:", self.strip_metadata)  # Removed
        options_layout.addRow("Timestamps:", self.preserve_timestamps)
        options_group.setLayout(options_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.embed_btn = QPushButton("Embed Message")
        self.embed_btn.clicked.connect(self.embed_message)
        
        self.extract_btn = QPushButton("Extract Message")
        self.extract_btn.clicked.connect(self.extract_message)
        
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.clicked.connect(self.clear_all)
        self.clear_btn.setObjectName("clearButton")
        self.clear_btn.setStyleSheet("""
            QPushButton#clearButton {
                background-color: #dc3545;
                color: white;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
                border-radius: 3px;
            }
            QPushButton#clearButton:hover {
                background-color: #8b0000;
            }
            QPushButton#clearButton:pressed {
                background-color: #660000;
            }
        """)
        
        button_layout.addWidget(self.embed_btn)
        button_layout.addWidget(self.extract_btn)
        button_layout.addWidget(self.clear_btn)
        
        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(150)
        self.results_text.setReadOnly(True)
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        
        # Add all to layout
        layout.addWidget(file_group)
        layout.addWidget(message_group)
        layout.addWidget(options_group)
        layout.addLayout(button_layout)
        layout.addWidget(results_group)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _create_right_panel(self) -> QWidget:
        """Create the right image preview panel with before/after comparison."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Comparison group
        comparison_group = QGroupBox("Before/After Comparison")
        comparison_layout = QHBoxLayout()

        # Before image
        self.before_image_label = QLabel("Original")
        self.before_image_label.setAlignment(Qt.AlignCenter) # type: ignore
        self.before_image_label.setScaledContents(True)
        self.before_image_label.setStyleSheet("border: 1px solid #aaa;")
        comparison_layout.addWidget(self.before_image_label)

        # After image
        self.after_image_label = QLabel("Stego")
        self.after_image_label.setAlignment(Qt.AlignCenter) # type: ignore
        self.after_image_label.setScaledContents(True)
        self.after_image_label.setStyleSheet("border: 1px solid #aaa;")
        comparison_layout.addWidget(self.after_image_label)

        comparison_group.setLayout(comparison_layout)
        layout.addWidget(comparison_group)

        # Image info
        info_group = QGroupBox("Image Information")
        info_layout = QVBoxLayout()
        
        # Basic info
        basic_info_layout = QFormLayout()
        self.info_dimensions = QLabel("")
        self.info_format = QLabel("")
        self.info_quality = QLabel("")
        # Enable word wrap and set minimum height for multi-line quality display
        self.info_quality.setWordWrap(True)
        self.info_quality.setMinimumHeight(80)  # Enough for 4-5 lines
        self.info_quality.setAlignment(Qt.AlignTop)  # type: ignore # Align to top
        basic_info_layout.addRow("Dimensions:", self.info_dimensions)
        basic_info_layout.addRow("Format:", self.info_format)
        basic_info_layout.addRow("Steganography Quality:", self.info_quality)
        info_layout.addLayout(basic_info_layout)
        
        # Increase maximum height to accommodate multi-line quality display
        info_group.setMaximumHeight(180)
        
        # Metadata section removed - not working properly

        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Add stretch to push content to top and eliminate empty space
        layout.addStretch()

        widget.setLayout(layout)
        return widget
    
    def select_image(self):
        """Open file dialog to select an image."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "",
            "Image files (*.png *.jpg *.jpeg *.bmp *.tiff);;All files (*.*)"
        )
        
        if file_path:
            self.current_image_path = file_path
            self.image_path_label.setText(os.path.basename(file_path))
            self.load_image_preview(file_path)
    
    def load_image_preview(self, file_path: str):
        """Load and display image preview in both before/after labels."""
        try:
            # Load with PIL to get proper format info
            from PIL import Image as PILImage
            pil_image = PILImage.open(file_path)
            image_format = pil_image.format or "Unknown"
            
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(300, 225, Qt.KeepAspectRatio, Qt.SmoothTransformation) # type: ignore
                self.before_image_label.setPixmap(scaled_pixmap)
                self.info_dimensions.setText(f"{pixmap.width()} x {pixmap.height()}")
                self.info_format.setText(image_format)

        except Exception as e:
            self.before_image_label.setText(f"Error: {str(e)}")

    def load_stego_image_preview(self, file_path: str):
        """Load and display stego image in after label and show comparison metrics."""
        try:
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(300, 225, Qt.KeepAspectRatio, Qt.SmoothTransformation) # type: ignore
                self.after_image_label.setPixmap(scaled_pixmap)
                
            # Show comparison metrics
            from src.core.image_stego import ImageSteganography
            metrics = ImageSteganography().get_image_comparison_metrics(self.current_image_path, file_path)
            if metrics:
                # Convert technical metrics to user-friendly descriptions
                quality_description = self.get_quality_description(metrics)
                self.info_quality.setText(quality_description)
                self.info_quality.setStyleSheet("color: #28a745; font-weight: bold; padding: 5px; border-radius: 3px;")  # Green styling
                
                # Clear any tooltips since we display metrics directly
                self.info_quality.setToolTip("")
            else:
                self.info_quality.setText("Unable to analyze quality")
                self.info_quality.setStyleSheet("color: #6c757d;")  # Gray for unknown
        except Exception as e:
            self.after_image_label.setText(f"Error: {str(e)}")
    
    def get_quality_description(self, metrics: dict) -> str:
        """Convert technical metrics to user-friendly quality description with technical details."""
        mse = metrics.get('mse', 0)
        psnr = metrics.get('psnr', 0)
        ssim = metrics.get('ssim', 0)
        
        # Determine overall quality based on metrics
        if psnr >= 50 and ssim >= 0.99:
            quality = "🟢 EXCELLENT - Virtually undetectable"
            details = "Hidden data is completely invisible to the naked eye"
        elif psnr >= 40 and ssim >= 0.95:
            quality = "🟡 VERY GOOD - Barely noticeable"
            details = "Hidden data causes minimal visual changes"
        elif psnr >= 30 and ssim >= 0.90:
            quality = "🟠 GOOD - Slight differences"
            details = "Minor visual changes may be visible on close inspection"
        elif psnr >= 20 and ssim >= 0.80:
            quality = "🔴 FAIR - Noticeable changes"
            details = "Visual differences are apparent but acceptable"
        else:
            quality = "🔴 POOR - Significant changes"
            details = "Hidden data causes obvious visual degradation"
        
        # Add simple quality metrics in plain English
        noise_level = "Very Low" if mse < 1 else "Low" if mse < 5 else "Medium" if mse < 15 else "High"
        image_quality = "Excellent" if psnr >= 40 else "Good" if psnr >= 30 else "Fair" if psnr >= 20 else "Poor"
        similarity = "Nearly Identical" if ssim >= 0.95 else "Very Similar" if ssim >= 0.90 else "Similar" if ssim >= 0.80 else "Different"
        
        simple_metrics = f"Quality: {image_quality} | Noise: {noise_level} | Similarity: {similarity}"
        
        return f"{quality}\n{details}\n\n{simple_metrics}"
    
    def toggle_encryption(self, state):
        """Toggle encryption password input."""
        self.password_input.setEnabled(state == Qt.CheckState.Checked) # type: ignore
        if state != Qt.Checked: # type: ignore
            self.password_input.clear()
    
    def embed_message(self):
        """Embed message into image."""
        if not self.current_image_path:
            QMessageBox.warning(self, "Warning", "Please select an image first.")
            return
        
        message = self.message_text.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to embed.")
            return
        
        # Get output path
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Steganographic Image", "",
            "PNG files (*.png);;JPEG files (*.jpg);;BMP files (*.bmp);;TIFF files (*.tiff);;All files (*.*)"
        )
        
        if not output_path:
            return
        
        # Setup encryption if needed
        crypto = None
        password = None
        if self.use_encryption.isChecked():
            password = self.password_input.text().strip()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter an encryption password.")
                return
            
            crypto = CryptoManager()
            crypto.set_password(password)
        
        # Start background operation
        self.start_operation("embed_image", {
            'image_path': self.current_image_path,
            'message': message,
            'output_path': output_path,
            'crypto': crypto,
            'password': password,
            # 'strip_metadata': self.strip_metadata.isChecked(),  # Removed
            'preserve_timestamps': self.preserve_timestamps.isChecked()
        })
    
    def extract_message(self):
        """Extract message from image."""
        if not self.current_image_path:
            QMessageBox.warning(self, "Warning", "Please select an image first.")
            return
        
        # Setup encryption if needed
        crypto = None
        password = None
        if self.use_encryption.isChecked():
            password = self.password_input.text().strip()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter the decryption password.")
                return
            
            crypto = CryptoManager()
            crypto.set_password(password)
        
        # Start background operation
        self.start_operation("extract_image", {
            'image_path': self.current_image_path,
            'crypto': crypto,
            'password': password
        })
    
    def start_operation(self, operation: str, kwargs: Dict[str, Any]):
        """Start a background steganography operation."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.embed_btn.setEnabled(False)
        self.extract_btn.setEnabled(False)
        
        self.worker_thread = WorkerThread(operation, **kwargs)
        self.worker_thread.finished.connect(self.operation_finished)
        self.worker_thread.start()
    
    def operation_finished(self, success: bool, message: str):
        """Handle completion of background operation."""
        self.progress_bar.setVisible(False)
        self.embed_btn.setEnabled(True)
        self.extract_btn.setEnabled(True)
        
        if success:
            if message.startswith("Extracted message:"):
                # Show extracted message in red formatting
                extracted_msg = message[18:].strip()  # Remove "Extracted message: " prefix
                self.results_text.append(f'<span style="color: #dc3545; font-weight: bold;">🔍 EXTRACTED MESSAGE: {extracted_msg}</span>')
            elif message.startswith("EMBED_SUCCESS:"):
                # Show embedded message and load comparison
                output_path = message[14:]  # Remove "EMBED_SUCCESS:" prefix
                self.results_text.append(f'<span style="color: #28a745; font-weight: bold;">✓ Message embedded successfully!</span>')
                self.load_stego_image_preview(output_path)
            else:
                self.results_text.append(f'<span style="color: #28a745; font-weight: bold;">✓ {message}</span>')
        else:
            self.results_text.append(f'<span style="color: #dc3545; font-weight: bold;">✗ {message}</span>')
        
        self.worker_thread = None
    
    def clear_all(self):
        """Clear all input fields and reset the interface."""
        self.message_text.clear()
        self.password_input.clear()
        self.results_text.clear()
        self.use_encryption.setChecked(False)
        # self.strip_metadata.setChecked(True)  # Removed
        self.preserve_timestamps.setChecked(True)
        
        # Clear image previews
        self.before_image_label.clear()
        self.before_image_label.setText("Original")
        self.after_image_label.clear()
        self.after_image_label.setText("Stego")
        
        # Clear metadata displays - removed (not working properly)
        # self.before_metadata_text.clear()
        # self.after_metadata_text.clear()
        
        # Reset image info
        self.info_dimensions.setText("")
        self.info_format.setText("")
        self.info_quality.setText("")
        
        # Reset image path
        self.current_image_path = ""
        
        # Update status
        self.results_text.append('<span style="color: #6c757d; font-style: italic;">Interface cleared</span>')


class TextSteganographyTab(QWidget):
    """Tab for text steganography operations."""
    
    def __init__(self, crypto_manager: CryptoManager):
        super().__init__()
        self.crypto_manager = crypto_manager
        self.worker_thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI for text steganography."""
        layout = QVBoxLayout()
        
        # Main splitter
        splitter = QSplitter(Qt.Vertical) # type: ignore
        
        # Top panel - Input
        top_panel = self._create_top_panel()
        splitter.addWidget(top_panel)
        
        # Bottom panel - Output
        bottom_panel = self._create_bottom_panel()
        splitter.addWidget(bottom_panel)
        
        # Set splitter proportions
        splitter.setSizes([400, 400])
        
        layout.addWidget(splitter)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def _create_top_panel(self) -> QWidget:
        """Create the top input panel."""
        widget = QWidget()
        layout = QHBoxLayout()
        
        # Cover text input
        cover_group = QGroupBox("Cover Text")
        cover_layout = QVBoxLayout()
        
        self.cover_text = QTextEdit()
        self.cover_text.setPlaceholderText("Enter or paste the cover text here...")
        
        # Load buttons layout
        load_btn_layout = QHBoxLayout()
        
        load_cover_btn = QPushButton("Load Cover Text")
        load_cover_btn.clicked.connect(self.load_cover_text)
        
        load_stego_btn = QPushButton("Load Steganographic Text")
        load_stego_btn.clicked.connect(self.load_steganographic_text)
        
        load_btn_layout.addWidget(load_cover_btn)
        load_btn_layout.addWidget(load_stego_btn)
        
        # Method selection
        method_group = QGroupBox("Steganography Method")
        method_layout = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Unicode (Invisible)", "Whitespace"])
        self.method_combo.setToolTip("Choose the text steganography method")
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_combo)
        method_group.setLayout(method_layout)
        cover_layout.addWidget(method_group)
        
        cover_layout.addWidget(self.cover_text)
        cover_layout.addLayout(load_btn_layout)
        cover_group.setLayout(cover_layout)
        
        # Secret message input
        secret_group = QGroupBox("Secret Message")
        secret_layout = QVBoxLayout()
        
        self.secret_text = QTextEdit()
        self.secret_text.setPlaceholderText("Enter your secret message here...")
        self.secret_text.setMaximumHeight(150)
        
        # Options
        options_layout = QFormLayout()
        
        self.use_encryption_text = QCheckBox("Use Encryption")
        self.use_encryption_text.stateChanged.connect(self.toggle_text_encryption)
        
        self.password_text = QLineEdit()
        self.password_text.setEchoMode(QLineEdit.Password)
        self.password_text.setEnabled(False)
        self.password_text.setPlaceholderText("Enter encryption password")
        
        options_layout.addRow("Encryption:", self.use_encryption_text)
        options_layout.addRow("Password:", self.password_text)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.embed_text_btn = QPushButton("Embed in Text")
        self.embed_text_btn.clicked.connect(self.embed_in_text)
        
        self.extract_text_btn = QPushButton("Extract from Text")
        self.extract_text_btn.clicked.connect(self.extract_from_text)
        
        self.clear_all_btn = QPushButton("Clear All")
        self.clear_all_btn.clicked.connect(self.clear_all_text)
        self.clear_all_btn.setObjectName("clearButtonText")
        self.clear_all_btn.setStyleSheet("""
            QPushButton#clearButtonText {
                background-color: #dc3545;
                color: white;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
                border-radius: 3px;
            }
            QPushButton#clearButtonText:hover {
                background-color: #8b0000;
            }
            QPushButton#clearButtonText:pressed {
                background-color: #660000;
            }
        """)
        
        button_layout.addWidget(self.embed_text_btn)
        button_layout.addWidget(self.extract_text_btn)
        button_layout.addWidget(self.clear_all_btn)
        
        secret_layout.addWidget(self.secret_text)
        secret_layout.addLayout(options_layout)
        secret_layout.addLayout(button_layout)
        secret_group.setLayout(secret_layout)
        
        layout.addWidget(cover_group)
        layout.addWidget(secret_group)
        
        widget.setLayout(layout)
        return widget
    
    def _create_bottom_panel(self) -> QWidget:
        """Create the bottom output panel."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Output text
        output_group = QGroupBox("Output / Results")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        # Output buttons
        output_btn_layout = QHBoxLayout()
        
        load_output_btn = QPushButton("Load Text")
        load_output_btn.clicked.connect(self.load_output_text)
        
        save_btn = QPushButton("Save to File")
        save_btn.clicked.connect(self.save_output)
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_output)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_output)
        
        output_btn_layout.addWidget(load_output_btn)
        output_btn_layout.addWidget(save_btn)
        output_btn_layout.addWidget(copy_btn)
        output_btn_layout.addWidget(clear_btn)
        output_btn_layout.addStretch()
        
        output_layout.addWidget(self.output_text)
        output_layout.addLayout(output_btn_layout)
        output_group.setLayout(output_layout)
        
        # Results display
        results_group = QGroupBox("Status & Messages")
        results_layout = QVBoxLayout()
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setMaximumHeight(100)
        self.results_display.setPlaceholderText("Status messages will appear here...")
        
        results_layout.addWidget(self.results_display)
        results_group.setLayout(results_layout)
        
        layout.addWidget(output_group)
        layout.addWidget(results_group)
        
        widget.setLayout(layout)
        return widget
    
    def load_cover_text(self):
        """Load cover text from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Cover Text", "",
            "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.cover_text.setPlainText(f.read())
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
    
    def load_steganographic_text(self):
        """Load steganographic text from file for extraction."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Steganographic Text", "",
            "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    self.cover_text.setPlainText(content)
                    # Show a hint to the user
                    self.results_display.append("📂 Steganographic text loaded. Use 'Extract from Text' to reveal hidden message.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
    
    def toggle_text_encryption(self, state):
        """Toggle encryption password input for text."""
        self.password_text.setEnabled(state == Qt.Checked) # type: ignore
        if state != Qt.Checked: # type: ignore
            self.password_text.clear()
    
    def embed_in_text(self):
        """Embed secret message in cover text."""
        cover_text = self.cover_text.toPlainText().strip()
        secret_text = self.secret_text.toPlainText().strip()
        
        if not cover_text:
            QMessageBox.warning(self, "Warning", "Please enter cover text.")
            return
        
        if not secret_text:
            QMessageBox.warning(self, "Warning", "Please enter a secret message.")
            return
        
        # Setup encryption if needed
        crypto = None
        password = None
        if self.use_encryption_text.isChecked():
            password = self.password_text.text().strip()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter an encryption password.")
                return
            
            crypto = CryptoManager()
            crypto.set_password(password)
        
        # Get selected method
        method_map = {
            "Unicode (Invisible)": "unicode",
            "Whitespace": "whitespace"
        }
        method = method_map.get(self.method_combo.currentText(), "unicode")
        
        # Start background operation
        self.start_text_operation("embed_text", {
            'cover_text': cover_text,
            'secret_message': secret_text,
            'method': method,
            'crypto': crypto,
            'password': password
        })
    
    def extract_from_text(self):
        """Extract secret message from text."""
        stego_text = self.cover_text.toPlainText().strip()
        
        if not stego_text:
            QMessageBox.warning(self, "Warning", "Please enter text to extract from.")
            return
        
        # Setup encryption if needed
        crypto = None
        password = None
        if self.use_encryption_text.isChecked():
            password = self.password_text.text().strip()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter the decryption password.")
                return
            
            crypto = CryptoManager()
            crypto.set_password(password)
        
        # Get selected method
        method_map = {
            "Unicode (Invisible)": "unicode",
            "Whitespace": "whitespace"
        }
        method = method_map.get(self.method_combo.currentText(), "unicode")
        
        # Start background operation
        self.start_text_operation("extract_text", {
            'stego_text': stego_text,
            'method': method,
            'crypto': crypto,
            'password': password
        })
    
    def start_text_operation(self, operation: str, kwargs: Dict[str, Any]):
        """Start a background text steganography operation."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.embed_text_btn.setEnabled(False)
        self.extract_text_btn.setEnabled(False)
        
        self.worker_thread = WorkerThread(operation, **kwargs)
        self.worker_thread.finished.connect(self.text_operation_finished)
        self.worker_thread.start()
    
    def text_operation_finished(self, success: bool, message: str):
        """Handle completion of background text operation."""
        self.progress_bar.setVisible(False)
        self.embed_text_btn.setEnabled(True)
        self.extract_text_btn.setEnabled(True)
        
        if success:
            if message.startswith("STEGO_TEXT:"):
                # Extract the steganographic text and put it directly in output
                stego_text = message[11:]  # Remove "STEGO_TEXT:" prefix
                self.output_text.clear()  # Clear previous content
                self.output_text.setPlainText(stego_text)  # Set only the steganographic text
                
                # Show success message in results area briefly
                self.results_display.append('<span style="color: #28a745; font-weight: bold;">✓ Text steganography completed successfully!</span>')
                self.results_display.append('<span style="color: #007bff; font-weight: bold;">📋 Steganographic text ready for copying/saving</span>')
            elif message.startswith("Extracted message:"):
                # Show extracted message in red formatting
                extracted_msg = message[18:].strip()  # Remove "Extracted message: " prefix
                self.output_text.clear()  # Clear previous content
                self.results_display.append(f'<span style="color: #dc3545; font-weight: bold;">🔍 EXTRACTED MESSAGE: {extracted_msg}</span>')
            else:
                self.output_text.append(f'<span style="color: #28a745; font-weight: bold;">✓ {message}</span>')
        else:
            self.output_text.append(f'<span style="color: #dc3545; font-weight: bold;">✗ {message}</span>')
        
        self.worker_thread = None
    
    def load_output_text(self):
        """Load text into the output area."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Text", "",
            "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    self.output_text.setPlainText(content)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")
    
    def save_output(self):
        """Save output to file."""
        content = self.output_text.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "Warning", "No content to save.")
            return
        
        # Suggest a default filename
        default_name = "steganographic_text.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Steganographic Text", default_name,
            "Text files (*.txt);;All files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                QMessageBox.information(self, "Success", "Steganographic text saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
    
    def copy_output(self):
        """Copy output to clipboard."""
        content = self.output_text.toPlainText().strip()
        if content:
            QApplication.clipboard().setText(content) # type: ignore
            # Brief status message
            self.results_display.append("📋 Steganographic text copied to clipboard!")
        else:
            QMessageBox.warning(self, "Warning", "No content to copy.")
    
    def clear_output(self):
        """Clear output text."""
        self.output_text.clear()
    
    def clear_all_text(self):
        """Clear all text steganography input fields and reset the interface."""
        self.cover_text.clear()
        self.secret_text.clear()
        self.password_text.clear()
        self.output_text.clear()
        self.results_display.clear()
        self.use_encryption_text.setChecked(False)
        self.method_combo.setCurrentIndex(0)
        
        # Update status
        self.results_display.append('<span style="color: #6c757d; font-style: italic;">Text interface cleared</span>')

    # Removed duplicate clear_output method


class FileSteganographyTab(QWidget):
    """Tab for file steganography operations."""
    
    def __init__(self, crypto_manager: CryptoManager):
        super().__init__()
        self.crypto_manager = crypto_manager
        self.current_file_path = ""
        self.worker_thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI for file steganography."""
        layout = QVBoxLayout()
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - controls
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - results and integrity check
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set initial splitter sizes
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def _create_left_panel(self) -> QWidget:
        """Create the left control panel."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # File selection
        file_group = QGroupBox("File Selection")
        file_layout = QFormLayout()
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setWordWrap(True)
        
        select_btn = QPushButton("Select File")
        select_btn.clicked.connect(self.select_file)
        
        file_layout.addRow("Current File:", self.file_path_label)
        file_layout.addRow("", select_btn)
        file_group.setLayout(file_layout)
        
        # Message input
        message_group = QGroupBox("Message")
        message_layout = QVBoxLayout()
        
        self.message_text = QTextEdit()
        self.message_text.setMaximumHeight(150)
        self.message_text.setPlaceholderText("Enter your secret message here...")
        
        message_layout.addWidget(self.message_text)
        message_group.setLayout(message_layout)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QFormLayout()
        
        self.use_encryption = QCheckBox("Use Encryption")
        self.use_encryption.stateChanged.connect(self.toggle_encryption)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setEnabled(False)
        self.password_input.setPlaceholderText("Enter encryption password")
        
        options_layout.addRow("Encryption:", self.use_encryption)
        options_layout.addRow("Password:", self.password_input)
        options_group.setLayout(options_layout)
        
        # Embed/Extract buttons
        button_group = QGroupBox("Operations")
        button_layout = QVBoxLayout()
        
        self.embed_btn = QPushButton("Embed Message")
        self.embed_btn.clicked.connect(self.embed_message)
        
        self.extract_btn = QPushButton("Extract Message")
        self.extract_btn.clicked.connect(self.extract_message)
        
        button_layout.addWidget(self.embed_btn)
        button_layout.addWidget(self.extract_btn)
        button_group.setLayout(button_layout)
        
        # Clear button
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_all)
        clear_btn.setObjectName("clearButtonFile")
        clear_btn.setStyleSheet("""
            QPushButton#clearButtonFile {
                background-color: #dc3545;
                color: white;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
                border-radius: 3px;
            }
            QPushButton#clearButtonFile:hover {
                background-color: #8b0000;
            }
            QPushButton#clearButtonFile:pressed {
                background-color: #660000;
            }
        """)
        
        # Add groups to layout
        layout.addWidget(file_group)
        layout.addWidget(message_group)
        layout.addWidget(options_group)
        layout.addWidget(button_group)
        layout.addWidget(clear_btn)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def _create_right_panel(self) -> QWidget:
        """Create the right results panel."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Results display
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setMaximumHeight(200)
        
        results_layout.addWidget(self.results_display)
        results_group.setLayout(results_layout)
        
        # File integrity check section
        integrity_group = QGroupBox("File Integrity Check")
        integrity_layout = QVBoxLayout()
        
        # File selection for integrity check
        file_select_layout = QHBoxLayout()
        
        self.original_file_label = QLabel("No original file selected")
        self.original_file_label.setWordWrap(True)
        select_original_btn = QPushButton("Select Original")
        select_original_btn.clicked.connect(self.select_original_file)
        
        file_select_layout.addWidget(QLabel("Original:"))
        file_select_layout.addWidget(self.original_file_label)
        file_select_layout.addWidget(select_original_btn)
        
        file_select_layout2 = QHBoxLayout()
        
        self.modified_file_label = QLabel("No modified file selected")
        self.modified_file_label.setWordWrap(True)
        select_modified_btn = QPushButton("Select Modified")
        select_modified_btn.clicked.connect(self.select_modified_file)
        
        file_select_layout2.addWidget(QLabel("Modified:"))
        file_select_layout2.addWidget(self.modified_file_label)
        file_select_layout2.addWidget(select_modified_btn)
        
        check_integrity_btn = QPushButton("Check Integrity")
        check_integrity_btn.clicked.connect(self.check_integrity)
        
        self.integrity_results = QTextEdit()
        self.integrity_results.setReadOnly(True)
        self.integrity_results.setMaximumHeight(250)  # Reasonable height for display
        self.integrity_results.setLineWrapMode(QTextEdit.NoWrap)  # Prevent line wrapping
        self.integrity_results.setStyleSheet("font-family: monospace; font-size: 9pt;")  # Use monospace font
        
        integrity_layout.addLayout(file_select_layout)
        integrity_layout.addLayout(file_select_layout2)
        integrity_layout.addWidget(check_integrity_btn)
        integrity_layout.addWidget(self.integrity_results)
        integrity_group.setLayout(integrity_layout)
        
        # File information section
        info_group = QGroupBox("File Information")
        info_layout = QVBoxLayout()
        
        self.file_info_display = QTextEdit()
        self.file_info_display.setReadOnly(True)
        self.file_info_display.setMaximumHeight(200)  # Reasonable height
        self.file_info_display.setLineWrapMode(QTextEdit.NoWrap)  # Prevent line wrapping
        self.file_info_display.setStyleSheet("font-family: monospace; font-size: 9pt;")  # Monospace font
        
        info_layout.addWidget(self.file_info_display)
        info_group.setLayout(info_layout)
        
        layout.addWidget(results_group)
        layout.addWidget(integrity_group)
        layout.addWidget(info_group)
        
        widget.setLayout(layout)
        return widget
    
    def select_file(self):
        """Select a file for steganography."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "",
            "All Supported (*.pdf *.docx *.xlsx *.pptx *.zip);;PDF files (*.pdf);;Word documents (*.docx);;Excel files (*.xlsx);;PowerPoint files (*.pptx);;ZIP files (*.zip);;All files (*.*)"
        )
        
        if file_path:
            self.current_file_path = file_path
            self.file_path_label.setText(file_path)
            self.update_file_info()
    
    def select_original_file(self):
        """Select original file for integrity check."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Original File", "",
            "All files (*.*)"
        )
        
        if file_path:
            self.original_file_path = file_path
            self.original_file_label.setText(file_path)
    
    def select_modified_file(self):
        """Select modified file for integrity check."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Modified File", "",
            "All files (*.*)"
        )
        
        if file_path:
            self.modified_file_path = file_path
            self.modified_file_label.setText(file_path)
    
    def update_file_info(self):
        """Update file information display."""
        if not self.current_file_path:
            return
        
        try:
            from src.core.file_stego import FileSteganography
            file_stego = FileSteganography()
            info = file_stego.get_file_info(self.current_file_path)
            
            # Use plain text for better hash display
            info_text = f"""File Information:

Name: {info.get('name', 'Unknown')}
Format: {info.get('format', 'Unknown')}
Size: {info.get('size', 0):,} bytes
Supported: {'Yes' if info.get('is_supported', False) else 'No'}

Hash:
{info.get('hash', 'Unknown')}

Modified: {info.get('modification_time', 0)}
            """
            
            self.file_info_display.setPlainText(info_text)
            
        except Exception as e:
            self.file_info_display.setPlainText(f"Error getting file info: {str(e)}")
    
    def toggle_encryption(self, state):
        """Toggle encryption password input."""
        self.password_input.setEnabled(state == Qt.CheckState.Checked)
        if state != Qt.CheckState.Checked:
            self.password_input.clear()
    
    def embed_message(self):
        """Embed message in the selected file."""
        if not self.current_file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        
        message = self.message_text.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to embed.")
            return
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Steganographic File", "",
            "All files (*.*)"
        )
        
        if not output_path:
            return
        
        password = None
        if self.use_encryption.isChecked():
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter a password for encryption.")
                return
        
        self.start_operation("embed_file", {
            'cover_path': self.current_file_path,
            'payload': message,
            'output_path': output_path,
            'password': password
        })
    
    def extract_message(self):
        """Extract message from the selected file."""
        if not self.current_file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        
        password = None
        if self.use_encryption.isChecked():
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "Warning", "Please enter a password for decryption.")
                return
        
        self.start_operation("extract_file", {
            'file_path': self.current_file_path,
            'password': password
        })
    
    def check_integrity(self):
        """Check file integrity between original and modified files."""
        if not hasattr(self, 'original_file_path') or not hasattr(self, 'modified_file_path'):
            QMessageBox.warning(self, "Warning", "Please select both original and modified files.")
            return
        
        self.start_operation("check_integrity", {
            'original_path': self.original_file_path,
            'modified_path': self.modified_file_path
        })
    
    def clear_all(self):
        """Clear all inputs and outputs."""
        self.current_file_path = ""
        self.file_path_label.setText("No file selected")
        self.message_text.clear()
        self.results_display.clear()
        self.file_info_display.clear()
        self.integrity_results.clear()
        self.use_encryption.setChecked(False)
        self.password_input.clear()
        
        if hasattr(self, 'original_file_path'):
            delattr(self, 'original_file_path')
        if hasattr(self, 'modified_file_path'):
            delattr(self, 'modified_file_path')
        
        self.original_file_label.setText("No original file selected")
        self.modified_file_label.setText("No modified file selected")
    
    def start_operation(self, operation: str, kwargs: dict):
        """Start a background file steganography operation."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.embed_btn.setEnabled(False)
        self.extract_btn.setEnabled(False)
        
        self.worker_thread = WorkerThread(operation, **kwargs)
        self.worker_thread.finished.connect(self.operation_finished)
        self.worker_thread.start()
    
    def operation_finished(self, success: bool, message: str):
        """Handle completion of background operation."""
        self.progress_bar.setVisible(False)
        self.embed_btn.setEnabled(True)
        self.extract_btn.setEnabled(True)
        
        if success:
            if message.startswith("INTEGRITY_CHECK:"):
                # Handle integrity check results
                import ast
                try:
                    data_str = message[16:]  # Remove "INTEGRITY_CHECK:" prefix
                    data = ast.literal_eval(data_str)
                    
                    # Use plain text for better hash display
                    integrity_text = f"""File Integrity Check Results:

Size Changed: {'Yes' if data['size_changed'] else 'No'}
Hash Changed: {'Yes' if data['hash_changed'] else 'No'}
Modification Time Changed: {'Yes' if data['modification_time_changed'] else 'No'}
Likely Modified: {'Yes' if data['likely_modified'] else 'No'}

Original Size: {data['original_size']:,} bytes
Modified Size: {data['modified_size']:,} bytes

Original Hash:
{data['original_hash']}

Modified Hash:
{data['modified_hash']}
"""
                    
                    self.integrity_results.setPlainText(integrity_text)
                except Exception as e:
                    self.integrity_results.setPlainText(f"Error parsing integrity results: {str(e)}")
            else:
                self.results_display.append(f'<span style="color: #28a745; font-weight: bold;">✓ {message}</span>')
        else:
            self.results_display.append(f'<span style="color: #dc3545; font-weight: bold;">✗ {message}</span>')
        
        self.worker_thread = None

class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.crypto_manager = CryptoManager()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the main UI."""
        self.setWindowTitle("StegNinja - Advanced Steganography Toolkit")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("StegNinja - Advanced Steganography Toolkit")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter) # type: ignore
        title_label.setStyleSheet("padding: 10px; color: #2c3e50;")
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Image steganography tab
        self.image_tab = ImageSteganographyTab(self.crypto_manager)
        self.tab_widget.addTab(self.image_tab, "Image Steganography")
        
        # Text steganography tab
        self.text_tab = TextSteganographyTab(self.crypto_manager)
        self.tab_widget.addTab(self.text_tab, "Text Steganography")
        
        # File steganography tab
        self.file_tab = FileSteganographyTab(self.crypto_manager)
        self.tab_widget.addTab(self.file_tab, "File Steganography")
        
        # Add to layout
        layout.addWidget(title_label)
        layout.addWidget(self.tab_widget)
        
        central_widget.setLayout(layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Apply styles
        self.apply_styles()
    
    def apply_styles(self):
        """Apply custom styles to the application."""
        style = """
        QMainWindow {
            background-color: #f5f5f5;
        }
        
        QTabWidget::pane {
            border: 1px solid #007bff;
            border-radius: 8px;
        }
        
        QTabWidget::tab-bar {
            alignment: center;
        }
        
        QTabBar::tab {
            background: #e1e1e1;
            border: 1px solid #007bff;
            border-bottom: none;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            padding: 12px 50px;
            margin-right: 2px;
            margin-bottom: 0px;
            min-width: 180px;
        }
        
        QTabBar::tab:selected {
            background: #add8e6;
            border: 1px solid #007bff;
            border-bottom: none;
            color: #003366;
            font-weight: bold;
            padding: 12px 50px;
            margin-right: 2px;
            margin-bottom: 0px;
            min-width: 180px;
        }
        
        QTabBar::tab:hover {
            background: #f0f0f0;
        }
        
        QGroupBox {
            font-weight: bold;
            border: 2px solid #cccccc;
            border-radius: 5px;
            margin: 5px 0px;
            padding-top: 10px;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        
        QPushButton {
            background-color: #007bff;
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 3px;
            font-weight: bold;
        }
        
        QPushButton:hover {
            background-color: #0056b3;
        }
        
        QPushButton:pressed {
            background-color: #004085;
        }
        
        QPushButton:disabled {
            background-color: #cccccc;
        }
        
        QTextEdit, QLineEdit {
            border: 1px solid #007bff;
            border-radius: 3px;
            padding: 5px;
            background-color: white;
        }
        
        QTextEdit:focus, QLineEdit:focus {
            border-color: #0056b3;
        }
        
        QProgressBar {
            border: 1px solid #007bff;
            border-radius: 3px;
            text-align: center;
        }
        
        QProgressBar::chunk {
            background-color: #007bff;
            border-radius: 2px;
        }
        """
        
        self.setStyleSheet(style)
