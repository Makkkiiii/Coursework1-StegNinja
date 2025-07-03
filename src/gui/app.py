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
            elif self.operation == "analyze":
                self._analyze()
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _embed_image(self):
        image_stego = ImageSteganography()
        crypto = self.kwargs.get('crypto')
        password = self.kwargs.get('password')
        
        if crypto and crypto.is_key_set():
            image_stego.set_crypto_manager(crypto)
        
        result = image_stego.embed(
            self.kwargs['image_path'],
            self.kwargs['message'],
            self.kwargs['output_path'],
            password=password
        )
        
        if result:
            self.finished.emit(True, "Message embedded successfully!")
        else:
            self.finished.emit(False, "Failed to embed message.")
    
    def _extract_image(self):
        image_stego = ImageSteganography()
        crypto = self.kwargs.get('crypto')
        password = None
        
        if crypto and crypto.is_key_set():
            image_stego.set_crypto_manager(crypto)
            # Also get the password for direct passing to extract_text
            password = self.kwargs.get('password')
        
        # Use extract_text to get decoded string instead of raw bytes
        message = image_stego.extract_text(self.kwargs['image_path'], password=password)
        
        if message:
            self.finished.emit(True, f"Extracted message: {message}")
        else:
            self.finished.emit(False, "No message found or extraction failed.")
    
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
        
        message = text_stego.extract(self.kwargs['stego_text'], method=method, password=password)
        
        if message:
            self.finished.emit(True, f"Extracted message: {message}")
        else:
            self.finished.emit(False, "No hidden message found.")
    
    def _analyze(self):
        # Placeholder for analysis functionality
        self.finished.emit(True, "Analysis completed.")


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
        splitter = QSplitter(Qt.Horizontal) # type: ignore
        
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
        
        options_layout.addRow("Security:", self.use_encryption)
        options_layout.addRow("Password:", self.password_input)
        options_group.setLayout(options_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.embed_btn = QPushButton("Embed Message")
        self.embed_btn.clicked.connect(self.embed_message)
        
        self.extract_btn = QPushButton("Extract Message")
        self.extract_btn.clicked.connect(self.extract_message)
        
        button_layout.addWidget(self.embed_btn)
        button_layout.addWidget(self.extract_btn)
        
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
        """Create the right image preview panel."""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Image preview
        preview_group = QGroupBox("Image Preview")
        preview_layout = QVBoxLayout()
        
        # Scrollable area for image
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setAlignment(Qt.AlignCenter) # type: ignore
        scroll_area.setMinimumSize(500, 400)
        
        self.image_label = QLabel("No image loaded")
        self.image_label.setAlignment(Qt.AlignCenter) # type: ignore
        self.image_label.setScaledContents(True)
        self.image_label.setStyleSheet("border: 1px solid gray;")
        
        scroll_area.setWidget(self.image_label)
        preview_layout.addWidget(scroll_area)
        preview_group.setLayout(preview_layout)
        
        # Image info
        info_group = QGroupBox("Image Information")
        info_layout = QFormLayout()
        
        self.info_dimensions = QLabel("N/A")
        self.info_size = QLabel("N/A")
        self.info_format = QLabel("N/A")
        self.info_capacity = QLabel("N/A")
        
        info_layout.addRow("Dimensions:", self.info_dimensions)
        info_layout.addRow("File Size:", self.info_size)
        info_layout.addRow("Format:", self.info_format)
        info_layout.addRow("Capacity:", self.info_capacity)
        info_group.setLayout(info_layout)
        
        layout.addWidget(preview_group)
        layout.addWidget(info_group)
        
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
        """Load and display image preview."""
        try:
            pixmap = QPixmap(file_path)
            if not pixmap.isNull():
                # Scale image to fill more of the available space while maintaining aspect ratio
                scaled_pixmap = pixmap.scaled(600, 450, Qt.KeepAspectRatio, Qt.SmoothTransformation) # type: ignore
                self.image_label.setPixmap(scaled_pixmap)
                
                # Update image info
                self.info_dimensions.setText(f"{pixmap.width()} x {pixmap.height()}")
                file_size = os.path.getsize(file_path)
                self.info_size.setText(f"{file_size:,} bytes")
                self.info_format.setText(os.path.splitext(file_path)[1].upper()[1:])
                
                # Calculate approximate capacity (simplified)
                capacity = (pixmap.width() * pixmap.height() * 3) // 8  # Rough estimate
                self.info_capacity.setText(f"~{capacity:,} characters")
            else:
                self.image_label.setText("Failed to load image")
        except Exception as e:
            self.image_label.setText(f"Error loading image: {str(e)}")
    
    def toggle_encryption(self, state):
        """Toggle encryption password input."""
        self.password_input.setEnabled(state == Qt.Checked) # type: ignore
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
            "PNG files (*.png);;All files (*.*)"
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
            'password': password
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
            else:
                self.results_text.append(f'<span style="color: #28a745; font-weight: bold;">✓ {message}</span>')
        else:
            self.results_text.append(f'<span style="color: #dc3545; font-weight: bold;">✗ {message}</span>')
        
        self.worker_thread = None


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
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Unicode", "Whitespace"])
        
        self.use_encryption_text = QCheckBox("Use Encryption")
        self.use_encryption_text.stateChanged.connect(self.toggle_text_encryption)
        
        self.password_text = QLineEdit()
        self.password_text.setEchoMode(QLineEdit.Password)
        self.password_text.setEnabled(False)
        self.password_text.setPlaceholderText("Enter encryption password")
        
        options_layout.addRow("Method:", self.method_combo)
        options_layout.addRow("Encryption:", self.use_encryption_text)
        options_layout.addRow("Password:", self.password_text)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.embed_text_btn = QPushButton("Embed in Text")
        self.embed_text_btn.clicked.connect(self.embed_in_text)
        
        self.extract_text_btn = QPushButton("Extract from Text")
        self.extract_text_btn.clicked.connect(self.extract_from_text)
        
        button_layout.addWidget(self.embed_text_btn)
        button_layout.addWidget(self.extract_text_btn)
        
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
        method = "unicode" if self.method_combo.currentText() == "Unicode" else "whitespace"
        
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
        method = "unicode" if self.method_combo.currentText() == "Unicode" else "whitespace"
        
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
