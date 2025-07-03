# StegNinja - Advanced Steganography Toolkit

A professional GUI-based steganography toolkit for security research and red team operations.

**Strike from the shadows. Hide in plain sight. Leave no trace.**

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

### 🖼️ Image Steganography

- **LSB Embedding**: Hide data in the least significant bits of image pixels
- **Multiple Formats**: Support for PNG, BMP, and TIFF images
- **Capacity Analysis**: Real-time calculation of hiding capacity
- **Image Preview**: Live preview of cover images with metadata

### 📝 Text Steganography

- **Unicode Method**: Hide data using invisible Unicode characters
- **Whitespace Method**: Embed data in trailing whitespace
- **Text Processing**: Support for various text formats and encodings

### 🔐 Security Features

- **AES Encryption**: Professional-grade encryption using Fernet (AES 128)
- **Password Protection**: Secure your hidden data with passwords
- **Key Derivation**: PBKDF2 with SHA-256 for secure key generation
- **Secure Random**: Cryptographically secure random number generation

### 🎨 Modern GUI

- **Responsive Design**: Works at all window sizes with proper scaling
- **Professional Layout**: Clean, intuitive interface using Qt splitters
- **Progress Tracking**: Real-time progress indicators for operations
- **Error Handling**: Comprehensive error messages and validation
- **Background Processing**: Non-blocking operations with worker threads

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows, macOS, or Linux

### Setup

1. **Clone or download the project**

   ```bash
   git clone <repository-url>
   cd CW1Programming
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

## Dependencies

- **PyQt5**: Modern GUI framework
- **Pillow (PIL)**: Image processing and manipulation
- **OpenCV**: Advanced computer vision operations
- **NumPy**: Numerical computing for efficient operations
- **Cryptography**: Professional cryptographic library

## Usage

### Image Steganography

1. **Embedding a Message**:

   - Select an image file (PNG, BMP, or TIFF recommended)
   - Enter your secret message
   - Optionally enable encryption with a password
   - Click "Embed Message" and choose output location
   - Save the steganographic image

2. **Extracting a Message**:
   - Select the steganographic image
   - If encrypted, enter the correct password
   - Click "Extract Message"
   - View the hidden message in the results

### Text Steganography

1. **Embedding in Text**:

   - Enter or load cover text
   - Enter your secret message
   - Choose method (Unicode or Whitespace)
   - Optionally enable encryption
   - Click "Embed in Text"
   - Copy or save the steganographic text

2. **Extracting from Text**:
   - Paste the steganographic text
   - If encrypted, enter the password
   - Click "Extract from Text"
   - View the extracted message

## Project Structure

```
CW1Programming/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── .github/
│   └── copilot-instructions.md
├── src/
│   ├── core/              # Core steganography modules
│   │   ├── __init__.py    # Base classes
│   │   ├── image_stego.py # Image steganography
│   │   └── text_stego.py  # Text steganography
│   ├── gui/               # GUI components
│   │   ├── __init__.py
│   │   └── app.py         # Main application window
│   └── utils/             # Utility modules
│       ├── __init__.py
│       └── crypto.py      # Cryptographic utilities
├── assets/                # Application assets
├── tests/                 # Test modules
│   └── __init__.py
```

## Security Considerations

- **Encryption**: Always use encryption for sensitive data
- **Key Management**: Use strong, unique passwords
- **Cover Selection**: Choose appropriate cover media
- **Operational Security**: Be aware of metadata and forensic analysis
- **Legal Compliance**: Ensure compliance with local laws and regulations

## Development

### Code Style

- Follow PEP 8 conventions
- Use type hints for all functions
- Include comprehensive docstrings
- Implement proper error handling

### Testing

```bash
# Run tests (when implemented)
python -m pytest tests/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the coding guidelines
4. Add tests for new features
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and authorized security research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

## Support

For issues, questions, or contributions, please:

- Create an issue in the repository
- Follow the project guidelines
- Provide detailed information about problems

---

**Note**: This is a professional security research tool. Use responsibly and ethically.
