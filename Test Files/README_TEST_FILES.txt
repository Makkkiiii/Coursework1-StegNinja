StegNinja Auto-Detection Test Files
====================================

This directory contains test files for validating automatic steganography detection.

TEXT STEGANOGRAPHY:
- unicode_detection_test.txt: Contains Unicode steganography
- whitespace_detection_test.txt: Contains whitespace steganography

IMAGE STEGANOGRAPHY:
- stego_image_detection_test.png: Contains LSB steganography
- normal_image_test.png: Normal image, no steganography
- cover_image.png: Original cover image

FILE STEGANOGRAPHY:
- stego_pdf_detection_test.pdf: Contains PDF steganography
- normal_pdf_test.pdf: Normal PDF, no steganography
- stego_zip_detection_test.zip: Contains ZIP steganography
- normal_zip_test.zip: Normal ZIP, no steganography

TESTING INSTRUCTIONS:
1. Run: python main.py
2. Navigate to each steganography tab
3. Load test files using file selection buttons
4. Observe automatic detection messages
5. Use Extract buttons to reveal hidden messages

EXPECTED BEHAVIOR:
- Files with steganography: Green detection message + instruction to use Extract button
- Files without steganography: Blue "no content detected" message
- Auto-detection does NOT extract messages automatically (preserves Extract button purpose)
