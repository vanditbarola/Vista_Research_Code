# Vista_Research_Code
VISTA is a secure data transmission model combining hybrid cryptography and image steganography. It ensures confidentiality and stealth in communication. This repository contains the complete implementation code for the project.
# VISTA: Visual Image Steganography with Trusted Architecture

VISTA is a secure data transmission model that integrates hybrid cryptography techniques with advanced image steganography to ensure both confidentiality and concealment in digital communication. This project offers a complete implementation of secure message embedding and extraction using encryption and steganography.

---

## 🔒 Features

- **Hybrid Cryptography:** Combines RSA (asymmetric) and AES (symmetric) encryption for enhanced security.
- **Image Steganography:** Uses LSB (Least Significant Bit) method to hide encrypted messages in images.
- **Secure Key Generation:** Ensures integrity and protection of encryption keys.
- **User-Friendly Interface:** Simple UI for encoding and decoding hidden messages.
- **Lightweight Execution:** Efficient code that runs with minimal resource consumption.

---

## 🧠 How It Works

1. **Encryption Phase:**
   - The user inputs a plaintext message.
   - AES encrypts the message.
   - RSA encrypts the AES key.
   - Both are combined and prepared for embedding.

2. **Steganography Phase:**
   - The encrypted message is embedded into an image using LSB substitution.
   - The output is a stego image that looks visually unchanged.

3. **Decryption Phase:**
   - The hidden message is extracted from the stego image.
   - RSA decrypts the AES key.
   - AES decrypts the message.

---

## 📁 Folder Structure

