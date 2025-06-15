# PegasCrypt V8.3

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)
![platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey)

A stylish, secure, and simple drag-and-drop encryption tool with a retro terminal aesthetic. PegasCrypt allows you to easily encrypt and decrypt individual files or entire folders using strong, industry-standard cryptographic algorithms.

## last version
![python_hRg8QVp0bW](https://github.com/user-attachments/assets/613e57c6-07d6-4f27-94a1-cf1f2493d7fb)

## 🌟 Features

*   **Strong Encryption:** Utilizes AES-256 in GCM mode, providing both confidentiality and data integrity.
*   **Secure Key Derivation:** Implements PBKDF2 with HMAC-SHA256 to protect your passwords against brute-force attacks.
*   **Folder Encryption:** Encrypt and decrypt entire directory structures into a single, portable file.
*   **Intuitive UI:** A simple drag-and-drop interface makes encryption accessible to everyone. No command-line needed.
*   **Live Previews:** Safely preview encrypted file content or metadata before committing to a full decryption.
*   **Multi-Language Support:** Instantly switch between English and Russian interfaces with a single click.
*   **Retro Aesthetic:** Features a cool, hacker-style terminal theme with scanlines and a "Courier" font.

## ⚙️ Installation

To run PegasCrypt, you need Python 3 and a few dependencies.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AlexMainYou/Pegas-crypt.git
    cd Pegas-crypt
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    # Create and activate a virtual environment (optional but good practice)
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

    # Install required packages
    pip install -r requirements.txt
    ```
    You will need to create a `requirements.txt` file with the following content:
    ```
    cryptography
    tkinterdnd2
    ```

3.  **Run the application:**
    ```bash
    python PegasCrypt.py
    ```

## 🚀 How to Use

The application is designed to be straightforward.

### To Encrypt a File or Folder

1.  Launch the application (`python PegasCrypt.py`).
2.  Select your desired encrypted file extension (`.Pegas` or `.ALX`) using the radio buttons.
3.  Drag and drop your file or folder onto the main window.
4.  The application will analyze the item and show a preview.
5.  Click the **[ Encrypt File ]** or **[ Encrypt Folder ]** button.
6.  Enter a strong password when prompted.
7.  Done! The original item will be securely removed, and a new encrypted file will appear in its place.

### To Decrypt a File or Folder

1.  Drag and drop an encrypted file (`.Pegas` or `.ALX`) onto the main window.
2.  You will be prompted to enter the password for a secure preview.
3.  If the password is correct, a preview of the original filename and content will be shown.
4.  Click the **[ Decrypt File ]** or **[ Decrypt Folder ]** button.
5.  If you entered the correct password for the preview, it will be cached and used automatically. Otherwise, you'll be prompted again.
6.  Done! The encrypted file will be removed, and the original file or folder will be restored.

## 📋 Feature Breakdown

| Feature                 | Description                                                                 | Status           |
| ----------------------- | --------------------------------------------------------------------------- | ---------------- |
| **File Encryption**     | Encrypt any single file with AES-256-GCM.                                   | ✅ Implemented   |
| **Folder Encryption**   | Archives and encrypts an entire folder tree into one file.                  | ✅ Implemented   |
| **Drag & Drop UI**      | Core functionality is based on intuitive drag-and-drop actions.             | ✅ Implemented   |
| **Security Previews**   | Password-protected previews prevent full decryption by mistake.             | ✅ Implemented   |
| **Password Caching**    | Caches the password after a successful preview for a smoother workflow.     | ✅ Implemented   |
| **Language Switching**  | On-the-fly UI language change between English and Russian.                  | ✅ Implemented   |

## 🔒 Security Model

Security is the top priority for PegasCrypt.

*   **Encryption Algorithm:** **AES-256 in GCM Mode**. GCM (Galois/Counter Mode) is an authenticated encryption mode. This not only keeps your data secret but also provides integrity checks, meaning the application can detect if an encrypted file has been tampered with.
*   **Key Derivation Function:** **PBKDF2 with HMAC-SHA256**. Your password is never used directly as the encryption key. Instead, it's put through 100,000 rounds of hashing via PBKDF2. This makes brute-force and dictionary attacks on your password extremely slow and computationally expensive.
*   **Salt:** A unique, cryptographically secure 16-byte salt is generated for every single encryption operation. This ensures that even if you encrypt two identical files with the same password, the resulting encrypted files will be completely different.

### PyQt5 version
![PegaCryptV6Qt_RoM8IOPbIV](https://github.com/user-attachments/assets/c82a06f2-81ed-4ce2-8433-378e12477732)


## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
