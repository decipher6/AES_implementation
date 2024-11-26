# AES_implementation
# AES File Encryption and Decryption Tool

This Python script provides functionality to encrypt and decrypt files using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode. It ensures the secure handling of sensitive files through password-based encryption and padding.

## Features
- **Encryption**: Securely encrypts a file using a password and generates a unique salt and initialization vector (IV).
- **Decryption**: Decrypts previously encrypted files using the correct password.
- **Password-based Key Derivation**: Utilizes PBKDF2HMAC with SHA256 to derive a secure encryption key from a password.

## Requirements
- Python 3.6 or higher
- `cryptography` library

Install the `cryptography` library using pip:
```bash
pip install cryptography
```

## Usage

### Command Line Arguments
1. **mode**: Choose between `encrypt` or `decrypt`.
2. **input_file**: Path to the file to encrypt or decrypt.
3. **output_file**: Path to save the resulting encrypted or decrypted file.
4. **password**: Password used for encryption or decryption.

### Examples
#### Encrypting a File
```bash
python main.py encrypt in.txt out.txt my_password
```
- Encrypts `in.txt` into `out.txt` using `my_password`.

#### Decrypting a File
```bash
python main.py decrypt out.txt re_in.txt my_password
```
- Decrypts `out.txt` into `re_in.txt` using `my_password`.

