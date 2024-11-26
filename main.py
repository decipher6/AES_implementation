from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64


def generate_key(password: str, salt: bytes) -> bytes:
   """Generates a key using PBKDF2HMAC with a password and salt."""
   kdf = PBKDF2HMAC(
       algorithm=SHA256(),
       length=32,
       salt=salt,
       iterations=100000,
       backend=default_backend()
   )
   return kdf.derive(password.encode())


def encrypt_file(input_file: str, output_file: str, password: str):
   """Encrypts a file using AES encryption."""
   salt = os.urandom(16)
   iv = os.urandom(16)
   key = generate_key(password, salt)


   with open(input_file, 'rb') as f:
       plaintext = f.read()


   # Padding plaintext to be AES block size compatible
   padder = padding.PKCS7(algorithms.AES.block_size).padder()
   padded_data = padder.update(plaintext) + padder.finalize()


   # Encrypting the data
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
   encryptor = cipher.encryptor()
   ciphertext = encryptor.update(padded_data) + encryptor.finalize()


   # Writing salt, IV, and ciphertext to the output file
   with open(output_file, 'wb') as f:
       f.write(salt + iv + ciphertext)


def decrypt_file(input_file: str, output_file: str, password: str):
   """Decrypts a file encrypted with AES encryption."""
   with open(input_file, 'rb') as f:
       salt = f.read(16)  # First 16 bytes are the salt
       iv = f.read(16)    # Next 16 bytes are the IV
       ciphertext = f.read()


   key = generate_key(password, salt)


   # Decrypting the data
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
   decryptor = cipher.decryptor()
   padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()


   # Removing padding
   unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
   plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()


   # Writing plaintext to the output file
   with open(output_file, 'wb') as f:
       f.write(plaintext)


if __name__ == "__main__":
   import argparse


   parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using AES.")
   parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
   parser.add_argument("input_file", help="Path to the input file")
   parser.add_argument("output_file", help="Path to the output file")
   parser.add_argument("password", help="Password for encryption/decryption")


   args = parser.parse_args()


   if args.mode == "encrypt":
       encrypt_file(args.input_file, args.output_file, args.password)
   elif args.mode == "decrypt":
       decrypt_file(args.input_file, args.output_file, args.password)
