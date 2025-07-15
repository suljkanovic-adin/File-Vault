import base64
import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Constants
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 100_000

# Check for a strong password
def is_strong_password(password):
    return (
        len(password) >= 8
        and any(c.isdigit() for c in password)
        and any(c.isupper() for c in password)
    )

# Derive encryption key from password and salt
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file, auto-delete original
def encrypt_file(filename, password):
    try:
        salt = os.urandom(SALT_LENGTH)
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)

        with open(filename, "rb") as file:
            data = file.read()
        encrypted = fernet.encrypt(data)

        with open(filename + ".enc", "wb") as file:
            file.write(salt + encrypted)

        os.remove(filename)
        print(f"Encrypted and original file deleted: {filename}")
    except Exception as e:
        print(f"Encryption failed: {str(e)}")

# Decrypt file and restore original
def decrypt_file(filename, password):
    try:
        with open(filename, "rb") as file:
            content = file.read()
        salt = content[:SALT_LENGTH]
        encrypted_data = content[SALT_LENGTH:]

        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)

        output_filename = filename.replace(".enc", "")
        with open(output_filename, "wb") as file:
            file.write(decrypted)
        print(f"Decryption successful: {output_filename}")
    except Exception as e:
        print(f"Decryption failed: {str(e)}")

# Main user interaction
def main():
    print("Secure File Vault")
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Choose an option (1 or 2): ")

    if choice == "1":
        filename = input("Enter the file to encrypt: ")
        if not os.path.isfile(filename):
            print("File not found.")
            return

        while True:
            password = getpass.getpass("Enter a strong password: ")
            if is_strong_password(password):
                break
            print("Weak password. Must be at least 8 characters, include digits and uppercase letters.")

        encrypt_file(filename, password)

    elif choice == "2":
        filename = input("Enter the file to decrypt (must end with .enc): ")
        if not os.path.isfile(filename):
            print("File not found.")
            return
        password = getpass.getpass("Enter the password: ")
        decrypt_file(filename, password)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
