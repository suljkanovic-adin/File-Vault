# Secure File Vault

This is a simple Python project that lets you encrypt and decrypt files using a password. It's a basic tool for learning how encryption works in Python using AES-256.

## What this project does

- Encrypts any file with a password
- Decrypts previously encrypted files
- Uses AES-256 encryption (via Fernet)
- Automatically deletes the original file after encryption
- Checks if the password is strong before continuing

## How to run it

### 1. Install Python and dependencies

Make sure you have Python 3 installed. Then install the required package:

```bash
pip install -r requirements.txt
```

The only dependency is:

```
cryptography
```

### 2. Run the script

```bash
python vault.py
```

You will see a menu:

```
1. Encrypt File
2. Decrypt File
```

Choose an option by entering 1 or 2.

### 3. Encrypting a file

- Enter the file name (it should exist)
- Enter a strong password (at least 8 characters, with a number and a capital letter)
- The file will be encrypted and saved with a `.enc` extension
- The original file will be deleted for safety

### 4. Decrypting a file

- Enter the name of the `.enc` file
- Enter the same password you used to encrypt it
- The file will be restored with the original name

## Example

```bash
$ python vault.py
Secure File Vault
1. Encrypt File
2. Decrypt File
Choose an option (1 or 2): 1
Enter the file to encrypt: test.txt
Enter a strong password: ********
Encrypted and original file deleted: test.txt
```

## Notes

- This is a basic learning project.
- Do not use it for real sensitive files.
- There’s no password recovery—if you forget it, the file is lost.

## License

This project is open under the MIT License.
