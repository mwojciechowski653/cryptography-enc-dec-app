# Folder Encryption and Decryption Application

## Overview

This project is a simple Python application that allows users to encrypt and decrypt all files in a specified folder. The application uses AES-256 encryption to ensure data security and provides options for both encryption and decryption using a user-supplied password.

## Features

- **Encrypt files**: Select a folder, and the application will encrypt all the files inside.
- **Decrypt files**: Decrypt previously encrypted files in a folder using the correct password.
- **Password protection**: Uses a password to protect and unlock encrypted files.

## Prerequisites

Before running this application, ensure you have the following installed:

- Python 3.x
- The required Python libraries, which can be installed via pip: (virtual environment is reccomended)

```bash
pip install -r requirements.txt
```

## Setup

```bash
git clone https://github.com/m-szur/ual-cryptography.git
```

```bash
cd ual-cryptography
```

## How to Use

- **Encrypt files**:

  Run the application and choose option to encrypt:

  ```bash
  python3 encrypt.py
  ```

  Input the folder path where the files to be encrypted are located.

  You can choose to decrypt later via the main menu.

- **Decrypt files**:

  Run the application and choose option to decrypt:

  ```bash
  python3 encrypt.py
  ```

  Input the folder path where the encrypted files are located.

  Enter the path to the key used during encryption. All encrypted files will be decrypted, and the original filenames will be restored.

  ```bash
  example.key
  ```

## Example Workflow

Encrypt a folder: After entering the folder path and password, files like example.txt will be encrypted and renamed to example.enc.

Decrypt a folder: You can later use the same password to restore the original files.

## To Do

- Discuss renaming files after encryption to e.g. image_encrypted.png
- Discuss recursively encrypting every subfolder and file in the selected folder.
- Discuss using absolute paths for folder input to avoid potential path issues.
- Discuss file formats.
- Add encrypting and decrypting logic to encrypt whole folder to one file
- Implement better error handling(does GUI errors counts?) and test
- Discuss Password
- improve code structure
