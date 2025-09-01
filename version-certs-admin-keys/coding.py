import os
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from tkinter import messagebox, simpledialog

# Function to recursively process folders and files
def process_folder(path, key, encrypted_files, failed_files, option):
    # List all files and directories in the folder
    for file_name in os.listdir(path):
        file_path = os.path.join(path, file_name)

        # If it's a file, try to encrypt it
        if os.path.isfile(file_path):
            try:
                success = encode(file_path, key)
                if success:
                    encrypted_files.append(file_name)  # Add to encrypted list
                else:
                    failed_files.append(file_name)  # Add to failed list
            except Exception as e:
                # Handle exceptions during encryption
                print(f"Error encrypting {file_name}: {e}")
                failed_files.append(file_name)
                if option == "g":
                    messagebox.showerror("Error encrypting file", f"Error encrypting {file_name}: {e}")
        # If it's a folder, recursively process its contents
        elif os.path.isdir(file_path):
            process_folder(file_path, key, encrypted_files, failed_files, option)


def encrypt_folder(folder_path, option, key):
    # Lists to keep track of encrypted and failed files
    encrypted_files = []
    failed_files = []

    # Start processing the folder and its subfolders
    process_folder(folder_path, key, encrypted_files, failed_files, option)

    # Print results
    print(f"Encryption complete for folder: {folder_path}.", f"Encrypted {len(encrypted_files)} out of {len(encrypted_files) + len(failed_files)} files.")
    if option == "g":
        messagebox.showinfo("Encryption completed", f"Encryption complete for folder: {folder_path}.\nEncrypted {len(encrypted_files)} out of {len(encrypted_files) + len(failed_files)} files.")
        
    if failed_files:
        print("Failed to encrypt the following files:")
        info = ""
        for failed_file in failed_files:
            print(f"- {failed_file}")
            info += f"- {failed_file}\n"
        if option == "g":
            messagebox.showerror("Error encrypting files", f"Error encrypting {info}")

# Recursive function to process folders and files for decryption
def process_decryption_folder(path, key, option):
    # List all files and directories in the folder
    for file_name in os.listdir(path):
        file_path = os.path.join(path, file_name)

        # If it's a file with a .enc extension, decrypt it
        if os.path.isfile(file_path) and file_name.endswith('.enc'):
            try:
                decode(file_path, key)
                print(f"Decrypted: {file_name}")
            except Exception as e:
                print(f"Error decrypting {file_name}: {e}")
                if option == "g":
                    messagebox.showerror("Error decrypting file", f"Error decrypting {file_name}: {e}")
        # If it's a directory, recursively process its contents
        elif os.path.isdir(file_path):
            process_decryption_folder(file_path, key, option)

# Main decryption function
def decrypt_folder(folder_path, key, option):
    # Check for .enc files in the specified folder
    enc_files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.enc')]

    if not enc_files:
        display_error("No encrypted files (.enc) found in the specified folder.")
        if option == "g":
            messagebox.showerror("No encrypted files", "No encrypted files (.enc) found in the specified folder.")
        return

    # Process the folder and subfolders recursively
    process_decryption_folder(folder_path, key, option)

    # Decryption completed
    print("Decryption complete.")
    if option == "g":
        messagebox.showinfo("Decryption complete", "Decryption complete.")
