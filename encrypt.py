import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils.file_utils import *
import json
import tkinter as tk
from tkinter import ttk, messagebox

def encode(file, key):
    # Get the file extension
    base_name, file_extension = os.path.splitext(file)

    try:
        print(f"Encrypting file: {file}.")
        
        # Create the encrypted file with .enc extension
        encrypted_file_path = f"{base_name}.enc"

        file_data = read_file(file) # Read the file content
        iv = get_random_bytes(16)  # Generate a random 16-byte initialization vector

        # Create an AES cipher object with the key and IV and encrypt data
        cipher = AES.new(key, AES.MODE_CFB, iv)

        data_to_encrypt = json.dumps({
            'file_extension': file_extension,
            'file_content': file_data.hex()
        }).encode()

        encrypted_data = iv + cipher.encrypt(data_to_encrypt)
        write_file(encrypted_file_path, encrypted_data) #write data to file
        os.remove(file) # Delete the original file

        return True  # Indicate that encryption was successful
    
    except Exception as e:
        display_error(f"Error encrypting {file}: {e}")
        return False  # Indicate that encryption was not successful


def encrypt_folder(folder_path, option):
    # Lists to keep track of encrypted and failed files
    encrypted_files = []
    failed_files = []

    #Generate and save the key
    key_file_path = f"{folder_path}.key"
    key = get_random_bytes(16)
    write_file(key_file_path, key)

    # List all files in the folder
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        
        # Only process files, not directories
        if os.path.isfile(file_path):
            # Try to encrypt the file and handle exceptions
            try:
                success = encode(file_path, key)
                if success:
                    encrypted_files.append(file_name)  # Add to encrypted list
                else:
                    failed_files.append(file_name)  # Add to failed list
            except Exception as e:
                # If there's an error during encoding, log the error and file name
                print(f"Error encrypting {file_name}: {e}")
                failed_files.append(file_name)
                if option == "g":
                    messagebox.showerror("Error encrypting file", f"Error encrypting {file_name}: {e}")
    
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


def decode(file, key):
    try:
        print(f"Decrypting file: {file}.")
        
        # Get the original file name
        base_name, _ = os.path.splitext(file)

        file_data = read_file(file) # Read the encrypted file content

        # Create an AES cipher object with the key and IV and decrypt data
        iv = file_data[:16]
        encrypted_content = file_data[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(encrypted_content)

        #parse json structure
        decrypted_json = json.loads(decrypted_data.decode())
        file_extension = decrypted_json['file_extension']
        file_content = bytes.fromhex(decrypted_json['file_content'])
        
        # Write the decrypted data to a new file
        decrypted_file_path = base_name + file_extension  
        write_file(decrypted_file_path, file_content)
        
        # Delete the encrypted file
        os.remove(file)
    except Exception as e:
        display_error(f"Error decrypting {file}: {e}")
    

def decrypt_folder(folder_path, key_path):
    # Check for .enc files in the specified folder
    enc_files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.enc')]

    if not enc_files:
        display_error("No encrypted files (.enc) found in the specified folder.")
        return
    
    # Load the key from the key file
    key = read_file(key_path)
    
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.enc'):  # Assuming encrypted files have .enc extension
            file_path = os.path.join(folder_path, file_name)
            decode(file_path, key)
    print("Decryption complete.")



def main():
    
    # 
    # TERMINAL VERSION
    # 
    # while True:
    #     print("Choose an option:")
    #     print("1. Encrypt files")
    #     print("2. Decrypt files")
    #     print("3. Exit")
    #     choice = input("Enter your choice (1/2/3): ")
    # 
    #     if choice == '1':
    #         folder_path = folder_input()
    #         encrypt_folder(folder_path,"t")
    #         print("Encryption complete.")
    #     elif choice == '2':
    #         folder_path = folder_input()
    #         key_path = key_file_input()
    #         decrypt_folder(folder_path, key_path)
    #     elif choice == '3':
    #         print("Exiting the application.")
    #         break
    #     else:
    #         display_error("Invalid choice! Please try again.")
    
    
    #
    # GUI VERSION
    #

    def check_value():
        if option.get() == "Encrypt":
            decide.forget()
            options_dropdown.forget()

            search_folder_button.pack()
        elif option.get() == "Decrypt":
            decide.forget()
            options_dropdown.forget()

            search_folder_button.pack()
        else:
            messagebox.showerror("Wrong option", "Please choose on of the available options")
            
    def choose_folder():
        folder_path = folder_input_gui()
        path.set(folder_path)
        if option.get() == "Encrypt":
            encrypt_button.pack()

    window = tk.Tk()
    window.geometry("400x400")
    window.title("Encryption and Decryption App")
    
    option = tk.StringVar()
    option.set("Encrypt")
    options_dropdown = ttk.Combobox(window, textvariable=option, values=("Encrypt", "Decrypt"))
    options_dropdown.pack()

    decide = tk.Button(window, text="Choose this option", command=check_value)
    decide.pack()

    path = tk.StringVar()
    search_folder_button = tk.Button(window, text="Choose folder", command=choose_folder)

    encrypt_button = tk.Button(window, text="Encrypt", command=lambda: encrypt_folder(path.get(), "g"))
    
    
    label = tk.Label(window, text=":)")
    label.pack()
    
    tk.mainloop()
    
if __name__ == '__main__':
    main()


# Example of usage:
#
# ENCRYPTION
# Choose number from the menu: 1
# Enter non-absolute path of the folder (for now)
# folder_path = 'example'
#
# DECRYPTION
# Choose number from the menu: 2
# Enter  path of the folder (absolute also works)
# folder_path = 'example'
# Enter  path of the key file
# key_path = 'example.key'