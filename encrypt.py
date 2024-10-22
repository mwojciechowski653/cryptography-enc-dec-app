import os
from Crypto.Random import get_random_bytes
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
import tkinter as tk
from tkinter import ttk, messagebox

def encrypt_folder(folder_path, option):
    # Lists to keep track of encrypted and failed files
    encrypted_files = []
    failed_files = []

    #Generate and save the key
    key = get_random_bytes(16)
    
    #TODO don't save the aes key, it's passed and encrypted with rsa
    key_file_path = f"{folder_path}.key" #TODO remove
    write_file(key_file_path, key) #TODO remove

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
    return key

def decrypt_folder(folder_path, key, option):
    # Check for .enc files in the specified folder
    enc_files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.enc')]

    if not enc_files:
        display_error("No encrypted files (.enc) found in the specified folder.")

        if option == "g":
            messagebox.showerror("No encrypted files", "No encrypted files (.enc) found in the specified folder.")
            
        return
    
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.enc'):  # Assuming encrypted files have .enc extension
            file_path = os.path.join(folder_path, file_name)
            decode(file_path, key)
    print("Decryption complete.")
    if option == "g":
        messagebox.showinfo("Decryption complete", "Decryption complete.")

def test_rsa_encryption():
    folder_name = "example"
    public_key_name = "name_public.pem"

    aes_key = encrypt_folder(folder_name, "dupa")
    rsa_encryption(public_key_name, aes_key, folder_name)

def test_rsa_decryption():
    folder_name = "example"
    password = "password"
    private_key_name = "name_private.pem"
    aes_key_name = "example.key.enc"
    aes_key = rsa_decryption(password, private_key_name, aes_key_name)
    decrypt_folder(folder_name, aes_key, "dupa")

def test_rsa_key_generation():
    generate_rsa_keys("name", "password")


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
    #         folder_path = folder_input("t")
    #         encrypt_folder(folder_path,"t")
    #         print("Encryption complete.")
    #     elif choice == '2':
    #         folder_path = folder_input("t")
    #         key_path = key_file_input("t")
    #         decrypt_folder(folder_path, key_path, "t")
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
            search_key_button.pack()
        else:
            messagebox.showerror("Wrong option", "Please choose one of the available options")
            
    def choose_folder():
        folder_path = folder_input("g")
        path.set(folder_path)
        if option.get() == "Encrypt":
            encrypt_button.pack()
        if option.get() == "Decrypt":
            if check.get():
                decrypt_button.pack()
            else:
                check.set(True)
    def choose_key():
        file_path = key_file_input("g")
        key_path.set(file_path)
        if check.get():
            decrypt_button.pack()
        else:
            check.set(True)
            
    def post_encrypt_decrypt(op):
        if op == "e":
            encrypt_folder(path.get(), "g")
            
            encrypt_button.forget()
        elif op == "d":
            decrypt_folder(path.get(), read_file(key_path.get()), "g")
            
            search_key_button.forget()
            decrypt_button.forget()

        search_folder_button.forget()
        
        option.set("Encrypt")
        options_dropdown.pack()
        decide.pack()
        path.set("")
        key_path.set("")
        check.set(False)
        
    window = tk.Tk()
    window.geometry("500x200")
    window.title("Encryption and Decryption App")
    window.option_add("*Font", "40")
    
    option = tk.StringVar()
    option.set("Encrypt")
    options_dropdown = ttk.Combobox(window, textvariable=option, values=("Encrypt", "Decrypt"))
    options_dropdown.pack()

    decide = tk.Button(window, text="Choose this option", command=check_value)
    decide.pack()

    path = tk.StringVar()
    key_path = tk.StringVar()
    check = tk.BooleanVar()
    check.set(False)
    search_folder_button = tk.Button(window, text="Choose folder", command=choose_folder)
    search_key_button = tk.Button(window, text="Choose key file", command=choose_key)

    encrypt_button = tk.Button(window, text="Encrypt", command=lambda: post_encrypt_decrypt("e"))
    
    decrypt_button = tk.Button(window, text="Decrypt", command=lambda: post_encrypt_decrypt("d"))

    #TODO replace with the actual function (to choose in options menu)
    test_button1 = tk.Button(window, text="Generate RSA keys (test)", command = test_rsa_key_generation)
    test_button2 = tk.Button(window, text="RSA encryption (test, do after generating keys)", command=lambda: test_rsa_encryption())
    test_button3 = tk.Button(window, text="RSA decryption (test, do after rsa encryption)", command=lambda: test_rsa_decryption())
    test_button1.pack()
    test_button2.pack()
    test_button3.pack()

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