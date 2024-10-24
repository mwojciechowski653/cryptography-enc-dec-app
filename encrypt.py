import os
from Crypto.Random import get_random_bytes
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
import tkinter as tk
from tkinter import ttk, messagebox

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


def encrypt_folder(folder_path, option):
    # Lists to keep track of encrypted and failed files
    encrypted_files = []
    failed_files = []

    #Generate and save the key
    key = get_random_bytes(16)

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
    return key

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
    # TERMINAL VERSION(without keys)
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

            name_button.pack()
            search_folder_button.pack()
        elif option.get() == "Decrypt":
            decide.forget()
            options_dropdown.forget()

            search_folder_button.pack()
            search_key_button.pack()
        elif option.get() == "Generate keys":
            decide.forget()
            options_dropdown.forget()
            
            name_label.pack()
            name_entry.pack()
            password_label.pack()
            password_entry.pack()
            create_keys_button.pack()
        else:
            messagebox.showerror("Wrong option", "Please choose one of the available options")
            
    def show_menu():
        option.set("Encrypt")
        options_dropdown.pack()
        decide.pack()
        path.set("")
        key_path.set("")
        check.set(False)
        name.set("")
        password.set("")
        
    def create_key():
        name = name_entry.get()
        password = password_entry.get()
        
        if len(name) < 1:
            messagebox.showerror("Too short name", "Name for your keys cannot be empty")
            return
        if len(password) < 1:
            messagebox.showerror("Too short password", "Password for your private key cannot be empty")
            return
        
        generate_rsa_keys(name, password)
        messagebox.showinfo("Keys generated", "Your keys are successfully created")
        
        name_label.forget()
        name_entry.forget()
        password_label.forget()
        password_entry.forget()
        create_keys_button.forget()
        
        show_menu()
            
    def choose_folder():
        folder_path = folder_input("g")
        path.set(folder_path)
        if option.get() == "Encrypt":
            encrypt_button.pack()
            if check.get():
                encrypt_button.pack()
            else:
                check.set(True)
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
            
    def choose_key_name(op):
        file_path = key_file_input("k")
        name.set(file_path)
        if op == "e":
            if check.get():
                encrypt_button.pack()
            else:
                check.set(True)
            
    def post_encrypt_decrypt(op):
        if op == "e":
            try:
                RSA.import_key(read_file(name.get()))
            except:
                messagebox.showerror("Wrong key name", "This name is wrong")
                return
            
            aes_key = encrypt_folder(path.get(), "g")
            rsa_encryption(name.get(), aes_key, "content")

            encrypt_button.forget()
            
        elif op == "d":
            decrypt_folder(path.get(), read_file(key_path.get()), "g")
            
            search_key_button.forget()
            decrypt_button.forget()

        search_folder_button.forget()
        name_button.forget()
        
        show_menu()
        
    # main window
    window = tk.Tk()
    window.geometry("500x200")
    window.title("Encryption and Decryption App")
    window.option_add("*Font", "40")
    
    # main menu
    option = tk.StringVar()
    option.set("Encrypt")
    options_dropdown = ttk.Combobox(window, textvariable=option, values=("Encrypt", "Decrypt", "Generate keys"))
    options_dropdown.pack()

    decide = tk.Button(window, text="Choose this option", command=check_value)
    decide.pack()

    # encrypt/decrypt gui
    path = tk.StringVar()
    key_path = tk.StringVar()
    check = tk.BooleanVar()
    check.set(False)
    
    search_folder_button = tk.Button(window, text="Choose folder", command=choose_folder)
    search_key_button = tk.Button(window, text="Choose key file", command=choose_key)

    encrypt_button = tk.Button(window, text="Encrypt", command=lambda: post_encrypt_decrypt("e"))
    decrypt_button = tk.Button(window, text="Decrypt", command=lambda: post_encrypt_decrypt("d"))

    name_button = tk.Button(window, text="Choose your key", command=lambda: choose_key_name("e"))
    # key gen gui
    name = tk.StringVar()
    password = tk.StringVar()
    
    name_label = tk.Label(window, text="Enter name for your key")
    name_entry = tk.Entry(window, textvariable=name)
    password_label = tk.Label(window, text="Enter password for your key")
    password_entry = tk.Entry(window, textvariable=password)
    
    create_keys_button = tk.Button(window, text="Create keys", command=create_key)

    #TODO replace with the actual function (to choose in options menu)
    # test_button3 = tk.Button(window, text="RSA decryption (test, do after rsa encryption)", command=lambda: test_rsa_decryption())
    # test_button3.pack()

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