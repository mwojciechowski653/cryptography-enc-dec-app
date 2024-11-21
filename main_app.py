from Crypto.Random import get_random_bytes
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from admin import *
from certificate import *
from coding import *
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog


def main():
    admin = Admin()

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

            name_button_e.pack()
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
        
        certificate = Certificate(name, admin)
        certificate.creating_and_signing_certificate(admin)
        
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
                name_button_d.pack()
                password_label.pack()
                password_entry.pack()
            else:
                check.set(True)
                
    def choose_key():
        file_path = key_file_input("enc")
        key_path.set(file_path)
        if check.get():
            name_button_d.pack()
            password_label.pack()
            password_entry.pack()
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
        if op == "d":
            decrypt_button.pack()
            
    def post_encrypt_decrypt(op):
        if op == "e":
            try:
                RSA.import_key(read_file(name.get()))
            except:
                messagebox.showerror("Wrong key name", "This name is wrong")
                return
            
            aes_key = encrypt_folder(path.get(), "g")
            content = simpledialog.askstring("Content name", "Enter name for your encrypted aes key:")
            if content == "":
                content = "content"
            rsa_encryption(name.get(), aes_key, content)

            encrypt_button.forget()
            name_button_e.forget()
            
        elif op == "d":
            try:
                nam = name.get()
                pa = password.get()
                RSA.import_key(read_file(name.get()), passphrase=password.get())
            except:
                messagebox.showerror("Wrong key/password", "This key or password is wrong")                
                return

            aes_key = rsa_decryption(password.get(), name.get(), key_path.get())
            decrypt_folder(path.get(), aes_key, "g")
                        
            search_key_button.forget()
            decrypt_button.forget()
            password_label.forget()
            password_entry.forget()
            name_button_d.forget()

        search_folder_button.forget()
        
        show_menu()
        

    # !!! new option !!!
    # choosing the certificate to check validity
    # certificate_list = certificate.get_certificate_list()
    # certificate.check_certificate_validity(certificate_list[0])    

    # creating admin
    admin.generate_keys()
    admin.encrypt_authority_key()

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
    search_key_button = tk.Button(window, text="Choose content file", command=choose_key)

    encrypt_button = tk.Button(window, text="Encrypt", command=lambda: post_encrypt_decrypt("e"))
    decrypt_button = tk.Button(window, text="Decrypt", command=lambda: post_encrypt_decrypt("d"))

    name_button_e = tk.Button(window, text="Choose your public key", command=lambda: choose_key_name("e"))
    name_button_d = tk.Button(window, text="Choose your private key", command=lambda: choose_key_name("d"))
    # key gen gui
    name = tk.StringVar()
    password = tk.StringVar()
    
    name_label = tk.Label(window, text="Enter name for your key")
    name_entry = tk.Entry(window, textvariable=name)
    password_label = tk.Label(window, text="Enter password for your key")
    password_entry = tk.Entry(window, textvariable=password)
    
    create_keys_button = tk.Button(window, text="Create keys", command=create_key)
    
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