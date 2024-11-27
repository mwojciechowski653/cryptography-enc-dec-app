from crypto.admin import Admin
from crypto.certificate_service import CertificateService
from constants import *
from crypto.header import *


from Crypto.Random import get_random_bytes
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from coding import *
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

users = []

def main():
    #
    # GUI VERSION
    #
    def show_main_menu():
        create_user_button.pack()
        enter_app_button.pack()
        
    def forget_main_menu():
        create_user_button.forget()
        enter_app_button.forget()
        
    def show_app_menu():
        # need to create buttons because of .destroy() in forget_app_menu()
        global issue_cert_button, encrypt_button, decrypt_button
        issue_cert_button = tk.Button(window, text="Issue certificate", command=issue_certificate)
        encrypt_button = tk.Button(window, text="Encrypt", width=10, height=3, command=show_encrypt_menu)
        decrypt_button = tk.Button(window, text="Decrypt", width=10, height=3, command=show_decrypt_menu)
        
        go_back_to_menu_button.pack(anchor=tk.W)
        issue_cert_button.place(x=350, y=0)
        encrypt_button.place(x=115, y=100)
        decrypt_button.place(x=265, y=100)
        
    def forget_app_menu():
        global issue_cert_button, encrypt_button, decrypt_button
        go_back_to_menu_button.forget()
        issue_cert_button.destroy()
        encrypt_button.destroy()
        decrypt_button.destroy()
    
    def enter_app():
        forget_main_menu()
        show_app_menu()
        
    def enter_main_menu():
        forget_app_menu()
        show_main_menu()
        
    def show_encrypt_menu():
        forget_app_menu()
        
        admin = Admin()
        certificate = CertificateService()
        if os.path.isdir(CERTIFICATE_FOLDER):
            for file_name in os.listdir(CERTIFICATE_FOLDER):
                cert_listbox.insert(tk.END, file_name)
        
        go_back_to_app_button.pack(anchor=tk.W)
        cert_listbox.pack()
        confirm_certs_button.pack()
        
    def show_decrypt_menu():
        pass
        
    def go_back_to_app():
        cert_listbox.forget()
        go_back_to_app_button.forget()
        confirm_certs_button.forget()
        choose_folder_to_encrypt.forget()
        cert_listbox.delete("0", tk.END)
        encrypt_button.forget()
        
        show_app_menu()
        
    def create_user():
        name = simpledialog.askstring("Enter name", "Please enter your name:")
        password = simpledialog.askstring("Enter password", "Please enter your password:")
        
        if name and password:
            generate_rsa_keys(name, password)
            messagebox.showinfo("Created user", "Your account was successfully created!")
        else:
            messagebox.showerror("Empty data", "Both user name and password should not be empty")
    
    def issue_certificate():
        name = simpledialog.askstring("Enter name", "Please enter admin name:")
        password = simpledialog.askstring("Enter password", "Please enter admin password:")

        if name == "authority" and password == "crypto":
            messagebox.showinfo("Access granted", "Access granted!")
            admin = Admin()
            certService = CertificateService(admin)
            while True:
                user_name = simpledialog.askstring("Enter user name", "Please enter user name:")
                if user_name:
                    break
                else:
                    messagebox.showerror("Empty name", "You entered empty user name")
            certService.creating_and_signing_certificate(user_name)
            messagebox.showinfo("Issued certificate", f"Certificate for {user_name} was successfully issued!")
        else:
            messagebox.showerror("Access denied", "Wrong name and/or password")
        
    def process_certs():
        choosen = cert_listbox.curselection()
        choosen_cerst = []
        for i in choosen:
            choosen_cerst.append(cert_listbox.get(i))
        
        certificate = CertificateService()
        certificate.load_certificate_from_folder(choosen_cerst)
        liste = CertificateService.get_certificate_list()

        for cert in liste:
            if certificate.check_certificate_validity(cert):  # in general need to check for all certificates
                users.append(cert)
        if len(users):
            choose_folder_to_encrypt.pack()
        else:
            choose_folder_to_encrypt.forget()
            messagebox.showinfo("Choose certificate", "To proceed choose at least one certificate!")
            
    def choose_folder():
        folder_path = folder_input("g")
        folder_path_var.set(folder_path)
        encrypt_button.pack()
        
    def encrypt():
        admin = Admin()
        key = admin.get_decrypted_aes_key()
        
        path = folder_path_var.get()
        
        encrypt_folder(path, "g", key)
        create_header(users, key, path)
        
    # app window
    window = tk.Tk()
    window.title("Cryptographic app")
    window.geometry("500x250")
    window.option_add("*Font", "40")

    # widgets for main menu
    create_user_button = tk.Button(window, text="Create new user", command=create_user)
    enter_app_button = tk.Button(window, text="Enter app", command=enter_app)

    # widgets for app
    go_back_to_menu_button = tk.Button(window, text="Go back to main menu", command=enter_main_menu)
    issue_cert_button = tk.Button(window, text="Issue certificate", command=issue_certificate)
    encrypt_button = tk.Button(window, text="Encrypt", width=10, height=3, command=show_encrypt_menu)
    decrypt_button = tk.Button(window, text="Decrypt", width=10, height=3, command=show_decrypt_menu)
    
    # widgets for encrypt
    folder_path_var = tk.StringVar()
    
    cert_listbox = tk.Listbox(window, selectmode=tk.MULTIPLE, height=3)
    go_back_to_app_button = tk.Button(window, text="Go back", command=go_back_to_app)
    confirm_certs_button = tk.Button(window, text="Confirm", command=process_certs)
    choose_folder_to_encrypt = tk.Button(window, text="Choose folder to encrypt", command=choose_folder)
    encrypt_button = tk.Button(window, text="Encrypt", command=encrypt)

    show_main_menu()
    
    window.mainloop()
    
if __name__ == '__main__':
    main()