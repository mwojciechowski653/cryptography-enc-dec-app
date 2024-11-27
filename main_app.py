from Crypto.Random import get_random_bytes
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from coding import *
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog


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
        encrypt_button = tk.Button(window, text="Encrypt", width=10, height=3)
        decrypt_button = tk.Button(window, text="Decrypt", width=10, height=3)
        
        go_back_to_menu_button.pack(anchor=tk.W)
        issue_cert_button.place(x=350, y=0)
        encrypt_button.place(x=125, y=100)
        decrypt_button.place(x=275, y=100)
        
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
            # generate_rsa_keys(name, password)
            messagebox.showinfo("Access granted", "Placeholder")
        else:
            messagebox.showerror("Access denied", "Wrong name and/or password")
        
    # app window
    window = tk.Tk()
    window.title("Cryptographic app")
    window.geometry("500x200")
    window.option_add("*Font", "40")

    # widgets for main menu
    create_user_button = tk.Button(window, text="Create new user", command=create_user)
    enter_app_button = tk.Button(window, text="Enter app", command=enter_app)

    # widgets for app
    go_back_to_menu_button = tk.Button(window, text="Go back to main menu", command=enter_main_menu)
    issue_cert_button = tk.Button(window, text="Issue certificate", command=issue_certificate)
    encrypt_button = tk.Button(window, text="Encrypt", width=10, height=3)
    decrypt_button = tk.Button(window, text="Decrypt", width=10, height=3)

    show_main_menu()
    
    

    window.mainloop()
    
if __name__ == '__main__':
    main()