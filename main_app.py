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
        create_user_button = tk.Button(window, text="Create new user", command=create_user)
        create_user_button.pack()
        enter_app_button = tk.Button(window, text="Enter app")
        enter_app_button.pack()
        
    def create_user():
        name = simpledialog.askstring("Enter name", "Please enter your name:")
        password = simpledialog.askstring("Enter password", "Please enter your password:")
        
        if name and password:
            generate_rsa_keys(name, password)
            messagebox.showinfo("Created user", "Your account was successfully created!")
        else:
            messagebox.showerror("Empty data", "Both user name and password should not be empty")
    
    window = tk.Tk()
    window.title("Cryptographic app")
    window.geometry("500x200")
    window.option_add("*Font", "40")
    
    show_main_menu()

    

    window.mainloop()
    
if __name__ == '__main__':
    main()