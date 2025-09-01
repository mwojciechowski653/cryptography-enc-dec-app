import tkinter as tk

from coding import *
from constants import *
from crypto.admin import Admin
from crypto.certificate_service import CertificateService
from crypto.header import *

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
        forget_app_menu()

        go_back_to_app_button_from_decrypt.pack(anchor=tk.W)
        choose_folder_to_decrypt.pack()
        choose_private_key.pack()
        
    def go_back_to_app():
        cert_listbox.forget()
        go_back_to_app_button.forget()
        go_back_to_app_button_from_decrypt.forget()
        confirm_certs_button.forget()
        choose_folder_to_encrypt.forget()
        choose_folder_to_decrypt.forget()
        cert_listbox.delete("0", tk.END)
        encrypt_button2.forget()
        check.set(False)
        decrypt_button2.forget()
        choose_private_key.forget()
        
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

        users = []
        for cert in liste:
            if certificate.check_certificate_validity(cert):  # in general need to check for all certificates
                users.append(cert)
        if len(users):
            choose_folder_to_encrypt.pack()
        else:
            choose_folder_to_encrypt.forget()
            messagebox.showinfo("Choose certificate", "To proceed choose at least one certificate!")
            
    def choose_folder_e():
        folder_path = folder_input("g")
        folder_path_var.set(folder_path)
        encrypt_button2.pack()
        
    def choose_folder_d():
        folder_path = folder_input("g")
        folder_path_var.set(folder_path)
        if check.get():
            decrypt_button2.pack()
        else:
            check.set(True)

    def choose_key():
        key_path = key_file_input("k")
        private_key_path.set(key_path)
        if check.get():
            decrypt_button2.pack()
        else:
            check.set(True)


    def encrypt():
        admin = Admin()
        key = admin.get_decrypted_aes_key()
        
        path = folder_path_var.get()
        
        encrypt_folder(path, "g", key)
        create_header(users, key, path)
    
    def decrypt():
        name = simpledialog.askstring("Enter name", "Please enter your name:")
        password = simpledialog.askstring("Enter password", "Please enter your password:")
        
        if name and password:
            certificate = CertificateService()
            certs = []
            if os.path.isdir(CERTIFICATE_FOLDER):
                for file_name in os.listdir(CERTIFICATE_FOLDER):
                    certs.append(file_name)

            certificate.load_certificate_from_folder(certs)
            liste = CertificateService.get_certificate_list()
            mine_certs = []
            check2 = False
            for cert in liste:
                if str(cert.subject).split(sep="=")[1][:-2] == name:
                    mine_certs.append(cert)
            for my_cert in mine_certs:
                if certificate.check_certificate_validity(my_cert): #in general need to check for all certificates
                    check2 = True

            # if at least one will be fine go with decryption
            if check2:
                try:
                    key = get_key_from_header(f"{folder_path_var.get()}/header.json", private_key_path.get(), name, password)
                    decrypt_folder(folder_path_var.get(), key, "g")
                except:
                    messagebox.showerror("Error", "Incorrect folder or key data")
            else:
                messagebox.showerror("Wrong user", "There is no valid certificate for this user")
        else:
            messagebox.showerror("Empty data", "Both user name and password should not be empty")

    # check if keys for admin exists (should be initialized only on first run of app)
    try:
        aes = open("KeyFolder/app_aes.key.enc")
        priv = open("KeyFolder/app_private.pem")
        pub = open("KeyFolder/app_public.pem")
        
        aes.close()
        priv.close()
        pub.close()
    except FileNotFoundError:
        admin = Admin()
        admin.create_all_admin_keys()
    
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
    choose_folder_to_encrypt = tk.Button(window, text="Choose folder to encrypt", command=choose_folder_e)
    encrypt_button2 = tk.Button(window, text="Encrypt", command=encrypt)

    # widgets for decrypt
    private_key_path = tk.StringVar()
    check = tk.BooleanVar()
    check.set(False)
    choose_folder_to_decrypt = tk.Button(window, text="Choose folder to decrypt", command=choose_folder_d)
    choose_private_key = tk.Button(window, text="Choose private key", command=choose_key)
    go_back_to_app_button_from_decrypt = tk.Button(window, text="Go back", command=go_back_to_app)
    decrypt_button2 = tk.Button(window, text="Decrypt", command=decrypt)
    show_main_menu()
    
    window.mainloop()
    
if __name__ == '__main__':
    main()