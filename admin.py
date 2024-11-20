import os, shutil
from encrypt import *
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *


class Admin:
    def __init__(self) -> None:
        self.name = "authority"                                                                 # the name of admin user
        self.password = "crypto"                                                                # password of admin user
        self.key_name = "key_manager"
        self.key_password = "password"
        self.project_folder = os.path.dirname(os.path.abspath(__file__))                        # path to our project
        self.key_folder_name = "KeyFolder"
        self.key_folder = os.path.join(self.project_folder, self.key_folder_name)               # path to folder with keys
        self.authority_key_files = [f"{self.name}_public.pem", f"{self.name}_private.pem"]           # names of our keys' paths
        self.key_manager_key_files = [f"{self.key_name}_public.pem", f"{self.key_name}_private.pem"]

    def generate_keys(self):
        generate_rsa_keys(self.name, self.password)                                             # generating public and private keys for admin user
        generate_rsa_keys(self.key_name, self.key_password)
        
    def encrypt_authority_key(self):
        all_files_exist = all(os.path.isfile(os.path.join(self.project_folder, file)) for file in self.authority_key_files)
    
        if all_files_exist:
            moving_files(self.authority_key_files, self.project_folder, self.key_folder)            # moving keys files to KeyFolder
        
        public_key_name = self.key_manager_key_files[0]                                                # public key name of file

        try:
            RSA.import_key(read_file(public_key_name))                                          # importing the public key into an RSA object
        except:
            print("Wrong key name", "This name is wrong")
            return
            
        aes_key = encrypt_folder(self.key_folder_name, "t")                                     # encryption in aes
        rsa_encryption(public_key_name = public_key_name, data = aes_key, name = self.key_folder_name)

    def decrypt_key(self):
        private_key_name = self.key_manager_key_files[1]    
        private_key_path = os.path.join(self.project_folder, private_key_name)
        
        try:
            RSA.import_key(read_file(private_key_name), passphrase = self.key_password)
        except:
            print("Wrong key/password", "This key or password is wrong")
            return

        aes_key = rsa_decryption(self.key_password, private_key_name, "KeyFolder.key.enc")
        decrypt_folder(self.key_folder_name, aes_key, "t")
    
