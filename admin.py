import os, shutil
from encrypt import *
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *


class Admin:
    def __init__(self) -> None:
        self.name = "authority"                                                                 # the name of admin user
        self.password = "crypto"                                                                # password of admin user
        self.project_folder = os.path.dirname(os.path.abspath(__file__))                        # path to our project
        self.key_folder_name = "KeyFolder"
        self.key_folder = os.path.join(self.project_folder, self.key_folder_name)               # path to folder with keys

    def create_and_code_authority_key(self):
        generate_rsa_keys(self.name, self.password)                                             # generating public and private keys for admin user
        authority_key_files = [f"{self.name}_public.pem", f"{self.name}_private.pem"]           # names of our keys' paths

        self.copying_files(authority_key_files, self.project_folder, self.key_folder)            # moving keys files to KeyFolder
        public_key_name = authority_key_files[0]                                                # public key name of file

        try:
            RSA.import_key(read_file(public_key_name))                                          # importing the public key into an RSA object
        except:
            print("Wrong key name", "This name is wrong")
            return
            
        aes_key = encrypt_folder(self.key_folder_name, "t")                                     # encryption in aes
        rsa_encryption(public_key_name = public_key_name, data = aes_key, name = self.key_folder_name)
        os.remove(os.path.join(self.project_folder, authority_key_files[1]))
    
    def copying_files(self, files, source_folder, destination_folder):
        os.makedirs(destination_folder, exist_ok=True)

        for filename in files:
            source_file = os.path.join(source_folder, filename)
            destination_file = os.path.join(destination_folder, filename)
    
            # Copying the files
            if os.path.isfile(source_file):
                shutil.copy(source_file, destination_file)
                #print(f"Moved: {filename}")

        #print("All files were moved")