import os
from coding import *
from constants import APP_PRIVATE_KEY_NAME, APP_AES_NAME, APP_PUBLIC_KEY_NAME, KEY_FOLDER, KEY_FOLDER_NAME, PROJECT_FOLDER, APP_PRIVATE_KEY_PATH, APP_AES_PATH
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *


class Admin:
    def __init__(self) -> None:
        self.name = "authority"                                                                   # the name of admin user
        self.password = "crypto"                                                                  # password of admin user                          
                            
    def get_decrypted_aes_key(self):                                                              # decrypting authority keys
        return rsa_decryption(self.password, APP_PRIVATE_KEY_PATH, APP_AES_PATH)              # key manager password, private manager key, folder encrypted - .key.enc
    

    def create_all_admin_keys(self):
        private_key, public_key = generate_rsa_keys("app", self.password)
        aes_key = get_random_bytes(16)
        rsa_encryption(APP_PUBLIC_KEY_NAME, aes_key, "app_aes")
        all_keys = [APP_PUBLIC_KEY_NAME, APP_PRIVATE_KEY_NAME, APP_AES_NAME]
        moving_files(all_keys, PROJECT_FOLDER, KEY_FOLDER)
        return private_key, public_key, aes_key

        
