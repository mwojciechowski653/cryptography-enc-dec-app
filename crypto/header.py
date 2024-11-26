from typing import List
from utils.file_utils import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization
import json

#creates a header file in the ecnrypted folder with the information about authorized users
def create_header(selected_certificates: List[Certificate], aes_key,folder_path):
    authorized_users = []
    for cert in selected_certificates:
        user = {}

        #encrypt the AES key with the user's public key
        public_key_bytes = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        user_public_key = RSA.import_key(public_key_bytes)
        cipher_rsa = PKCS1_OAEP.new(user_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        #save the user's name and the encrypted AES key
        var = cert.subject
        user['name'] = cert.subject.rfc4514_string().replace("CN=","")
        user['encrypted_key'] = encrypted_aes_key.hex()
        authorized_users.append(user)

    #save the header to a file
    write_file(f"{folder_path}/header.json", json.dumps({
        'authorized_users': authorized_users
    }).encode())


#gets the AES key from the header file and DELETES a header file
def get_key_from_header(header_file, user_private_key_path, user_name, user_password):
    header = json.loads(read_file(header_file))

    for user in header['authorized_users']:
        #find user and decrypt the AES key with the private key
        if user['name'] == user_name:
            # Load the RSA private key
            private_key = RSA.import_key(read_file(user_private_key_path), passphrase=user_password)

            # Decrypt the data with the private key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            encrypted_data = bytes.fromhex(user['encrypted_key'])
            decrypted_key = cipher_rsa.decrypt(encrypted_data)

            os.remove(header_file)

            return decrypted_key