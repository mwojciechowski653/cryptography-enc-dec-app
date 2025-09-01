from utils.file_utils import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#Generate RSA keys and save them to files
def generate_rsa_keys(name, password):
    private_key = RSA.generate(3072)  
    public_key = private_key.publickey()  

    private_key_data = private_key.export_key(passphrase=password, pkcs=8,
                                                protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                                prot_params={'iteration_count':131072})
    public_key_data = public_key.export_key()

    write_file(f"{name}_public.pem", public_key_data)
    write_file(f"{name}_private.pem", private_key_data)
    
    return private_key, public_key



# Encrypt the data with the public key
def rsa_encryption(public_key_name, data, name):
    public_key = RSA.import_key(read_file(public_key_name))
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    write_file(f"{name}.key.enc", encrypted_data)


def rsa_decryption(password, private_key_path, encrypted_key_path):
    # Load the RSA private key
    private_key = RSA.import_key(read_file(private_key_path), passphrase=password)

    # Decrypt the data with the private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_data = read_file(encrypted_key_path)
    decrypted_key = cipher_rsa.decrypt(encrypted_data)

    return decrypted_key