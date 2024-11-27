import os
import json
from utils.file_utils import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encode(file, key):
    # Get the file extension
    base_name, file_extension = os.path.splitext(file)

    try:
        print(f"Encrypting file: {file}.")
        
        # Create the encrypted file with .enc extension
        encrypted_file_path = f"{base_name}.enc"

        file_data = read_file(file) 
        iv = get_random_bytes(16)  # Generate a random 16-byte initialization vector

        # Create an AES cipher object with the key and IV and encrypt data
        cipher = AES.new(key, AES.MODE_CFB, iv)

        data_to_encrypt = json.dumps({
            'file_extension': file_extension,
            'file_content': file_data.hex()
        }).encode()

        encrypted_data = iv + cipher.encrypt(data_to_encrypt)
        write_file(encrypted_file_path, encrypted_data) #write data to file
        os.remove(file) # Delete the original file

        return True  
    
    except Exception as e:
        display_error(f"Error encrypting {file}: {e}")
        return False  

def decode(file, key):
    try:
        print(f"Decrypting file: {file}.")
        
        # Get the original file name
        base_name, _ = os.path.splitext(file)

        file_data = read_file(file) # Read the encrypted file content

        # Create an AES cipher object with the key and IV and decrypt data
        iv = file_data[:16]
        encrypted_content = file_data[16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted_data = cipher.decrypt(encrypted_content)

        #parse json structure
        decrypted_json = json.loads(decrypted_data.decode())
        file_extension = decrypted_json['file_extension']
        file_content = bytes.fromhex(decrypted_json['file_content'])
        
        # Write the decrypted data to a new file
        decrypted_file_path = base_name + file_extension  
        write_file(decrypted_file_path, file_content)
        
        # Delete the encrypted file
        os.remove(file)
    except Exception as e:
        display_error(f"Error decrypting {file}: {e}")
        raise Exception(f"{e}")
