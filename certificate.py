from cryptography.x509 import Name, NameAttribute, CertificateBuilder, load_der_x509_certificate, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

import datetime
from datetime import timezone
import random

from typing import DefaultDict
from encrypt import *
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from admin import *


class Certificate:
    
    project_folder = os.path.dirname(os.path.abspath(__file__))                        # path to our project
    key_folder_name = "KeyFolder"
    key_folder = os.path.join(project_folder, key_folder_name)               # path to folder with keys
    certificates_list = []
    certificate_folder_path = os.path.join(project_folder, "certificates") 


    def __init__(self, subject_name, admin:Admin) -> None:
        self.subject_name = subject_name
        self.subject_public_key = ""
        self.authority_name = admin.name
        self.authority_private_key = ""
    
    def get_public_key(self, public_key_path):
        with open(public_key_path, "rb") as key_file:
            public_key =  serialization.load_pem_public_key(key_file.read())
        return public_key
    
    def get_issuer_private_key(self, admin:Admin):
        private_key_path = os.path.join(Certificate.project_folder, f"{admin.name}_private.pem")

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=admin.password.encode(),  # hasło admina
        )
        return private_key
        

    def creating_and_signing_certificate(self, admin:Admin):
        # Creating authority
        admin = self.creating_admin()
        self.authority_name = admin.name
        #admin.decrypt_key()
        
        subject = Name([NameAttribute(NameOID.COMMON_NAME, self.subject_name)])                 # creating subject identity, Name - a list of attributes, NameAttribute - one attribute, NameOID.COMMON_NAME - inform us that it's a name of subject
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, self.authority_name)])                # creating authority identity
        serial_number = random.randint(1, 2**64 - 1)                                            # generating serial number in 64-bit range

        public_key = self.get_user_public_key()
        builder = CertificateBuilder(
            issuer_name = issuer,                                                               # who is making an certificate
            subject_name = subject,                                                             # who need to have certificate
            serial_number=serial_number,
            public_key = public_key,
            not_valid_before = datetime.datetime.now(timezone.utc),
            not_valid_after = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365),
            )
        
        private_key = self.get_issuer_private_key(admin)
        admin.encrypt_authority_key()

        signed_certificate = builder.sign(
            private_key = private_key,
            algorithm = hashes.SHA256(),
            )
        self.writing_certificate_to_folder(signed_certificate)
        
        return signed_certificate
    
    def writing_certificate_to_folder(self, certificate):
        os.makedirs(Certificate.certificate_folder_path, exist_ok=True)
        pem_certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file_path = os.path.join(Certificate.certificate_folder_path, f"{self.subject_name}_certificate.pem")
        write_file(file_path, pem_certificate)
        
    def load_certificate_from_folder(self):
        if os.path.isdir(Certificate.certificate_folder_path):
            for file_name in os.listdir(Certificate.certificate_folder_path):
                file_path = os.path.join(Certificate.certificate_folder_path, file_name)
                
                if file_name.endswith(".pem") or file_name.endswith(".crt"):
                    try:
                        certificate_file = read_file(file_path)
               
                        try:
                            certificate = load_pem_x509_certificate(certificate_file)
                            Certificate.certificates_list.append(certificate)
                            print(f"Uploading certificate PEM: {file_name} went correctly")
                            
                        except ValueError:
                            try:
                                certificate = load_der_x509_certificate(certificate_file)
                                Certificate.certificates_list.append(certificate)
                                print(f"Uploading certificate DER: {file_name} went correctly")
                                
                            except ValueError:
                                print(f"Uploading certificate: {file_name} failed")
                                
                    except Exception as ex:
                        print(f"Opening certificate {file_name} file failed")
        else:
            print("Certificate folder doesn't exist")
            
    def check_certificate_validity(self, certificate, admin:Admin):
        #admin.decrypt_key()

        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            if certificate.not_valid_before <= now <= certificate.not_valid_after:
                print(f"Certificate {certificate.serial_number}is within the validity period")
            else:
                print(f"Certificate {certificate.serial_number} is expired")
                return False
            
            try:
                authority_public_key_path = os.path.join(Certificate.project_folder, f"{self.authority_name}_public.pem")
                authority_public_key = self.get_public_key(authority_public_key_path)
                
                certificate.public_key().verify(                                                # retrieves the user public key
                    certificate.signature,                                                      # signature generated by the certificate issuer (admin) using their private key
                    certificate.tbs_certificate_bytes,                                          # TBS stands for "To Be Signed", represents the part of the certificate that was signed by the issuer's private key
                    padding.PKCS1v15(),                                                         # specify the padding scheme
                    certificate.signature_hash_algorithm,                                       # hashing algorithm used in signature
                )
                print(f"The signature of certificate {certificate.serial_number} is correct")
            except InvalidSignature:
                print(f"The signature of certificate {certificate.serial_number} is invalid.")
                return None
            except Exception as e:
                print(f"Error during certificate signature verification {certificate.serial_number}: {e}")
                return None
            public_key = certificate.public_key()                                               # getting user public key from certificate
            file_path = os.path.join(Certificate.project_folder, f"{certificate.name}_public.pem")  
            write_file(file_path, public_key)

            return public_key

        except Exception as e:
            print(f"Error during certificate verification {certificate.serial_number}: {e}")
            return None
        
    @classmethod
    def get_certificate_list(cls):
        return cls.certificates_list

    

if __name__ == '__main__':
    def creating_admin():
        admin = Admin()
        #admin.generate_keys()
        #admin.encrypt_authority_key()
        return admin

    #test_rsa_key_generation()
    #test_rsa_encryption()
    #test_rsa_decryption()
    admin = creating_admin()
    certificate = Certificate("name", admin)
    #certificate.creating_and_signing_certificate(admin)
    certificate.load_certificate_from_folder()
    liste = Certificate.get_certificate_list()
    print(liste[0])
    

    

    


# https://cryptography.io/en/latest/x509/reference/