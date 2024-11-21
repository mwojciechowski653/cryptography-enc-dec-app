from cryptography.x509 import Name, NameAttribute, CertificateBuilder, load_der_x509_certificate, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
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
    
    project_folder = os.path.dirname(os.path.abspath(__file__))                         # path to our project
    key_folder_name = "KeyFolder"                                                       # name of the folder with authority passwords
    key_folder = os.path.join(project_folder, key_folder_name)                          # path to folder with keys
    certificates_list = []                                                              # certificates list
    certificate_folder_path = os.path.join(project_folder, "certificates")              # path to certificates list


    def __init__(self, subject_name, admin:Admin) -> None:
        self.subject_name = subject_name                                                # user name
        self.subject_public_key = ""                                                    # user public key
        self.authority_name = admin.name                                                # authority name
        self.authority_private_key = ""                                                 # authority private key
    
    def get_public_key(self, public_key_path):                                          # getting public key from the path
        with open(public_key_path, "rb") as key_file:
            public_key =  serialization.load_pem_public_key(key_file.read())
        return public_key
    
    def get_issuer_private_key(self, admin:Admin):                                                      # getting user private key 
        private_key_path = os.path.join(Certificate.key_folder, f"{admin.name}_private.pem")        # user private key path

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=admin.password.encode(),                                                           # admin password
        )
        return private_key
        

    def creating_and_signing_certificate(self, admin:Admin):
        # Creating authority
        #admin = self.creating_admin()
        #self.authority_name = admin.name
        
        #admin.decrypt_key()                                                                     # decrypting authority keys 
        
        subject = Name([NameAttribute(NameOID.COMMON_NAME, self.subject_name)])                 # creating subject identity, Name - a list of attributes, NameAttribute - one attribute, NameOID.COMMON_NAME - inform us that it's a name of subject
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, self.authority_name)])                # creating authority identity
        serial_number = random.randint(1, 2**64 - 1)                                            # generating serial number in 64-bit range

        user_public_key_path = os.path.join(Certificate.project_folder, f"{self.subject_name}_public.pem") 
        public_key = self.get_public_key(user_public_key_path)                                      # user public key
        builder = CertificateBuilder(
            issuer_name = issuer,                                                                   # who is making an certificate
            subject_name = subject,                                                                 # who need to have certificate
            serial_number=serial_number,                                                            # serial number
            public_key = public_key,                                                                # user public key
            not_valid_before = datetime.datetime.now(timezone.utc),                                 # when certificate was created - time right now
            not_valid_after = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365),   # when certificate lasts - time year later
            )
        
        private_key = self.get_issuer_private_key(admin)                                            # authority private key
        admin.encrypt_authority_key()                                                               # encrypting all authority keys

        signed_certificate = builder.sign(                                                          # signing certificate
            private_key = private_key,                                                              # authority key
            algorithm = hashes.SHA256(),
            )
        self.writing_certificate_to_folder(signed_certificate)                                      # putting certificat to the certificates folder
        
        return signed_certificate
    
    def writing_certificate_to_folder(self, certificate):                                                       # putting certificat to the certificates folder
        os.makedirs(Certificate.certificate_folder_path, exist_ok=True)                                         # checking if certificate folder exist if not create it
        pem_certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)                         # putting certificate class to the .pem file
        file_path = os.path.join(Certificate.certificate_folder_path, f"{self.subject_name}_certificate.pem")   # path of .pem file
        write_file(file_path, pem_certificate)                                                                  # writing certificate to the file
        
    def load_certificate_from_folder(self):                                                                     # getting all certificates from the forlder certificates
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
            
    def get_common_name_from_certificate(self, certificate):                                # getting name of the certificate
        subject = certificate.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    
        if common_name:                            
            return common_name[0].value
        return None 

    def check_certificate_validity(self, certificate, admin:Admin):
        admin.decrypt_key()

        try:
            # Używamy nowej właściwości, która zwraca datę z przypisaną strefą czasową (UTC)
            now = datetime.datetime.now(datetime.timezone.utc)

            # Zamiast używać `not_valid_before` i `not_valid_after`, używamy `not_valid_before_utc` i `not_valid_after_utc`
            certificate_not_valid_before = certificate.not_valid_before_utc
            certificate_not_valid_after = certificate.not_valid_after_utc

            if certificate_not_valid_before <= now <= certificate_not_valid_after:                                      # checking if it does not lasts
                print(f"Certificate {certificate.serial_number}is within the validity period")
            else:
                print(f"Certificate {certificate.serial_number} is expired")
                return False
            
            try:
                authority_public_key_path = os.path.join(Certificate.key_folder, f"{self.authority_name}_public.pem")
                authority_public_key = self.get_public_key(authority_public_key_path)
                
                authority_public_key.verify(                                                    
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
            

            file_path = os.path.join(Certificate.project_folder, f"{self.get_common_name_from_certificate(certificate)}_certificate_public.pem")  
            
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,  # Format PEM
                format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standardowy format klucza publicznego
                )

            write_file(file_path, pem_public_key)


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

    admin = creating_admin()
    certificate = Certificate("name", admin)
    #certificate.creating_and_signing_certificate(admin)
    certificate.load_certificate_from_folder()
    liste = Certificate.get_certificate_list()
    print(liste[0])
    certificate.check_certificate_validity(liste[0], admin)
    

    

    


# https://cryptography.io/en/latest/x509/reference/