from cryptography.x509 import Name, NameAttribute, CertificateBuilder, load_der_x509_certificate, load_pem_x509_certificate, Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import datetime
from datetime import timezone
import random

from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from crypto.admin import *
from constants import APP_PRIVATE_KEY_NAME,PROJECT_FOLDER, KEY_FOLDER, CERTIFICATE_FOLDER


class CertificateService:
    certificates_list = []                                                              # certificates list

    def __init__(self, admin:Admin=None) -> None:
        self.admin = admin                                                              #admin object only needed when issuing certificate
    
    def get_public_key(self, public_key_path):                                          # getting public key from the path and returning it as an object
        with open(public_key_path, "rb") as key_file:
            public_key =  serialization.load_pem_public_key(key_file.read())
        return public_key
    
    def get_issuer_private_key(self):                                                      # getting user private key and returning it as an object
        private_key_path = os.path.join(KEY_FOLDER, APP_PRIVATE_KEY_NAME)            

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=self.admin.password.encode(),                                                           
        )
        return private_key
        

    def creating_and_signing_certificate(self, subject_name): 
        if(self.admin == None):                                                              
            messagebox.showerror("No admin", "There is no admin object")
            return None
        
        subject = Name([NameAttribute(NameOID.COMMON_NAME, subject_name)])                         # creating subject identity, Name - a list of attributes, NameAttribute - one attribute, NameOID.COMMON_NAME - inform us that it's a name of subject
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, self.admin.name)])                        # creating authority identity
        serial_number = random.randint(1, 2**64 - 1)                                                  # generating serial number in 64-bit range

        user_public_key_path = os.path.join(PROJECT_FOLDER, f"{subject_name}_public.pem") 
        public_key = self.get_public_key(user_public_key_path)                                          # user public key
        builder = CertificateBuilder(                                                                   # building the certificate
            issuer_name = issuer,                                                                       # who is making an certificate
            subject_name = subject,                                                                     # who need to have certificate
            serial_number = serial_number,                                                              # serial number
            public_key = public_key,                                                                    # user public key
            not_valid_before = datetime.datetime.now(timezone.utc),                                     # when certificate was created - time right now
            not_valid_after = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365),       # when certificate lasts - time year later
            )
        
        private_key = self.get_issuer_private_key()                                                  # app private key

        signed_certificate = builder.sign(                                                          # signing certificate
            private_key = private_key,                                                              # authority key
            algorithm = hashes.SHA256(),
            )
        self.writing_certificate_to_folder(signed_certificate, subject_name)                                      # putting certificat to the certificates folder
        
        return signed_certificate
    
    def writing_certificate_to_folder(self, certificate:Certificate, name):                                    
        os.makedirs(CERTIFICATE_FOLDER, exist_ok=True)                                                          # checking if certificate folder exist if not create it
        pem_certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)                         # putting certificate class to the .pem file
        file_path = os.path.join(CERTIFICATE_FOLDER, f"{name}_certificate.pem")                                 
        write_file(file_path, pem_certificate)                                                                  # writing certificate to the file
        
    def load_certificate_from_folder(self):                                                                     # getting all certificates from the forlder certificates
        if os.path.isdir(CERTIFICATE_FOLDER):
            for file_name in os.listdir(CERTIFICATE_FOLDER):
                file_path = os.path.join(CERTIFICATE_FOLDER, file_name)
                
                if file_name.endswith(".pem") or file_name.endswith(".crt"):
                    try:
                        certificate_file = read_file(file_path)
               
                        try:
                            certificate = load_pem_x509_certificate(certificate_file)
                            CertificateService.certificates_list.append(certificate)
                            messagebox.showinfo("Uploading PEM certificate",f"Uploading certificate PEM: {file_name} went correctly")
                            
                        except ValueError:
                            try:
                                certificate = load_der_x509_certificate(certificate_file)
                                CertificateService.certificates_list.append(certificate)
                                messagebox.showinfo("Uploading DER certificate",f"Uploading certificate DER: {file_name} went correctly")
                                
                            except ValueError:
                                messagebox.showerror("Uploading certificate error", f"Uploading certificate: {file_name} failed")
                                
                    except Exception:
                        messagebox.showerror("Opening certificate error", f"Opening certificate {file_name} file failed")
        else:
            messagebox.showerror("No folder error", "Certificate folder doesn't exist")
            
    def get_common_name_from_certificate(self, certificate:Certificate):                                # getting name of the certificate's user
        subject = certificate.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    
        if common_name:                            
            return common_name[0].value
        return None 

    def check_certificate_validity(self, certificate:Certificate):
        try:
            now = datetime.datetime.now(datetime.timezone.utc)

            certificate_not_valid_before = certificate.not_valid_before_utc
            certificate_not_valid_after = certificate.not_valid_after_utc

            if now < certificate_not_valid_before or now > certificate_not_valid_after:
                messagebox.showerror("Certificate is not valid", f"Certificate {certificate.serial_number} is expired")
                return False
            
            try:
                authority_public_key_path = os.path.join(KEY_FOLDER, "app_public.pem")
                authority_public_key = self.get_public_key(authority_public_key_path)
                
                authority_public_key.verify(                                                    
                    certificate.signature,                                                      # signature generated by the certificate issuer (admin) using their private key
                    certificate.tbs_certificate_bytes,                                          # TBS stands for "To Be Signed", represents the part of the certificate that was signed by the issuer's private key
                    padding.PKCS1v15(),                                                         # specify the padding scheme
                    certificate.signature_hash_algorithm,                                       # hashing algorithm used in signature
                )
                messagebox.showinfo("Certificate is valid",f"The signature of certificate {certificate.serial_number} is correct")
            except InvalidSignature:
                messagebox.showerror("Certificate is invalid", f"The signature of certificate {certificate.serial_number} is invalid.")
                return None
            except Exception as e:
                messagebox.showerror("Error", f"Error during certificate signature verification {certificate.serial_number}: {e}")
                return None
            public_key = certificate.public_key()                                               # getting user public key from certificate
            
            return public_key

        except Exception as e:
            messagebox.showerror("Error", f"Error during certificate verification {certificate.serial_number}: {e}")
            return None
        
    @classmethod
    def get_certificate_list(cls):
        return cls.certificates_list

    

if __name__ == '__main__':
    admin = Admin()
    admin.create_all_admin_keys()

    certificate = CertificateService(admin)
    generate_rsa_keys("user1", "password1")
    certificate.creating_and_signing_certificate("user1")
    certificate.load_certificate_from_folder()
    liste = CertificateService.get_certificate_list()
    print(liste[0])
    certificate.check_certificate_validity(liste[0])
    

    

# https://cryptography.io/en/latest/x509/reference/