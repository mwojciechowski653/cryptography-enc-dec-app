from cryptography.x509 import Name, NameAttribute, CertificateBuilder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

from typing import DefaultDict
from encrypt import *
from utils.file_utils import *
from crypto.aes import *
from crypto.rsa import *
from admin import *


class Certificate:
    def __init__(self, subject_name, authority_name) -> None:
        self.subject_name = subject_name
        self.subject_public_key = ""
        self.authority_name = authority_name
        self.authority_private_key = ""
        
    def creating_admin(self):
        admin = Admin()
        admin.create_and_code_authority_key()
        
    def creating_certificate(self):
        subject = Name([NameAttribute(NameOID.COMMON_NAME, self.subject_name)])                 # creating subject identity, Name - a list of attributes, NameAttribute - one attribute, NameOID.COMMON_NAME - inform us that it's a name of subject
        issuer = Name([NameAttribute(NameOID.COMMON_NAME, self.authority_name)])

        builder = CertificateBuilder(
            issuer_name = issuer,                                                               # who is making an certificate
            subject_name = subject,                                                             # who need to have certificate
            #public_key = user_public_key,
            not_valid_before=datetime.datetime.utcnow(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=365),
            )
        
        signed_certificate = builder.sign(
            private_key = private_key, 
            algorithm = hashes.SHA256(),
            )

# https://cryptography.io/en/latest/x509/reference/