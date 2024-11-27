from crypto.admin import Admin
from crypto.certificate_service import CertificateService
from crypto.rsa import generate_rsa_keys
from crypto.header import *
from coding import *
from constants import *
from Crypto.Random import get_random_bytes

# CASE 0
#CREATING ADMIN KEYS (only once, no need for GUI)
# admin = Admin()
# admin.create_all_admin_keys()

# CASE 1
#CREATING USER KEYS (all)
# generate_rsa_keys("user2", "password1")

# CASE 2
# ISSUING CERTIFICATES (admin needed)
# admin = Admin()
# certService = CertificateService(admin)
# certService.creating_and_signing_certificate("user2")


# CASE 3
# ENCRYPTING FILES (admin needed)
# admin = Admin()
# certificate = CertificateService()
# certs = []
# if os.path.isdir(CERTIFICATE_FOLDER):
#    for file_name in os.listdir(CERTIFICATE_FOLDER):
#        certs.append(file_name)
# 
# # listbox for choosing what certs to respect
# choosen_cerst=[]
# certificate.load_certificate_from_folder(choosen_cerst)
# liste = CertificateService.get_certificate_list()
# users = []
# for cert in liste:
#    if certificate.check_certificate_validity(cert):   #in general need to check for all certificates
#        users.append(cert)
# key = admin.get_decrypted_aes_key()
# encrypt_folder("example", "g", key)
# create_header(users, key, "example")

# CASE 4
# DECRYPTING FILES (NO admin needed)
# certificate = CertificateService()
# certificate.load_certificate_from_folder()
# liste = CertificateService.get_certificate_list()
# mine_certs = []
# for cert in liste:
#     if str(cert.subject).split(sep="=")[1][:-2] == "user1":
#         mine_certs.append(cert)
# for my_cert in mine_certs:
#     print(my_cert.subject)
#     certificate.check_certificate_validity(my_cert) #in general need to check for all certificates
# if at least one will be fine go with decryption
# key = get_key_from_header("example/header.json", "user1_private.pem", "user1", "password1")
# decrypt_folder("example", key, "g")