from crypto.admin import Admin
from crypto.certificate_service import CertificateService
from crypto.rsa import generate_rsa_keys
from crypto.header import *
from coding import *
from Crypto.Random import get_random_bytes

# CASE 0
#CREATING ADMIN KEYS (only once, no need for GUI)
# admin = Admin()
# admin.create_all_admin_keys()

# CASE 1
#CREATING USER KEYS (all)
# generate_rsa_keys("user1", "password1")

# CASE 2
# ISSUING CERTIFICATES (admin needed)
# admin = Admin()
# certService = CertificateService(admin)
# certService.creating_and_signing_certificate("user1")


# CASE 3
# ENCRYPTING FILES (admin needed)
# admin = Admin()
# certificate = CertificateService()
# certificate.load_certificate_from_folder()
# liste = CertificateService.get_certificate_list()
# certificate.check_certificate_validity(liste[0])     #in general need to check for all certificates
# key = admin.get_decrypted_aes_key()
# encrypt_folder("example", "g", key)
# create_header(liste, key, "example")

# CASE 4
# DECRYPTING FILES (NO admin needed)
# certificate = CertificateService()
# certificate.load_certificate_from_folder()
# certificate.check_certificate_validity(certificate.get_certificate_list()[0]) #in general need to check for all certificates
# key = get_key_from_header("example/header.json", "user1_private.pem", "user1", "password1")
# decrypt_folder("example", key, "g")