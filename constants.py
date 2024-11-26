import os

PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__)) 

KEY_FOLDER_NAME = "KeyFolder"
KEY_FOLDER = os.path.join(PROJECT_FOLDER, KEY_FOLDER_NAME)

APP_PRIVATE_KEY_NAME = "app_private.pem"
APP_PUBLIC_KEY_NAME = "app_public.pem"
APP_AES_NAME = "app_aes.key.enc"

APP_PRIVATE_KEY_PATH = os.path.join(KEY_FOLDER, APP_PRIVATE_KEY_NAME)
APP_PUBLIC_KEY_PATH = os.path.join(KEY_FOLDER, APP_PUBLIC_KEY_NAME)
APP_AES_PATH = os.path.join(KEY_FOLDER, APP_AES_NAME)

CERTIFICATE_FOLDER_NAME = "certificates"
CERTIFICATE_FOLDER = os.path.join(PROJECT_FOLDER, CERTIFICATE_FOLDER_NAME)
