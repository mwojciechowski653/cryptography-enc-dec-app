import os

def folder_input():
    folder_path = input('Enter the folder path to encrypt: ')
    # todo ifs
    return folder_path


def password_input():
    password = input('Enter a password: ')
    # todo ifs
    return password

def encode(file, password):
    # todo
    return 

def encrypt_folder(folder_path, password):
    for file in folder_path:
        encode(file, password)

    print(folder_path, password)

def display_error(mess):
    print(mess)


folder_path = folder_input()
password = password_input()
encrypt_folder(folder_path, password)
