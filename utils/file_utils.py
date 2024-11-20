import os, shutil
from tkinter import messagebox, filedialog

def display_error(message):
    print(f"Error: {message}")

def read_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

def write_file(file_path, data):
    with open(file_path, 'wb') as f:
        f.write(data)
        
def moving_files(files, source_folder, destination_folder):
    os.makedirs(destination_folder, exist_ok=True)

    for filename in files:
        source_file = os.path.join(source_folder, filename)
        destination_file = os.path.join(destination_folder, filename)
    
        # Moving the files
        if os.path.isfile(source_file):
            shutil.move(source_file, destination_file)
            #print(f"Moved: {filename}")

        #print("All files were moved")

def folder_input(option):
    while True:
        if option == "t":
            folder_path = input('Enter the folder path to encrypt: ')
        else:
            folder_path = filedialog.askdirectory(title="Choose folder")
            
        # Check if the provided path is a valid directory
        if not os.path.isdir(folder_path):
            display_error("Invalid folder path! Please try again.")
            
            if option == "g":
                messagebox.showerror("Invalid folder path", "Invalid folder path! Please try again.")
            continue  # Prompt user again
        
        # Check if the folder is empty
        if not os.listdir(folder_path):
            display_error("The folder is empty! Please try again.")

            if option == "g":
                messagebox.showerror("The folder is empty!", "The folder is empty! Please try again.")
            continue  # Prompt user again
        
        # If everything is valid, return the folder path
        return folder_path

# def password_input():
#     while True:
#         password = input('Enter a password: ')
        
#         # Check if the password is empty
#         if not password:
#             display_error("Password cannot be empty! Please try again.")
#         else:
#             return password  # Return the valid password
        

def key_file_input(option):
    while True:
        if option == "t":
            file_path = input('Enter the file path of the key: ')
        else:
            file_path = filedialog.askopenfilename(title="Choose key file")
        
        # Check if the provided path is a valid file
        # if option != "enc":
        if not os.path.isfile(file_path):
            display_error("Invalid file path! Please try again.")
                
            if option == "g" or option == "k":
                messagebox.showerror("Invalid file path", "Invalid file path! Please try again.")
            continue  # Prompt user again
        
        # Check if the file has a .key extension
        if option == "t" or option == "g":
            if not file_path.endswith('.key'):
                display_error("File must have a .key extension! Please try again.")
                
                if option == "g":
                    messagebox.showerror(".key extension error", "File must have a .key extension! Please try again.")
                continue  # Prompt user again
        
        if option == "k":
            if not file_path.endswith('.pem'):
                display_error("Key must have a .pem extension! Please try again.")
                messagebox.showerror(".pem extension error", "Key must have a .pem extension! Please try again.")
                continue  # Prompt user again
            
        if option == "enc":
            if not file_path.endswith('.enc'):
                display_error("Content must have a .enc extension! Please try again.")
                messagebox.showerror(".enc extension error", "Content must have a .enc extension! Please try again.")
                continue  # Prompt user again
        
        # If everything is valid, return the file path
        return file_path
