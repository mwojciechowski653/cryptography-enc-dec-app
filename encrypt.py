import os

SUPPORTED_EXTENSIONS = ['.txt', '.jpg', '.png', '.pdf', '.docx']


def folder_input():
    while True:
        folder_path = input('Enter the folder path to encrypt: ')
        
        # Check if the provided path is a valid directory
        if not os.path.isdir(folder_path):
            display_error("Invalid folder path! Please try again.")
            continue  # Prompt user again
        
        # Check if the folder is empty
        if not os.listdir(folder_path):
            display_error("The folder is empty! Please try again.")
            continue  # Prompt user again
        
        # If everything is valid, return the folder path
        return folder_path


def password_input():
    while True:
        password = input('Enter a password: ')
        
        # Check if the password is empty
        if not password:
            display_error("Password cannot be empty! Please try again.")
        else:
            return password  # Return the valid password


def encode(file, password):
    # Get the file extension
    base_name, file_extension = os.path.splitext(file)

    # Check if the file extension is supported
    if file_extension.lower() not in SUPPORTED_EXTENSIONS:
        display_error(f"Unsupported file extension: {file_extension}. Skipping file.")
        return False  # Indicate that encryption was not successful

    try:
        print(f"Encrypting file: {file}.")
        
        # Create the encrypted file with .enc extension
        encrypted_file_path = f"{base_name}.enc"
        
        # Creating an empty file.
        with open(encrypted_file_path, 'w') as enc_file:
            # Todo
            # Replace with actual encrypted data
            enc_file.write("Encrypted data.")  
        
        # Delete the original file (commented out for safety)
        # os.remove(file)
        
        return True  # Indicate that encryption was successful
    except Exception as e:
        display_error(f"Error encrypting {file}: {e}")
        return False  # Indicate that encryption was not successful


def encrypt_folder(folder_path, password):
    # Lists to keep track of encrypted and failed files
    encrypted_files = []
    failed_files = []
    
    # List all files in the folder
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        
        # Only process files, not directories
        if os.path.isfile(file_path):
            # Try to encrypt the file and handle exceptions
            try:
                success = encode(file_path, password)
                if success:
                    encrypted_files.append(file_name)  # Add to encrypted list
                else:
                    failed_files.append(file_name)  # Add to failed list
            except Exception as e:
                # If there's an error during encoding, log the error and file name
                print(f"Error encrypting {file_name}: {e}")
                failed_files.append(file_name)
    
    # Print results
    print(f"Encryption complete for folder: {folder_path}.", f"Encrypted {len(encrypted_files)} out of {len(encrypted_files) + len(failed_files)} files.")
    
    if failed_files:
        print("Failed to encrypt the following files:")
        for failed_file in failed_files:
            print(f"- {failed_file}")


def decode(file, password):
    # Todo
    # decrypt the file and delete the *.enc file
    print(f"Decrypting file: {file}.")
    

def decrypt_folder(folder_path, password):
    # Check for .enc files in the specified folder
    enc_files = [file_name for file_name in os.listdir(folder_path) if file_name.endswith('.enc')]

    if not enc_files:
        display_error("No encrypted files (.enc) found in the specified folder.")
        return
    
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.enc'):  # Assuming encrypted files have .enc extension
            file_path = os.path.join(folder_path, file_name)
            decode(file_path, password)
    print("Decryption complete.")


def display_error(message):
    print(f"Error: {message}")


def main():
    while True:
        print("Choose an option:")
        print("1. Encrypt files")
        print("2. Decrypt files")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            folder_path = folder_input()
            password = password_input()
            encrypt_folder(folder_path, password)
            print("Encryption complete.")
        elif choice == '2':
            folder_path = folder_input()
            password = password_input()
            decrypt_folder(folder_path, password)
        elif choice == '3':
            print("Exiting the application.")
            break
        else:
            display_error("Invalid choice! Please try again.")

if __name__ == '__main__':
    main()


# Example of usage:
# Choose number from the menu: 1
# Enter non-absolute path of the folder (for now)
# folder_path = 'example'
# password = 'pass'
# To clean up use: rm example/*.enc
