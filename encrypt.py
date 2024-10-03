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
        encrypted_file_path = f"{base_name}_encrypted{file_extension}"
        
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


def create_decryption_script():
    # Todo
    decryption_script_content = "# Decryption logic"

    # Write the decryption script to a file
    with open('decryption_script.py', 'w') as script_file:
        script_file.write(decryption_script_content)
    
    print("The decryption script has been created as 'decryption_script.py'.")
    return


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

    create_decryption_script()
    
    # Print results
    print(f"Encryption complete for folder: {folder_path}.", f"Encrypted {len(encrypted_files)} out of {len(encrypted_files) + len(failed_files)} files.")
    
    if failed_files:
        print("Failed to encrypt the following files:")
        for failed_file in failed_files:
            print(f"- {failed_file}")


def display_error(message):
    print(f"Error: {message}")

# Main

# Example of usage:
# Enter non-absolute path of the folder (for now)
# folder_path = 'example'
# password = 'pass'

# To clean up use: rm example/*encrypted*

def main():
    folder_path = folder_input()
    if folder_path:
        password = password_input()
        if password:
            encrypt_folder(folder_path, password)

if __name__ == '__main__':
    main()

# To discuss:
# - i will
# - will we use absolute path for the folder input?
# - will we encrypt recursively every subfolder in the chosen folder?
# - we should edit SUPPORTED_EXTENSIONS.
# - how should we change the names of the files after encryption?