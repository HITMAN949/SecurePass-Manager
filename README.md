# SecurePass Manager

SecurePass Manager is a simple password manager application built with Python and Tkinter, utilizing cryptography for secure password storage and retrieval.

## Features

- **Master Password**: Set a master password to encrypt and decrypt stored passwords.
- **Encryption**: Uses AES encryption in CFB mode for storing passwords securely.
- **Storage**: Passwords are stored locally in a file (`passwords.txt`), encrypted with the master password.
- **GUI Interface**: Provides a user-friendly graphical interface using Tkinter for managing passwords.

## Installation

1. Clone the repository:

git clone https://github.com/your-username/securepass-manager.git

cd securepass-manager

2. Install dependencies:

pip install cryptography

3. Run the application:

python securepass_manager.py

## Usage

1. **Setting Master Password**:
- Launch the application and set your master password. This password is used for encrypting and decrypting other passwords stored in the manager.

2. **Saving Passwords**:
- Enter the service name and password, then click "Save Password" to encrypt and store the password securely.

3. **Retrieving Passwords**:
- Enter the service name and click "Retrieve Password" to decrypt and display the stored password.

## Security Considerations

- **Master Password**: Choose a strong master password to ensure the security of stored passwords.
- **Encryption**: Uses AES encryption with a randomly generated initialization vector (IV) for each password entry.
- **Salt**: A random salt is generated and used for key derivation to enhance security.

## Notes

- **File Storage**: Passwords are stored in a plaintext file (`passwords.txt`). Consider additional security measures for production use, such as encrypting the entire file or using a secure database.
- **Disclaimer**: This application is intended for educational purposes and may require further enhancements for use in production environments.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
