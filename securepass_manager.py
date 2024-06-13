import os
import base64
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

backend = default_backend()

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for 256-bit key
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(password: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(password.encode()) + encryptor.finalize()
    return iv + ct

def decrypt(token: bytes, key: bytes) -> str:
    iv = token[:16]
    ct = token[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    password = decryptor.update(ct) + decryptor.finalize()
    return password.decode()

def save_password(service: str, password: str, master_key: bytes):
    encrypted_password = encrypt(password, master_key)
    with open("passwords.txt", "a") as file:
        file.write(service + "," + base64.urlsafe_b64encode(encrypted_password).decode() + "\n")

def load_password(service: str, master_key: bytes) -> str:
    try:
        with open("passwords.txt", "r") as file:
            for line in file:
                stored_service, encrypted_password = line.strip().split(",")
                if stored_service == service:
                    encrypted_password = base64.urlsafe_b64decode(encrypted_password)
                    return decrypt(encrypted_password, master_key)
    except FileNotFoundError:
        return None
    return None

class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("400x300")

        self.master_key = None  # Initialize master_key to None

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Master Password:").pack(pady=5)
        self.master_password_entry = tk.Entry(self, show="*")
        self.master_password_entry.pack(pady=5)

        tk.Button(self, text="Set Master Password", command=self.set_master_password).pack(pady=5)

        self.service_var = tk.StringVar()
        tk.Label(self, text="Service:").pack(pady=5)
        tk.Entry(self, textvariable=self.service_var).pack(pady=5)

        self.password_var = tk.StringVar()
        tk.Label(self, text="Password:").pack(pady=5)
        tk.Entry(self, textvariable=self.password_var, show="*").pack(pady=5)

        tk.Button(self, text="Save Password", command=self.save_password).pack(pady=5)
        tk.Button(self, text="Retrieve Password", command=self.retrieve_password).pack(pady=5)

    def set_master_password(self):
        self.master_password = self.master_password_entry.get()
        self.salt = os.urandom(16)  # Generate a unique salt for each session
        self.master_key = generate_key(self.master_password, self.salt)
        messagebox.showinfo("Info", "Master password set!")

    def save_password(self):
        if self.master_key is None:
            messagebox.showwarning("Warning", "Please set the master password first.")
            return
        service = self.service_var.get()
        password = self.password_var.get()
        if service and password:
            save_password(service, password, self.master_key)
            messagebox.showinfo("Info", f"Password for {service} saved!")
        else:
            messagebox.showwarning("Warning", "Please enter both service and password.")

    def retrieve_password(self):
        if self.master_key is None:
            messagebox.showwarning("Warning", "Please set the master password first.")
            return
        service = self.service_var.get()
        if service:
            password = load_password(service, self.master_key)
            if password:
                messagebox.showinfo("Info", f"Password for {service} is {password}")
            else:
                messagebox.showwarning("Warning", f"No password found for {service}.")
        else:
            messagebox.showwarning("Warning", "Please enter a service name.")

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
