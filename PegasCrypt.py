import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class AdvancedEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Encryption/Decryption")
        master.geometry("400x250")
        master.configure(bg='black')

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file, bg="green", fg="black")
        self.encrypt_button.pack(pady=20)

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file, bg="green", fg="black")
        self.decrypt_button.pack(pady=20)

        self.status_label = tk.Label(master, text="Ready", fg="green", bg="black")
        self.status_label.pack(pady=20)

    def get_password(self):
        return simpledialog.askstring("Password", "Enter password:", show='*')

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if not file_path:
            return

        password = self.get_password()
        if not password:
            return

        try:
            with open(file_path, 'rb') as file:
                plaintext = file.read()

            salt = secrets.token_bytes(16)
            key = self.derive_key(password, salt)
            iv = secrets.token_bytes(12)
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            encrypted_data = salt + iv + encryptor.tag + ciphertext

            new_file_path = file_path + '.encrypted'
            with open(new_file_path, 'wb') as file:
                file.write(encrypted_data)

            os.remove(file_path)
            self.status_label.config(text="File encrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
        if not file_path:
            return

        password = self.get_password()
        if not password:
            return

        try:
            with open(file_path, 'rb') as file:
                data = file.read()

            salt = data[:16]
            iv = data[16:28]
            tag = data[28:44]
            ciphertext = data[44:]

            key = self.derive_key(password, salt)
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            new_file_path = os.path.splitext(file_path)[0]
            with open(new_file_path, 'wb') as file:
                file.write(plaintext)

            os.remove(file_path)
            self.status_label.config(text="File decrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Incorrect password or corrupted file.")

root = tk.Tk()
app = AdvancedEncryptionApp(root)
root.mainloop()