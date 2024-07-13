import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

class AdvancedEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Продвинутое шифрование/дешифрование")
        master.geometry("400x300")
        master.configure(bg='black')

        self.encrypt_button = tk.Button(master, text="Зашифровать файл", command=self.encrypt_file, bg="green", fg="black")
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(master, text="Расшифровать файл", command=self.decrypt_file, bg="green", fg="black")
        self.decrypt_button.pack(pady=10)

        self.extension_label = tk.Label(master, text="Выберите расширение для шифрования:", fg="green", bg="black")
        self.extension_label.pack(pady=5)

        self.extension_var = tk.StringVar(value=".ALX")
        self.alx_radio = tk.Radiobutton(master, text=".ALX", variable=self.extension_var, value=".ALX", fg="green", bg="black")
        self.alx_radio.pack(side=tk.LEFT, padx=20)
        self.pegas_radio = tk.Radiobutton(master, text=".Pegas", variable=self.extension_var, value=".Pegas", fg="green", bg="black")
        self.pegas_radio.pack(side=tk.RIGHT, padx=20)

        self.status_label = tk.Label(master, text="Готово", fg="green", bg="black")
        self.status_label.pack(pady=10)

    def get_password(self):
        return simpledialog.askstring("Пароль", "Введите пароль:", show='*')

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
        file_path = filedialog.askopenfilename(filetypes=[("Все файлы", "*.*")])
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

            extension = self.extension_var.get()
            new_file_path = os.path.splitext(file_path)[0] + extension
            with open(new_file_path, 'wb') as file:
                file.write(encrypted_data)

            os.remove(file_path)
            self.status_label.config(text=f"Файл успешно зашифрован с расширением {extension}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Зашифрованные файлы", "*.ALX;*.Pegas")])
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
            self.status_label.config(text="Файл успешно расшифрован")
        except Exception as e:
            messagebox.showerror("Ошибка", "Расшифровка не удалась. Неверный пароль или поврежденный файл.")

root = tk.Tk()
app = AdvancedEncryptionApp(root)
root.mainloop()
