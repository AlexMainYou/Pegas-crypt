import tkinter as tk
from tkinter import filedialog, messagebox
import os

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Text Encryption/Decryption")
        master.geometry("400x200")
        master.configure(bg='black')

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file, bg="green", fg="black")
        self.encrypt_button.pack(pady=20)

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file, bg="green", fg="black")
        self.decrypt_button.pack(pady=20)

        self.status_label = tk.Label(master, text="Ready", fg="green", bg="black")
        self.status_label.pack(pady=20)

    def process_file(self, file_path, is_encrypting):
        try:
            with open(file_path, 'rb') as file:
                content = bytearray(file.read())

            # Simple XOR encryption/decryption
            for i in range(len(content)):
                content[i] ^= 0x42

            new_extension = '.ALX' if is_encrypting else '.txt'
            new_file_path = os.path.splitext(file_path)[0] + new_extension

            with open(new_file_path, 'wb') as file:
                file.write(content)

            os.remove(file_path)
            
            action = "encrypted" if is_encrypting else "decrypted"
            self.status_label.config(text=f"File {action} successfully")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.process_file(file_path, True)

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("ALX files", "*.ALX")])
        if file_path:
            self.process_file(file_path, False)

root = tk.Tk()
app = EncryptionApp(root)
root.mainloop()