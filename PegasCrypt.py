import tkinter as tk
from tkinter import messagebox, ttk
import os
import secrets
import tarfile
import io
import shutil

# Required: pip install cryptography tkinterdnd2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import tkinterdnd2 as dnd

# --- Translation Data ---
TRANSLATIONS = {
    'window_title': {'en': "PegasCrypt V8.3", 'ru': "PegasCrypt V8.3"},
    'extension_label': {'en': "Extension:", 'ru': "Расширение:"},
    'drop_prompt': {'en': "Drag & Drop File or Folder Here for Analysis...", 'ru': "Перетащите файл или папку сюда для анализа..."},
    'choose_item': {'en': "[ Choose Item ]", 'ru': "[ Выберите элемент ]"},
    'encrypt_file': {'en': "[ Encrypt File ]", 'ru': "[ Зашифровать файл ]"},
    'decrypt_file': {'en': "[ Decrypt File ]", 'ru': "[ Расшифровать файл ]"},
    'encrypt_folder': {'en': "[ Encrypt Folder ]", 'ru': "[ Зашифровать папку ]"},
    'decrypt_folder': {'en': "[ Decrypt Folder ]", 'ru': "[ Расшифровать папку ]"},
    'status_ready': {'en': "Ready. Awaiting file or folder drop...", 'ru': "Готов к работе. Перетащите файл или папку..."},
    'status_analyzing': {'en': "Analyzing: {item_name}", 'ru': "Анализ: {item_name}"},
    'status_encrypted_as': {'en': "Success! Encrypted as {item_name}", 'ru': "Успех! Зашифрован как {item_name}"},
    'status_decrypted_as': {'en': "Success! Decrypted as {item_name}", 'ru': "Успех! Расшифрован как {item_name}"},
    'op_complete': {'en': "Operation complete.\n\nDrag the next item...", 'ru': "Операция завершена.\n\nПеретащите следующий элемент..."},
    'preview_header_file': {'en': "File:", 'ru': "Файл:"},
    'preview_header_folder': {'en': "Folder:", 'ru': "Папка:"},
    'preview_size': {'en': "Size:", 'ru': "Размер:"},
    'preview_mode_encrypt': {'en': "Mode: Encryption", 'ru': "Режим: Шифрование"},
    'preview_mode_decrypt': {'en': "Mode: Decryption", 'ru': "Режим: Расшифровка"},
    'preview_content_start': {'en': "Content (start):", 'ru': "Содержимое (начало):"},
    'preview_folder_content': {'en': "Contains {count} files/folders.", 'ru': "Содержит {count} файлов/папок."},
    'preview_recovered_name': {'en': "Recovered name:", 'ru': "Восстановленное имя:"},
    'preview_decrypted_content': {'en': "Content (decrypted start):", 'ru': "Содержимое (расшифрованное начало):"},
    'preview_access_denied': {'en': ">>> ACCESS DENIED <<<\n\nInvalid password or corrupted data.", 'ru': ">>> ДОСТУП ЗАПРЕЩЕН <<<\n\nНеверный пароль или файл поврежден."},
    'err_read_error': {'en': "Error reading file: {e}", 'ru': "Ошибка чтения файла: {e}"},
    'err_preview_error': {'en': "Error during preview: {e}", 'ru': "Ошибка при предпросмотре: {e}"},
    'err_encryption_title': {'en': "Encryption Error", 'ru': "Ошибка шифрования"},
    'err_decryption_fail': {'en': "Decryption failed. Invalid password or corrupted file!", 'ru': "Расшифровка не удалась. Неверный пароль или файл поврежден!"},
    'err_unexpected': {'en': "An unexpected error occurred:\n{e}", 'ru': "Произошла непредвиденная ошибка:\n{e}"},
    'confirm_overwrite_title': {'en': "Confirm", 'ru': "Подтверждение"},
    'confirm_overwrite_q': {'en': "Item '{name}' already exists. Overwrite?", 'ru': "Элемент '{name}' уже существует. Перезаписать?"},
    'password_prompt_preview': {'en': "Password for preview:", 'ru': "Пароль для предпросмотра:"},
    'password_prompt_encrypt': {'en': "Password for encryption:", 'ru': "Пароль для шифрования:"},
    'password_prompt_decrypt': {'en': "Password for decryption:", 'ru': "Пароль для расшифровки:"},
    'password_ok': {'en': "[ OK ]", 'ru': "[ OK ]"},
    'password_cancel': {'en': "[ Cancel ]", 'ru': "[ Отмена ]"},
}

# --- Constants & Style ---
BG_COLOR, FG_COLOR, ACCENT_BG, ACCENT_FG, ACTIVE_BG = "#000000", "#00FF00", "#002200", "#33FF33", "#003300"
FONT_FAMILY = "Courier"
PREVIEW_SIZE, FOLDER_MARKER = 4096, "__DIR__:"

# --- UI Components ---
class HoverButton(tk.Button):
    def __init__(self, master, **kw):
        super().__init__(master=master, **kw)
        self.defaultBackground = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    def on_enter(self, e): self['background'] = self['activebackground']
    def on_leave(self, e): self['background'] = self.defaultBackground

class CustomPasswordDialog(tk.Toplevel):
    def __init__(self, parent, parent_app, prompt="Enter password:"):
        super().__init__(parent)
        self.parent_app = parent_app
        self.result = None
        self.title("")
        self.geometry("350x150"); self.configure(bg=BG_COLOR); self.overrideredirect(True)
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 175
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 75
        self.geometry(f"+{x}+{y}")
        main_frame = tk.Frame(self, bg=BG_COLOR, highlightbackground=FG_COLOR, highlightthickness=1)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        tk.Label(main_frame, text=prompt, bg=BG_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 12)).pack(pady=(20, 5))
        self.password_entry = tk.Entry(main_frame, show="*", bg=ACCENT_BG, fg=FG_COLOR, insertbackground=FG_COLOR, font=(FONT_FAMILY, 12), relief=tk.FLAT, width=25)
        self.password_entry.pack(pady=5); self.password_entry.focus_set()
        button_frame = tk.Frame(main_frame, bg=BG_COLOR); button_frame.pack(pady=10)
        HoverButton(button_frame, text=self.parent_app._('password_ok'), command=self.on_ok, bg=ACCENT_BG, fg=FG_COLOR, activebackground=ACTIVE_BG, activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 10)).pack(side=tk.LEFT, padx=10)
        HoverButton(button_frame, text=self.parent_app._('password_cancel'), command=self.on_cancel, bg=ACCENT_BG, fg=FG_COLOR, activebackground=ACTIVE_BG, activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 10)).pack(side=tk.LEFT, padx=10)
        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())
    def on_ok(self):
        self.result = self.password_entry.get()
        if self.result: self.destroy()
    def on_cancel(self): self.result = None; self.destroy()

class Scanlines(tk.Canvas):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.bind("<Configure>", self.draw_scanlines)
    def draw_scanlines(self, event=None):
        self.delete("all")
        width, height = self.winfo_width(), self.winfo_height()
        for i in range(0, height, 2):
            self.create_line(0, i, width, i, fill="#001a00")

# --- Main Application ---
class CryptoTerminalApp:
    def __init__(self, master):
        self.master = master
        self.current_lang = 'ru'
        self.current_item_path = None
        self.is_folder = False
        self.cached_password = None
        self._setup_styles()
        self._create_widgets()
        self.retranslate_ui()

    def _(self, key):
        return TRANSLATIONS.get(key, {}).get(self.current_lang, key)

    def _setup_styles(self):
        self.master.geometry("600x600"); self.master.configure(bg=BG_COLOR); self.master.minsize(500, 400)
        style = ttk.Style(); style.theme_use('default')
        style.configure('TRadiobutton', background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, 10))
        style.map('TRadiobutton', background=[('active', BG_COLOR)], indicatorcolor=[('selected', FG_COLOR), ('!selected', ACCENT_BG)])

    def _create_widgets(self):
        Scanlines(self.master, bg=BG_COLOR, highlightthickness=0).place(relx=0, rely=0, relwidth=1, relheight=1)
        top_frame = tk.Frame(self.master, bg=BG_COLOR); top_frame.pack(fill=tk.X, padx=20, pady=10)
        self.extension_label = tk.Label(top_frame, bg=BG_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 10))
        self.extension_label.pack(side=tk.LEFT, padx=(0, 10))
        self.extension_var = tk.StringVar(value=".Pegas")
        ttk.Radiobutton(top_frame, text=".Pegas", variable=self.extension_var, value=".Pegas").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(top_frame, text=".ALX", variable=self.extension_var, value=".ALX").pack(side=tk.LEFT)
        self.lang_button = HoverButton(top_frame, command=self.toggle_language, bg=ACCENT_BG, fg=FG_COLOR, activebackground=ACTIVE_BG, activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 10, 'bold'))
        self.lang_button.pack(side=tk.RIGHT, padx=5)
        drop_frame = tk.Frame(self.master, bg=ACCENT_BG, relief=tk.SOLID, bd=1)
        drop_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)
        self.preview_text = tk.Text(drop_frame, bg=ACCENT_BG, fg=FG_COLOR, font=(FONT_FAMILY, 10), relief=tk.FLAT, bd=0, wrap=tk.WORD, insertbackground=FG_COLOR)
        self.preview_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        drop_frame.drop_target_register(dnd.DND_FILES)
        drop_frame.dnd_bind('<<Drop>>', self.handle_drop)
        drop_frame.dnd_bind('<<DragEnter>>', lambda e: drop_frame.config(bg=ACTIVE_BG))
        drop_frame.dnd_bind('<<DragLeave>>', lambda e: drop_frame.config(bg=ACCENT_BG))
        bottom_frame = tk.Frame(self.master, bg=BG_COLOR); bottom_frame.pack(fill=tk.X, padx=20, pady=10)
        self.action_button = HoverButton(bottom_frame, bg=ACCENT_BG, fg=ACCENT_FG, activebackground=ACTIVE_BG, activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 12, 'bold'), disabledforeground="#555")
        self.action_button.pack(expand=True, fill=tk.X, ipady=15)
        self.status_label = tk.Label(self.master, fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, 10))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=5)

    def toggle_language(self):
        self.current_lang = 'en' if self.current_lang == 'ru' else 'ru'
        self.retranslate_ui()
    
    def retranslate_ui(self):
        self.master.title(self._('window_title'))
        self.extension_label.config(text=self._('extension_label'))
        lang_btn_text = "[ RU ]" if self.current_lang == 'en' else "[ EN ]"
        self.lang_button.config(text=lang_btn_text)
        self.reset_state(initial=True)

    def animate_text(self, widget, text, index):
        if index <= len(text):
            widget.config(text=text[:index] + "_"); self.master.after(30, self.animate_text, widget, text, index + 1)
        else: widget.config(text=text)

    def handle_drop(self, event):
        filepath = event.data.strip('{}')
        if os.path.exists(filepath): self.process_item(filepath)
        else: self.animate_text(self.status_label, _('err_file_not_found').format(path=filepath), 0)

    def process_item(self, path):
        self.reset_state(clear_preview=False)
        self.current_item_path = path; self.is_folder = os.path.isdir(path)
        item_name = os.path.basename(path); file_ext = os.path.splitext(item_name)[1]
        self.preview_text.config(state=tk.NORMAL); self.preview_text.delete(1.0, tk.END)
        if file_ext.lower() in ['.alx', '.pegas']:
            self.action_button.config(command=self.decrypt_item)
            self.show_encrypted_preview()
        else:
            self.action_button.config(command=self.encrypt_item)
            if self.is_folder:
                self.action_button.config(text=self._('encrypt_folder')); self.show_folder_preview()
            else:
                self.action_button.config(text=self._('encrypt_file')); self.show_unencrypted_preview()
        self.action_button.config(state=tk.NORMAL)
        self.animate_text(self.status_label, self._('status_analyzing').format(item_name=item_name), 0)

    def show_unencrypted_preview(self):
        try:
            filename, filesize = os.path.basename(self.current_item_path), os.path.getsize(self.current_item_path)
            header = f"{self._('preview_header_file')} {filename}\n{self._('preview_size')} {filesize} bytes\n{self._('preview_mode_encrypt')}\n" + "-" * 40 + "\n\n"
            with open(self.current_item_path, 'rb') as f: preview_data = f.read(PREVIEW_SIZE)
            content = f"{self._('preview_content_start')}\n\n{preview_data.decode('utf-8', errors='ignore')}"
        except Exception as e: content = self._('err_read_error').format(e=e)
        self.preview_text.insert(tk.END, header + content); self.preview_text.config(state=tk.DISABLED)
        
    def show_folder_preview(self):
        try:
            foldername = os.path.basename(self.current_item_path)
            total_size, total_files = 0, 0
            for _, _, filenames in os.walk(self.current_item_path): total_files += len(filenames)
            header = f"{self._('preview_header_folder')} {foldername}\n{self._('preview_mode_encrypt')}\n" + "-" * 40 + "\n\n"
            content = self._('preview_folder_content').format(count=total_files)
        except Exception as e: content = self._('err_read_error').format(e=e)
        self.preview_text.insert(tk.END, header + content); self.preview_text.config(state=tk.DISABLED)

    def show_encrypted_preview(self):
        password = self.get_password(self._('password_prompt_preview'))
        if not password: self.reset_state(); return
        item_name, item_size = os.path.basename(self.current_item_path), os.path.getsize(self.current_item_path)
        header = f"{self._('preview_header_file')} {item_name}\n{self._('preview_size')} {item_size} bytes\n{self._('preview_mode_decrypt')}\n" + "-" * 40 + "\n\n"
        try:
            preview_data, original_name = self.get_preview_data(password)
            if preview_data is None:
                # ИСПРАВЛЕНО: Разделяем присвоение и вызов функции
                content = self._('preview_access_denied')
                self.action_button.config(state=tk.DISABLED)
            else:
                self.cached_password = password
                if original_name.startswith(FOLDER_MARKER):
                    self.action_button.config(text=self._('decrypt_folder'))
                    display_name = original_name.replace(FOLDER_MARKER, "")
                    content = f"{self._('preview_recovered_name')} {display_name} (Folder)\n\nEncrypted archive data..."
                else:
                    self.action_button.config(text=self._('decrypt_file'))
                    text_preview = preview_data.decode('utf-8', errors='ignore')
                    content = f"{self._('preview_recovered_name')} {original_name}\n\n{self._('preview_decrypted_content')}\n\n{text_preview}"
        except Exception as e: content = self._('err_preview_error').format(e=e)
        self.preview_text.insert(tk.END, header + content); self.preview_text.config(state=tk.DISABLED)

    def get_password(self, prompt):
        dialog = CustomPasswordDialog(self.master, parent_app=self, prompt=prompt)
        self.master.wait_window(dialog); return dialog.result

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        return kdf.derive(password.encode())

    def get_preview_data(self, password):
        try:
            with open(self.current_item_path, 'rb') as f: data = f.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes, ciphertext = data[46:46 + filename_len], data[46 + filename_len:]
            original_filename = filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext[:PREVIEW_SIZE], original_filename
        except (InvalidTag, ValueError, IndexError): return None, None

    def encrypt_item(self):
        if not self.current_item_path: return
        password = self.get_password(self._('password_prompt_encrypt'));
        if not password: return
        try:
            original_name = os.path.basename(self.current_item_path)
            if self.is_folder:
                in_memory_archive = io.BytesIO()
                with tarfile.open(fileobj=in_memory_archive, mode="w:gz") as tar: tar.add(self.current_item_path, arcname=original_name)
                plaintext, original_name = in_memory_archive.getvalue(), FOLDER_MARKER + original_name
            else:
                with open(self.current_item_path, 'rb') as f: plaintext = f.read()
            salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
            key = self.derive_key(password, salt)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            original_name_bytes = original_name.encode('utf-8')
            encrypted_data = salt + iv + encryptor.tag + len(original_name_bytes).to_bytes(2, 'big') + original_name_bytes + ciphertext
            new_path = os.path.join(os.path.dirname(self.current_item_path), os.path.splitext(os.path.basename(self.current_item_path))[0] + self.extension_var.get())
            with open(new_path, 'wb') as f: f.write(encrypted_data)
            if self.is_folder: shutil.rmtree(self.current_item_path)
            else: os.remove(self.current_item_path)
            self.animate_text(self.status_label, self._('status_encrypted_as').format(item_name=os.path.basename(new_path)), 0)
            self.reset_state()
        except Exception as e: messagebox.showerror(self._('err_encryption_title'), str(e), parent=self.master)

    def decrypt_item(self):
        if not self.current_item_path: return
        password = self.cached_password or self.get_password(self._('password_prompt_decrypt'))
        if not password: return
        try:
            with open(self.current_item_path, 'rb') as f: data = f.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big'); filename_bytes = data[46:46 + filename_len]
            ciphertext, original_name = data[46 + filename_len:], filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            output_dir = os.path.dirname(self.current_item_path)
            if original_name.startswith(FOLDER_MARKER):
                folder_name = original_name.replace(FOLDER_MARKER, ""); output_path = os.path.join(output_dir, folder_name)
                if os.path.exists(output_path) and not messagebox.askyesno(self._('confirm_overwrite_title'), self._('confirm_overwrite_q').format(name=folder_name), parent=self.master): return
                with io.BytesIO(plaintext) as mem_file:
                    with tarfile.open(fileobj=mem_file, mode="r:gz") as tar: tar.extractall(path=output_dir)
                display_name = folder_name
            else:
                output_path = os.path.join(output_dir, original_name)
                if os.path.exists(output_path) and not messagebox.askyesno(self._('confirm_overwrite_title'), self._('confirm_overwrite_q').format(name=original_name), parent=self.master): return
                with open(output_path, 'wb') as f: f.write(plaintext)
                display_name = original_name
            os.remove(self.current_item_path)
            self.animate_text(self.status_label, self._('status_decrypted_as').format(item_name=display_name), 0)
            self.reset_state()
        except (InvalidTag, ValueError, IndexError): messagebox.showerror("Error", self._('err_decryption_fail'), parent=self.master); self.cached_password = None
        except Exception as e: messagebox.showerror("Error", self._('err_unexpected').format(e=e), parent=self.master)

    def reset_state(self, clear_preview=True, initial=False):
        self.current_item_path = None; self.cached_password = None; self.is_folder = False
        self.action_button.config(state=tk.DISABLED, text=self._('choose_item'))
        if initial: prompt_text, status_text = self._('drop_prompt'), self._('status_ready')
        elif clear_preview: prompt_text, status_text = self._('op_complete'), self.status_label['text']
        else: return
        self.preview_text.config(state=tk.NORMAL); self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, prompt_text); self.preview_text.config(state=tk.DISABLED)
        if initial or clear_preview: self.animate_text(self.status_label, status_text.replace("_", ""), 0)

if __name__ == "__main__":
    root = dnd.TkinterDnD.Tk()
    app = CryptoTerminalApp(root)
    root.mainloop()