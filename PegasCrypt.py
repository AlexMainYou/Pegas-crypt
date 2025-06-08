import tkinter as tk
from tkinter import messagebox, ttk
import os
import secrets

# Требуется установка: pip install cryptography tkinterdnd2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import tkinterdnd2 as dnd

# --- СТИЛЬ ---
BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
ACCENT_BG = "#002200"
ACCENT_FG = "#33FF33"
ACTIVE_BG = "#003300"
FONT_FAMILY = "Courier"
PREVIEW_SIZE = 4096 # Размер превью в байтах (4 KB)

class HoverButton(tk.Button):
    """Кнопка с эффектом наведения."""
    def __init__(self, master, **kw):
        super().__init__(master=master, **kw)
        self.defaultBackground = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self['background'] = self['activebackground']

    def on_leave(self, e):
        self['background'] = self.defaultBackground

class CustomPasswordDialog(tk.Toplevel):
    """Кастомное диалоговое окно для ввода пароля в ретро-стиле."""
    def __init__(self, parent, prompt="Введите пароль:"):
        super().__init__(parent)
        self.parent = parent
        self.result = None

        self.title("")
        self.geometry("350x150")
        self.configure(bg=BG_COLOR)
        self.overrideredirect(True)
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (350 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (150 // 2)
        self.geometry(f"+{x}+{y}")

        main_frame = tk.Frame(self, bg=BG_COLOR, highlightbackground=FG_COLOR, highlightcolor=FG_COLOR, highlightthickness=1)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        tk.Label(main_frame, text=prompt, bg=BG_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 12)).pack(pady=(20, 5))

        self.password_entry = tk.Entry(main_frame, show="*", bg=ACCENT_BG, fg=FG_COLOR,
                                       insertbackground=FG_COLOR, font=(FONT_FAMILY, 12), relief=tk.FLAT, width=25)
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()

        button_frame = tk.Frame(main_frame, bg=BG_COLOR)
        button_frame.pack(pady=10)

        ok_button = HoverButton(button_frame, text="[ OK ]", command=self.on_ok,
                                bg=ACCENT_BG, fg=FG_COLOR, activebackground=ACTIVE_BG,
                                activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 10))
        ok_button.pack(side=tk.LEFT, padx=10)

        cancel_button = HoverButton(button_frame, text="[ Отмена ]", command=self.on_cancel,
                                    bg=ACCENT_BG, fg=FG_COLOR, activebackground=ACTIVE_BG,
                                    activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 10))
        cancel_button.pack(side=tk.LEFT, padx=10)

        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())

    def on_ok(self):
        self.result = self.password_entry.get()
        if self.result:
            self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()

class Scanlines(tk.Canvas):
    """Виджет для создания эффекта старого монитора (scanlines)."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.bind("<Configure>", self.draw_scanlines)

    def draw_scanlines(self, event=None):
        self.delete("all")
        width = self.winfo_width()
        height = self.winfo_height()
        for i in range(0, height, 2):
            self.create_line(0, i, width, i, fill="#001a00")

class CryptoTerminalApp:
    def __init__(self, master):
        self.master = master
        self.current_file_path = None
        self.is_encrypt_mode = True
        self.cached_password = None # Для хранения пароля после успешного превью

        self._setup_styles()
        self._create_widgets()
        self.animate_text(self.status_label, "Готов к работе. Перетащите файл...", 0)

    def _setup_styles(self):
        self.master.title("PegasCrypt V7.0")
        self.master.geometry("600x600") # << ИЗМЕНЕНО: высота увеличена на 50px
        self.master.configure(bg=BG_COLOR)
        self.master.minsize(500, 400)

        style = ttk.Style()
        style.theme_use('default')
        style.configure('TRadiobutton', background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, 10),
                        indicatorrelief=tk.FLAT)
        style.map('TRadiobutton',
                  background=[('active', BG_COLOR)],
                  indicatorcolor=[('selected', FG_COLOR), ('!selected', ACCENT_BG)])

    def _create_widgets(self):
        scanlines = Scanlines(self.master, bg=BG_COLOR, highlightthickness=0)
        scanlines.place(relx=0, rely=0, relwidth=1, relheight=1)

        top_frame = tk.Frame(self.master, bg=BG_COLOR)
        top_frame.pack(fill=tk.X, padx=20, pady=10)

        self.extension_label = tk.Label(top_frame, text="Расширение:", bg=BG_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 10))
        self.extension_label.pack(side=tk.LEFT, padx=(0, 10))

        self.extension_var = tk.StringVar(value=".Pegas") # Изменено по умолчанию
        self.pegas_radio = ttk.Radiobutton(top_frame, text=".Pegas", variable=self.extension_var, value=".Pegas")
        self.pegas_radio.pack(side=tk.LEFT, padx=10)
        self.alx_radio = ttk.Radiobutton(top_frame, text=".ALX", variable=self.extension_var, value=".ALX")
        self.alx_radio.pack(side=tk.LEFT)

        drop_frame = tk.Frame(self.master, bg=ACCENT_BG, relief=tk.SOLID, bd=1)
        drop_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        self.preview_text = tk.Text(drop_frame, bg=ACCENT_BG, fg=FG_COLOR, font=(FONT_FAMILY, 10),
                                    relief=tk.FLAT, bd=0, wrap=tk.WORD, insertbackground=FG_COLOR)
        self.preview_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.preview_text.insert(tk.END, "Перетащите файл сюда для анализа...")
        self.preview_text.config(state=tk.DISABLED)

        drop_frame.drop_target_register(dnd.DND_FILES)
        drop_frame.dnd_bind('<<Drop>>', self.handle_drop)
        drop_frame.dnd_bind('<<DragEnter>>', lambda e: drop_frame.config(bg=ACTIVE_BG))
        drop_frame.dnd_bind('<<DragLeave>>', lambda e: drop_frame.config(bg=ACCENT_BG))

        bottom_frame = tk.Frame(self.master, bg=BG_COLOR)
        bottom_frame.pack(fill=tk.X, padx=20, pady=10)

        self.action_button = HoverButton(bottom_frame, text="[ Выберите файл ]",
                                         bg=ACCENT_BG, fg=ACCENT_FG, activebackground=ACTIVE_BG,
                                         activeforeground=FG_COLOR, relief=tk.FLAT, bd=0, font=(FONT_FAMILY, 12, 'bold'),
                                         disabledforeground="#555")
        self.action_button.pack(expand=True, fill=tk.X, ipady=15) # Увеличена высота кнопки
        self.action_button.config(state=tk.DISABLED)

        self.status_label = tk.Label(self.master, text="", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, 10))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=5)

    def animate_text(self, widget, text, index):
        if index <= len(text):
            widget.config(text=text[:index] + "_")
            self.master.after(50, self.animate_text, widget, text, index + 1)
        else:
            widget.config(text=text)

    def handle_drop(self, event):
        filepath = event.data.strip('{}')
        if os.path.exists(filepath):
            self.process_file(filepath)
        else:
            self.animate_text(self.status_label, f"Ошибка: Файл не найден '{filepath}'", 0)

    def process_file(self, file_path):
        self.reset_state(clear_preview=False) # Сбрасываем кэш, но не текст превью
        self.current_file_path = file_path
        filename = os.path.basename(file_path)
        file_ext = os.path.splitext(filename)[1]

        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)

        if file_ext.lower() in ['.alx', '.pegas']:
            self.is_encrypt_mode = False
            self.action_button.config(text="[ Расшифровать ]", command=self.decrypt_file)
            self.show_encrypted_preview()
        else:
            self.is_encrypt_mode = True
            self.action_button.config(text="[ Зашифровать ]", command=self.encrypt_file)
            self.show_unencrypted_preview()

        self.action_button.config(state=tk.NORMAL)
        self.animate_text(self.status_label, f"Анализ файла: {filename}", 0)

    def show_unencrypted_preview(self):
        try:
            filename = os.path.basename(self.current_file_path)
            filesize = os.path.getsize(self.current_file_path)

            header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Шифрование\n"
            header += "-" * 40 + "\n\n"

            with open(self.current_file_path, 'rb') as f:
                preview_data = f.read(PREVIEW_SIZE)

            try:
                text_preview = preview_data.decode('utf-8', errors='ignore')
                content = "Содержимое (начало):\n\n" + text_preview
            except UnicodeDecodeError:
                content = "Содержимое: Бинарный файл (превью не доступно)"

            self.preview_text.insert(tk.END, header + content)
        except Exception as e:
            self.preview_text.insert(tk.END, f"Ошибка чтения файла: {e}")
        finally:
            self.preview_text.config(state=tk.DISABLED)

    def show_encrypted_preview(self):
        password = self.get_password("Пароль для предпросмотра:")
        if not password:
            self.reset_state()
            return

        filename = os.path.basename(self.current_file_path)
        filesize = os.path.getsize(self.current_file_path)
        header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Расшифровка\n"
        header += "-" * 40 + "\n\n"

        try:
            preview_data, original_filename = self.get_preview_data(password)
            if preview_data is None:
                content = ">>> ДОСТУП ЗАПРЕЩЕН <<<\n\nНеверный пароль или файл поврежден."
                self.action_button.config(state=tk.DISABLED)
            else:
                self.cached_password = password # Кэшируем пароль при успехе
                try:
                    text_preview = preview_data.decode('utf-8', errors='ignore')
                    content = f"Восстановленное имя: {original_filename}\n\n"
                    content += "Содержимое (расшифрованное начало):\n\n" + text_preview
                except UnicodeDecodeError:
                    content = "Содержимое: Бинарный файл (расшифрованное начало)"
        except Exception as e:
            content = f"Ошибка при предпросмотре: {e}"

        self.preview_text.insert(tk.END, header + content)
        self.preview_text.config(state=tk.DISABLED)

    def get_password(self, prompt):
        dialog = CustomPasswordDialog(self.master, prompt)
        self.master.wait_window(dialog)
        return dialog.result

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def get_preview_data(self, password):
        """Расшифровывает первую часть файла для превью, возвращает (данные, имя_файла)."""
        try:
            with open(self.current_file_path, 'rb') as f:
                data = f.read()

            # Новый формат: [salt][iv][tag][len_fname][fname][ciphertext]
            salt = data[0:16]
            iv = data[16:28]
            tag = data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]
            original_filename = filename_bytes.decode('utf-8')

            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext[:PREVIEW_SIZE], original_filename
        except (InvalidTag, ValueError, IndexError):
            return None, None # Ошибка пароля или формата файла

    def encrypt_file(self):
        if not self.current_file_path: return

        password = self.get_password("Пароль для шифрования:")
        if not password: return

        try:
            with open(self.current_file_path, 'rb') as file:
                plaintext = file.read()

            salt = secrets.token_bytes(16)
            key = self.derive_key(password, salt)
            iv = secrets.token_bytes(12)

            original_filename_bytes = os.path.basename(self.current_file_path).encode('utf-8')
            filename_len_bytes = len(original_filename_bytes).to_bytes(2, 'big')

            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            encrypted_data = salt + iv + encryptor.tag + filename_len_bytes + original_filename_bytes + ciphertext

            extension = self.extension_var.get()
            original_dir = os.path.dirname(self.current_file_path)
            encrypted_name = os.path.splitext(os.path.basename(self.current_file_path))[0]
            new_file_path = os.path.join(original_dir, encrypted_name + extension)

            with open(new_file_path, 'wb') as file:
                file.write(encrypted_data)

            os.remove(self.current_file_path)
            self.animate_text(self.status_label, f"Успех! Зашифрован как {os.path.basename(new_file_path)}", 0)
            self.reset_state()
        except Exception as e:
            messagebox.showerror("Ошибка шифрования", str(e), parent=self.master)

    def decrypt_file(self):
        if not self.current_file_path: return

        # Используем кэшированный пароль, если он есть, иначе запрашиваем
        password = self.cached_password
        if not password:
            password = self.get_password("Пароль для расшифровки:")
        if not password: return

        try:
            with open(self.current_file_path, 'rb') as file:
                data = file.read()

            salt = data[0:16]
            iv = data[16:28]
            tag = data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]

            original_filename = filename_bytes.decode('utf-8')

            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            original_dir = os.path.dirname(self.current_file_path)
            new_file_path = os.path.join(original_dir, original_filename)

            # Проверка, чтобы не перезаписать существующий файл без спроса
            if os.path.exists(new_file_path):
                 if not messagebox.askyesno("Подтверждение", f"Файл '{original_filename}' уже существует. Перезаписать?", parent=self.master):
                     return

            with open(new_file_path, 'wb') as file:
                file.write(plaintext)

            os.remove(self.current_file_path)
            self.animate_text(self.status_label, f"Успех! Файл расшифрован как {original_filename}", 0)
            self.reset_state()
        except (InvalidTag, ValueError, IndexError):
            messagebox.showerror("Ошибка", "Расшифровка не удалась. Неверный пароль или файл поврежден!", parent=self.master)
            self.cached_password = None # Сбрасываем неверный пароль
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла непредвиденная ошибка:\n{e}", parent=self.master)

    def reset_state(self, clear_preview=True):
        """Сброс интерфейса в начальное состояние."""
        self.current_file_path = None
        self.cached_password = None # Всегда сбрасываем кэш пароля
        self.action_button.config(state=tk.DISABLED, text="[ Выберите файл ]")
        if clear_preview:
            self.preview_text.config(state=tk.NORMAL)
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, "Операция завершена.\n\nПеретащите следующий файл...")
            self.preview_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = dnd.TkinterDnD.Tk()
    app = CryptoTerminalApp(root)
    root.mainloop()