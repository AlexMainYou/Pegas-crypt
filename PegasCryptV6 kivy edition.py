# kivy_app_single_file.py

import os
import secrets

# Требуется: pip install kivy cryptography
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.popup import Popup
from kivy.core.window import Window
from kivy.utils import get_color_from_hex
from kivy.graphics import Color, Rectangle, Line

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ====================================================================
# <<< НАЧАЛО БЛОКА common_crypto_logic >>>
# ====================================================================

PREVIEW_SIZE = 4096 # Размер превью в байтах (4 KB)

class CryptoLogic:
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def get_preview_data(self, file_path, password):
        try:
            with open(file_path, 'rb') as f: data = f.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]
            original_filename = filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext[:PREVIEW_SIZE], original_filename
        except (InvalidTag, ValueError, IndexError):
            return None, None

    def encrypt_file(self, file_path, password, extension):
        try:
            with open(file_path, 'rb') as file: plaintext = file.read()
            salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
            key = self.derive_key(password, salt)
            original_filename_bytes = os.path.basename(file_path).encode('utf-8')
            filename_len_bytes = len(original_filename_bytes).to_bytes(2, 'big')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            encrypted_data = salt + iv + encryptor.tag + filename_len_bytes + original_filename_bytes + ciphertext
            original_dir, encrypted_name = os.path.dirname(file_path), os.path.splitext(os.path.basename(file_path))[0]
            new_file_path = os.path.join(original_dir, encrypted_name + extension)
            with open(new_file_path, 'wb') as file: file.write(encrypted_data)
            os.remove(file_path)
            return True, f"Успех! Зашифрован как {os.path.basename(new_file_path)}"
        except Exception as e:
            return False, f"Ошибка шифрования: {e}"

    def decrypt_file(self, file_path, password):
        try:
            with open(file_path, 'rb') as file: data = file.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]
            original_filename = filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            original_dir = os.path.dirname(file_path)
            new_file_path = os.path.join(original_dir, original_filename)
            if os.path.exists(new_file_path):
                return "confirm_overwrite", new_file_path
            with open(new_file_path, 'wb') as file: file.write(plaintext)
            os.remove(file_path)
            return True, f"Успех! Файл расшифрован как {original_filename}"
        except (InvalidTag, ValueError, IndexError):
            return False, "Расшифровка не удалась. Неверный пароль или файл поврежден!"
        except Exception as e:
            return False, f"Произошла непредвиденная ошибка: {e}"

    def confirm_and_overwrite(self, old_path, new_path, password):
        try:
            with open(old_path, 'rb') as file: data = file.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]
            original_filename = filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            with open(new_path, 'wb') as file: file.write(plaintext)
            os.remove(old_path)
            return True, f"Успех! Файл перезаписан как {original_filename}"
        except Exception as e:
            return False, f"Ошибка при перезаписи: {e}"

# ====================================================================
# <<< КОНЕЦ БЛОКА common_crypto_logic >>>
# ====================================================================


# --- СТИЛЬ KIVY ---
BG_COLOR_KIVY = "#000000"
FG_COLOR_KIVY = "#00FF00"
ACCENT_BG_KIVY = "#002200"
ACCENT_FG_KIVY = "#33FF33"
FONT_FAMILY_KIVY = "cour" 

class CryptoTerminalLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = [20, 10, 20, 20]
        self.spacing = 10
        self.logic = CryptoLogic()
        self.current_file_path = None
        self.is_encrypt_mode = True
        self.cached_password = None

        with self.canvas.before:
            Color(*get_color_from_hex(BG_COLOR_KIVY))
            self.bg_rect = Rectangle(size=self.size, pos=self.pos)
            Color(0, 0.1, 0, 1)
            self.scanlines = []
        self.bind(size=self._update_graphics, pos=self._update_graphics)
        Window.bind(on_dropfile=self._on_file_drop)
        self._create_widgets()
        self._update_graphics()

    # ... (весь остальной код класса CryptoTerminalLayout из моего предыдущего ответа без изменений) ...
    def _update_graphics(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size
        self.canvas.before.remove_group('scanlines')
        with self.canvas.before:
            for i in range(0, int(self.height), 2):
                Line(points=[self.x, self.y + i, self.x + self.width, self.y + i], group='scanlines')

    def _create_widgets(self):
        top_panel = BoxLayout(size_hint_y=None, height=40, spacing=10)
        top_panel.add_widget(Label(text="Расширение:", font_name=FONT_FAMILY_KIVY, color=get_color_from_hex(FG_COLOR_KIVY)))
        self.pegas_radio = CheckBox(group='ext', active=True, size_hint_x=None, width=40, color=get_color_from_hex(FG_COLOR_KIVY))
        self.alx_radio = CheckBox(group='ext', size_hint_x=None, width=40, color=get_color_from_hex(FG_COLOR_KIVY))
        top_panel.add_widget(self.pegas_radio)
        top_panel.add_widget(Label(text=".Pegas", font_name=FONT_FAMILY_KIVY, color=get_color_from_hex(FG_COLOR_KIVY)))
        top_panel.add_widget(self.alx_radio)
        top_panel.add_widget(Label(text=".ALX", font_name=FONT_FAMILY_KIVY, color=get_color_from_hex(FG_COLOR_KIVY)))
        self.add_widget(top_panel)
        self.preview_text = TextInput(text="Перетащите файл сюда для анализа...", readonly=True, background_color=get_color_from_hex(ACCENT_BG_KIVY), foreground_color=get_color_from_hex(FG_COLOR_KIVY), font_name=FONT_FAMILY_KIVY, font_size='14sp', padding=[10, 10])
        self.add_widget(self.preview_text)
        bottom_panel = BoxLayout(orientation='vertical', size_hint_y=None, height=120, spacing=10)
        self.action_button = Button(text="[ Выберите файл ]", font_name=FONT_FAMILY_KIVY, font_size='24sp', bold=True, background_normal='', background_color=get_color_from_hex(ACCENT_BG_KIVY), color=get_color_from_hex(ACCENT_FG_KIVY), size_hint_y=None, height=90, disabled=True)
        self.action_button.bind(on_press=self.on_action_button_press)
        bottom_panel.add_widget(self.action_button)
        self.status_label = Label(text="Готов к работе.", font_name=FONT_FAMILY_KIVY, color=get_color_from_hex(FG_COLOR_KIVY), size_hint_y=None, height=20)
        bottom_panel.add_widget(self.status_label)
        self.add_widget(bottom_panel)

    def _on_file_drop(self, window, file_path, *args):
        self.process_file(file_path.decode('utf-8'))

    def process_file(self, file_path):
        self.reset_state(clear_preview=False)
        self.current_file_path = file_path
        filename = os.path.basename(file_path)
        file_ext = os.path.splitext(filename)[1]
        if file_ext.lower() in ['.alx', '.pegas']:
            self.is_encrypt_mode = False
            self.action_button.text = "[ Расшифровать ]"
            self.show_encrypted_preview()
        else:
            self.is_encrypt_mode = True
            self.action_button.text = "[ Зашифровать ]"
            self.show_unencrypted_preview()
        self.action_button.disabled = False
        self.status_label.text = f"Анализ файла: {filename}"

    def show_unencrypted_preview(self):
        try:
            filename = os.path.basename(self.current_file_path)
            filesize = os.path.getsize(self.current_file_path)
            header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Шифрование\n" + "-" * 40 + "\n\n"
            with open(self.current_file_path, 'rb') as f: preview_data = f.read(PREVIEW_SIZE)
            text_preview = preview_data.decode('utf-8', errors='ignore')
            content = "Содержимое (начало):\n\n" + text_preview
            self.preview_text.text = header + content
        except Exception as e:
            self.preview_text.text = f"Ошибка чтения файла: {e}"

    def show_encrypted_preview(self):
        self.show_password_dialog("Пароль для предпросмотра:", self._on_preview_password)

    def _on_preview_password(self, password):
        if not password:
            self.reset_state()
            return
        filename = os.path.basename(self.current_file_path)
        filesize = os.path.getsize(self.current_file_path)
        header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Расшифровка\n" + "-" * 40 + "\n\n"
        preview_data, original_filename = self.logic.get_preview_data(self.current_file_path, password)
        if preview_data is None:
            content = ">>> ДОСТУП ЗАПРЕЩЕН <<<\n\nНеверный пароль или файл поврежден."
            self.action_button.disabled = True
        else:
            self.cached_password = password
            text_preview = preview_data.decode('utf-8', errors='ignore')
            content = f"Восстановленное имя: {original_filename}\n\n" + "Содержимое (расшифрованное начало):\n\n" + text_preview
        self.preview_text.text = header + content
    
    def on_action_button_press(self, instance):
        if self.is_encrypt_mode:
            self.show_password_dialog("Пароль для шифрования:", self._on_encrypt_password)
        else:
            if self.cached_password: self.decrypt_with_password(self.cached_password)
            else: self.show_password_dialog("Пароль для расшифровки:", self.decrypt_with_password)
    
    def _on_encrypt_password(self, password):
        if not password: return
        extension = ".Pegas" if self.pegas_radio.active else ".ALX"
        success, message = self.logic.encrypt_file(self.current_file_path, password, extension)
        self.status_label.text = message
        if success: self.reset_state()
            
    def decrypt_with_password(self, password):
        if not password: return
        result, message = self.logic.decrypt_file(self.current_file_path, password)
        if result == "confirm_overwrite":
            self.show_confirm_dialog(f"Файл '{os.path.basename(message)}' уже существует. Перезаписать?", lambda: self.confirm_overwrite_action(message, password))
        else:
            self.status_label.text = message
            if result: self.reset_state()
            else: self.cached_password = None

    def confirm_overwrite_action(self, new_path, password):
        success, message = self.logic.confirm_and_overwrite(self.current_file_path, new_path, password)
        self.status_label.text = message
        if success: self.reset_state()

    def show_password_dialog(self, title_text, callback):
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        content.add_widget(Label(text=title_text, color=get_color_from_hex(FG_COLOR_KIVY), font_name=FONT_FAMILY_KIVY))
        password_input = TextInput(password=True, multiline=False, font_name=FONT_FAMILY_KIVY, background_color=get_color_from_hex(ACCENT_BG_KIVY), foreground_color=get_color_from_hex(FG_COLOR_KIVY))
        buttons = BoxLayout(spacing=10, size_hint_y=None, height=40)
        ok_button, cancel_button = Button(text="[ OK ]", font_name=FONT_FAMILY_KIVY), Button(text="[ Отмена ]", font_name=FONT_FAMILY_KIVY)
        buttons.add_widget(ok_button)
        buttons.add_widget(cancel_button)
        content.add_widget(password_input)
        content.add_widget(buttons)
        popup = Popup(title='Ввод пароля', content=content, size_hint=(None, None), size=(400, 200), separator_color=get_color_from_hex(FG_COLOR_KIVY), background_color=get_color_from_hex(BG_COLOR_KIVY), title_color=get_color_from_hex(FG_COLOR_KIVY), title_font=FONT_FAMILY_KIVY)
        ok_button.bind(on_press=lambda instance: (callback(password_input.text), popup.dismiss()))
        cancel_button.bind(on_press=lambda instance: (callback(None), popup.dismiss()))
        popup.open()

    def show_confirm_dialog(self, text, on_yes):
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        content.add_widget(Label(text=text, color=get_color_from_hex(FG_COLOR_KIVY), font_name=FONT_FAMILY_KIVY))
        buttons = BoxLayout(spacing=10, size_hint_y=None, height=40)
        yes_button, no_button = Button(text="[ Да ]", font_name=FONT_FAMILY_KIVY), Button(text="[ Нет ]", font_name=FONT_FAMILY_KIVY)
        buttons.add_widget(yes_button)
        buttons.add_widget(no_button)
        content.add_widget(buttons)
        popup = Popup(title='Подтверждение', content=content, size_hint=(None, None), size=(400, 150))
        yes_button.bind(on_press=lambda instance: (on_yes(), popup.dismiss()))
        no_button.bind(on_press=lambda instance: popup.dismiss())
        popup.open()

    def reset_state(self, clear_preview=True):
        self.current_file_path, self.cached_password = None, None
        self.action_button.disabled, self.action_button.text = True, "[ Выберите файл ]"
        if clear_preview: self.preview_text.text = "Операция завершена.\n\nПеретащите следующий файл..."

class CryptoTerminalApp(App):
    def build(self):
        Window.clearcolor = get_color_from_hex(BG_COLOR_KIVY)
        Window.size = (600, 500)
        self.title = "PegasCrypt V6.0 [Kivy Edition]"
        return CryptoTerminalLayout()

if __name__ == "__main__":
    CryptoTerminalApp().run()