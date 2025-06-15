import sys
import os
import secrets

# Требуется установка: pip install PyQt5 cryptography
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QTextEdit, QPushButton, QRadioButton,
                             QDialog, QLineEdit, QMessageBox, QFrame)
from PyQt5.QtGui import QPainter, QColor, QFont, QPen
from PyQt5.QtCore import Qt, QTimer, pyqtSlot, QSize

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- СТИЛЬ И КОНСТАНТЫ ---
BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
ACCENT_BG = "#002200"
ACCENT_FG = "#33FF33"
ACTIVE_BG = "#003300"
FONT_FAMILY = "Courier"
PREVIEW_SIZE = 4096 # Размер превью в байтах (4 KB)

# Глобальный стиль приложения в формате QSS (аналог CSS)
STYLESHEET = f"""
    QWidget {{
        background-color: {BG_COLOR};
        color: {FG_COLOR};
        font-family: "{FONT_FAMILY}";
    }}
    QLabel {{
        background-color: transparent;
    }}
    QTextEdit {{
        background-color: {ACCENT_BG};
        border: 1px solid {FG_COLOR};
        font-size: 11pt;
        padding: 5px;
    }}
    QRadioButton {{
        font-size: 10pt;
    }}
    QRadioButton::indicator {{
        width: 15px;
        height: 15px;
    }}
    QRadioButton::indicator:unchecked {{
        background-color: {ACCENT_BG};
    }}
    QRadioButton::indicator:checked {{
        background-color: {FG_COLOR};
    }}
    QLineEdit {{
        background-color: {ACCENT_BG};
        border: none;
        font-size: 12pt;
        padding: 5px;
    }}
    QMessageBox {{
        background-color: {ACCENT_BG};
    }}
    QMessageBox QLabel {{
        color: {FG_COLOR};
    }}
    QMessageBox QPushButton {{
        background-color: {ACTIVE_BG};
        color: {FG_COLOR};
        padding: 8px 20px;
        border: none;
        min-width: 60px;
    }}
    QMessageBox QPushButton:hover {{
        background-color: {ACCENT_FG};
        color: {BG_COLOR};
    }}
"""

class BigButton(QPushButton):
    """
    Кастомная кнопка, текст которой растягивается на всю высоту.
    Именно то, что вы просили.
    """
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(90) # Делаем кнопку высокой (в 3-4 раза выше обычной)
        self._bg_color = QColor(ACCENT_BG)
        self._fg_color = QColor(ACCENT_FG)
        self._hover_bg_color = QColor(ACTIVE_BG)
        self._hover_fg_color = QColor(FG_COLOR)
        self.is_hovering = False

    def paintEvent(self, event):
        # Переопределяем отрисовку, чтобы полностью контролировать внешний вид
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Фон
        bg_color = self._hover_bg_color if self.is_hovering else self._bg_color
        painter.fillRect(self.rect(), bg_color)

        # Текст
        fg_color = self._hover_fg_color if self.is_hovering else self._fg_color
        painter.setPen(QPen(fg_color))
        
        # Подбираем размер шрифта, чтобы он заполнил высоту
        font = QFont(FONT_FAMILY, 10, QFont.Bold)
        
        # <<< ИСПРАВЛЕНИЕ ЗДЕСЬ
        # Преобразуем результат в int(), так как setPixelSize не принимает float
        font.setPixelSize(int(self.height() * 0.8)) 
        
        painter.setFont(font)
        
        # Рисуем текст по центру
        painter.drawText(self.rect(), Qt.AlignCenter, self.text())

    def enterEvent(self, event):
        self.is_hovering = True
        self.update() # Перерисовать
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.is_hovering = False
        self.update() # Перерисовать
        super().leaveEvent(event)

class CustomPasswordDialog(QDialog):
    """Кастомное диалоговое окно для ввода пароля в ретро-стиле."""
    def __init__(self, parent, prompt="Введите пароль:"):
        super().__init__(parent)
        self.result = None
        self.setWindowTitle("Аутентификация")
        self.setFixedSize(350, 150)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        
        main_layout = QVBoxLayout(self)
        frame = QFrame(self)
        frame.setFrameShape(QFrame.Box)
        frame.setStyleSheet(f"border: 1px solid {FG_COLOR};")
        main_layout.addWidget(frame)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        layout.addWidget(QLabel(prompt, self))
        
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_entry)
        
        button_layout = QHBoxLayout()
        ok_button = QPushButton("[ OK ]", self)
        cancel_button = QPushButton("[ Отмена ]", self)
        
        button_style = f"""
            QPushButton {{ background-color: {ACCENT_BG}; border: none; padding: 5px 10px; }}
            QPushButton:hover {{ background-color: {ACTIVE_BG}; }}
        """
        ok_button.setStyleSheet(button_style)
        cancel_button.setStyleSheet(button_style)
        
        button_layout.addStretch()
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        
        self.password_entry.setFocus()

    def accept(self):
        self.result = self.password_entry.text()
        if self.result:
            super().accept()
    
    @staticmethod
    def getPassword(parent, prompt):
        dialog = CustomPasswordDialog(parent, prompt)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.result
        return None

class CryptoTerminalApp(QWidget):
    def __init__(self):
        super().__init__()
        self.current_file_path = None
        self.is_encrypt_mode = True
        self.cached_password = None
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self._animate_step)
        
        self.setAcceptDrops(True)
        self._init_ui()
        self.animate_text("Готов к работе. Перетащите файл...")
        
    def _init_ui(self):
        self.setWindowTitle("PegasCrypt V6.0 [PyQt5 Edition]")
        self.setGeometry(300, 300, 600, 500)
        self.setMinimumSize(500, 450)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 10, 20, 10)
        main_layout.setSpacing(10)

        top_layout = QHBoxLayout()
        self.extension_label = QLabel("Расширение:", self)
        self.pegas_radio = QRadioButton(".Pegas", self)
        self.alx_radio = QRadioButton(".ALX", self)
        self.pegas_radio.setChecked(True)
        top_layout.addWidget(self.extension_label)
        top_layout.addWidget(self.pegas_radio)
        top_layout.addWidget(self.alx_radio)
        top_layout.addStretch()
        
        main_layout.addLayout(top_layout)
        
        self.preview_text = QTextEdit(self)
        self.preview_text.setReadOnly(True)
        self.preview_text.setText("Перетащите файл сюда для анализа...")
        self.preview_text.setAcceptDrops(False)
        main_layout.addWidget(self.preview_text, 1)

        self.action_button = BigButton("[ Выберите файл ]", self)
        self.action_button.setEnabled(False)
        main_layout.addWidget(self.action_button)
        
        self.status_label = QLabel("", self)
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        self.action_button.clicked.connect(self.on_action_button_click)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(BG_COLOR))
        pen = QPen(QColor(0, 26, 0)) # #001a00
        pen.setWidth(1)
        painter.setPen(pen)
        for y in range(0, self.height(), 2):
            painter.drawLine(0, y, self.width(), y)
            
    def animate_text(self, text):
        self.full_text_to_animate = text
        self.animation_index = 0
        self.animation_timer.start(40)

    def _animate_step(self):
        if self.animation_index <= len(self.full_text_to_animate):
            current_text = self.full_text_to_animate[:self.animation_index]
            self.status_label.setText(current_text + "_")
            self.animation_index += 1
        else:
            self.status_label.setText(self.full_text_to_animate)
            self.animation_timer.stop()
            
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.preview_text.setStyleSheet(f"background-color: {ACTIVE_BG}; border: 1px solid {FG_COLOR};")
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.preview_text.setStyleSheet(f"background-color: {ACCENT_BG}; border: 1px solid {FG_COLOR};")
        
    def dropEvent(self, event):
        self.preview_text.setStyleSheet(f"background-color: {ACCENT_BG}; border: 1px solid {FG_COLOR};")
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            filepath = files[0]
            if os.path.exists(filepath):
                self.process_file(filepath)
            else:
                self.animate_text(f"Ошибка: Файл не найден '{filepath}'")

    @pyqtSlot()
    def on_action_button_click(self):
        if self.is_encrypt_mode:
            self.encrypt_file()
        else:
            self.decrypt_file()

    def process_file(self, file_path):
        self.reset_state(clear_preview=False)
        self.current_file_path = file_path
        filename = os.path.basename(file_path)
        file_ext = os.path.splitext(filename)[1]
        self.preview_text.clear()
        if file_ext.lower() in ['.alx', '.pegas']:
            self.is_encrypt_mode = False
            self.action_button.setText("[ Расшифровать ]")
            self.show_encrypted_preview()
        else:
            self.is_encrypt_mode = True
            self.action_button.setText("[ Зашифровать ]")
            self.show_unencrypted_preview()
        self.action_button.setEnabled(True)
        self.animate_text(f"Анализ файла: {filename}")
        
    def show_unencrypted_preview(self):
        try:
            filename = os.path.basename(self.current_file_path)
            filesize = os.path.getsize(self.current_file_path)
            header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Шифрование\n"
            header += "-" * 50 + "\n\n"
            with open(self.current_file_path, 'rb') as f:
                preview_data = f.read(PREVIEW_SIZE)
            try:
                text_preview = preview_data.decode('utf-8', errors='ignore')
                content = "Содержимое (начало):\n\n" + text_preview
            except UnicodeDecodeError:
                content = "Содержимое: Бинарный файл (превью не доступно)"
            self.preview_text.setText(header + content)
        except Exception as e:
            self.preview_text.setText(f"Ошибка чтения файла: {e}")

    def show_encrypted_preview(self):
        password = CustomPasswordDialog.getPassword(self, "Пароль для предпросмотра:")
        if not password:
            self.reset_state()
            return
        filename = os.path.basename(self.current_file_path)
        filesize = os.path.getsize(self.current_file_path)
        header = f"Файл: {filename}\nРазмер: {filesize} байт\nРежим: Расшифровка\n"
        header += "-" * 50 + "\n\n"
        try:
            preview_data, original_filename = self.get_preview_data(password)
            if preview_data is None:
                content = ">>> ДОСТУП ЗАПРЕЩЕН <<<\n\nНеверный пароль или файл поврежден."
                self.action_button.setEnabled(False)
            else:
                self.cached_password = password
                try:
                    text_preview = preview_data.decode('utf-8', errors='ignore')
                    content = f"Восстановленное имя: {original_filename}\n\n"
                    content += "Содержимое (расшифрованное начало):\n\n" + text_preview
                except UnicodeDecodeError:
                    content = "Содержимое: Бинарный файл (расшифрованное начало)"
        except Exception as e:
            content = f"Ошибка при предпросмотре: {e}"
        self.preview_text.setText(header + content)
        
    def get_password(self, prompt):
        return CustomPasswordDialog.getPassword(self, prompt)
    
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def get_preview_data(self, password):
        try:
            with open(self.current_file_path, 'rb') as f: data = f.read()
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

    def encrypt_file(self):
        if not self.current_file_path: return
        password = self.get_password("Пароль для шифрования:")
        if not password: return
        try:
            with open(self.current_file_path, 'rb') as file: plaintext = file.read()
            salt = secrets.token_bytes(16)
            key = self.derive_key(password, salt)
            iv = secrets.token_bytes(12)
            original_filename_bytes = os.path.basename(self.current_file_path).encode('utf-8')
            filename_len_bytes = len(original_filename_bytes).to_bytes(2, 'big')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            encrypted_data = salt + iv + encryptor.tag + filename_len_bytes + original_filename_bytes + ciphertext
            extension = ".Pegas" if self.pegas_radio.isChecked() else ".ALX"
            encrypted_name = os.path.splitext(os.path.basename(self.current_file_path))[0]
            new_file_path = os.path.join(os.path.dirname(self.current_file_path), encrypted_name + extension)
            with open(new_file_path, 'wb') as file: file.write(encrypted_data)
            os.remove(self.current_file_path)
            self.animate_text(f"Успех! Зашифрован как {os.path.basename(new_file_path)}")
            self.reset_state()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка шифрования", str(e))

    def decrypt_file(self):
        if not self.current_file_path: return
        password = self.cached_password or self.get_password("Пароль для расшифровки:")
        if not password: return
        try:
            with open(self.current_file_path, 'rb') as file: data = file.read()
            salt, iv, tag = data[0:16], data[16:28], data[28:44]
            filename_len = int.from_bytes(data[44:46], 'big')
            filename_bytes = data[46:46+filename_len]
            ciphertext = data[46+filename_len:]
            original_filename = filename_bytes.decode('utf-8')
            key = self.derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            new_file_path = os.path.join(os.path.dirname(self.current_file_path), original_filename)
            if os.path.exists(new_file_path):
                reply = QMessageBox.question(self, "Подтверждение", f"Файл '{original_filename}' уже существует. Перезаписать?",
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.No: return
            with open(new_file_path, 'wb') as file: file.write(plaintext)
            os.remove(self.current_file_path)
            self.animate_text(f"Успех! Файл расшифрован как {original_filename}")
            self.reset_state()
        except (InvalidTag, ValueError, IndexError):
            QMessageBox.critical(self, "Ошибка", "Расшифровка не удалась. Неверный пароль или файл поврежден!")
            self.cached_password = None
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла непредвиденная ошибка:\n{e}")

    def reset_state(self, clear_preview=True):
        self.current_file_path = None
        self.cached_password = None
        self.action_button.setEnabled(False)
        self.action_button.setText("[ Выберите файл ]")
        if clear_preview:
            self.preview_text.setText("Операция завершена.\n\nПеретащите следующий файл...")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    window = CryptoTerminalApp()
    window.show()
    sys.exit(app.exec_())