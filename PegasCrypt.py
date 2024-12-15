import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QLineEdit, QLabel, QPushButton, QProgressBar)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

class DropArea(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumSize(300, 200)
        self.setStyleSheet("""
            QWidget {
                background-color: #00041a;
                border: 2px dashed #00ff00;
                border-radius: 5px;
            }
        """)

        layout = QVBoxLayout()
        self.label = QLabel("Перетащите файл сюда")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("color: #00ff00; border: none;")
        layout.addWidget(self.label)
        self.setLayout(layout)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        if files:
            self.process_file(files[0])

    def process_file(self, file_path):
        if file_path.endswith('.pegas'):
            self.decrypt_file(file_path)
        else:
            self.encrypt_file(file_path)

    def encrypt_file(self, file_path):
        try:
            key_text = self.window().key_input.text()
            if not key_text:
                self.label.setText("Введите ключ!")
                return

            # Преобразуем ключ из текста в байты, используя первые 32 байта
            key = key_text.encode('utf-8')[:32]
            # Если ключ короче 32 байт, дополним его нулями
            key = key.ljust(32, b'\0')

            # Сохраняем оригинальное расширение
            original_ext = os.path.splitext(file_path)[1]

            # Генерируем случайный вектор инициализации (IV)
            iv = secrets.token_bytes(16)

            # Создаем объект cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Используем PKCS7 паддинг
            padder = padding.PKCS7(128).padder()

            with open(file_path, 'rb') as f:
                data = f.read()

            # Дополняем данные
            padded_data = padder.update(data) + padder.finalize()

            # Шифруем данные
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Записываем длину расширения, расширение и IV в начало файла
            ext_length = len(original_ext)
            header_data = bytearray(f"{ext_length:02d}{original_ext}".encode()) + iv

            # Создаем новый путь с расширением .pegas
            new_path = os.path.splitext(file_path)[0] + '.pegas'

            total_size = len(header_data) + len(encrypted_data)
            self.window().progress_bar.setMaximum(total_size)

            with open(new_path, 'wb') as f:
                f.write(header_data)
                self.window().progress_bar.setValue(len(header_data))
                f.write(encrypted_data)
                self.window().progress_bar.setValue(total_size)

            os.remove(file_path)
            self.label.setText("Файл зашифрован!")

        except Exception as e:
            self.label.setText(f"Ошибка: {str(e)}")
        finally:
            self.window().progress_bar.setValue(0)

    def decrypt_file(self, file_path):
        try:
            key_text = self.window().key_input.text()
            if not key_text:
                self.label.setText("Введите ключ!")
                return
            
            # Преобразуем ключ из текста в байты, используя первые 32 байта
            key = key_text.encode('utf-8')[:32]
            # Если ключ короче 32 байт, дополним его нулями
            key = key.ljust(32, b'\0')

            with open(file_path, 'rb') as f:
                # Читаем заголовок (длина расширения, расширение и IV)
                ext_length = int(f.read(2).decode())
                original_ext = f.read(ext_length).decode()
                iv = f.read(16)

                # Оставшиеся данные - зашифрованные данные
                encrypted_data = f.read()

            # Создаем объект cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Расшифровываем данные
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Удаляем паддинг
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

            # Создаем путь с оригинальным расширением
            new_path = os.path.splitext(file_path)[0] + original_ext

            total_size = len(encrypted_data)
            self.window().progress_bar.setMaximum(total_size)

            with open(new_path, 'wb') as f:
                f.write(decrypted_data)
                self.window().progress_bar.setValue(total_size)

            os.remove(file_path)
            self.label.setText("Файл расшифрован!")

        except Exception as e:
            self.label.setText(f"Ошибка: {str(e)}")
        finally:
            self.window().progress_bar.setValue(0)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PEGAS Encryptor")
        self.setMinimumSize(400, 300)

        self.setStyleSheet("""
    QMainWindow {
        background-color: #1a212b;
    }
    QLineEdit {
        background-color: #1a212b;
        color: #00ff00;
        border: 2px solid #00ff00;
        border-radius: 5px;
        padding: 5px;
    }
    QLabel {
        color: #00ff00;
    }
    QPushButton {
        background-color: #1a212b;
        color: #00ff00;
        border: 2px solid #00ff00;
        border-radius: 5px;
        padding: 5px;
    }
    QPushButton:hover {
        background-color: #1a212b;
    }
    QProgressBar {
        border: 2px solid #00ff00;
        border-radius: 5px;
        text-align: center;
        color: #00ff00;
    }
    QProgressBar::chunk {
        background-color: #00ff00;
    }
""")

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        key_label = QLabel("Encryption Key:")
        layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter key (up to 32 characters)...")
        layout.addWidget(self.key_input)

        self.drop_area = DropArea()
        layout.addWidget(self.drop_area)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.Text, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(0, 255, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())