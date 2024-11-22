import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QLineEdit, QLabel, QPushButton, QProgressBar)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor
import random

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
            seed = self.window().key_input.text()
            if not seed:
                self.label.setText("Введите ключ!")
                return

            # Сохраняем оригинальное расширение
            original_ext = os.path.splitext(file_path)[1]
            # Записываем длину расширения и само расширение в начало файла
            ext_length = len(original_ext)

            random.seed(seed)
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())

            # Добавляем информацию о расширении в начало данных
            ext_data = bytearray(f"{ext_length:02d}{original_ext}".encode())
            data = ext_data + data

            total_size = len(data)
            self.window().progress_bar.setMaximum(total_size)

            # Шифруем все данные, включая информацию о расширении
            for i in range(len(data)):
                data[i] ^= random.randint(0, 255)
                if i % 1000 == 0:
                    self.window().progress_bar.setValue(i)
                    QApplication.processEvents()

            # Создаем новый путь с расширением .pegas
            new_path = os.path.splitext(file_path)[0] + '.pegas'
            
            with open(new_path, 'wb') as f:
                f.write(data)

            os.remove(file_path)
            self.label.setText("Файл зашифрован!")
            self.window().progress_bar.setValue(total_size)

        except Exception as e:
            self.label.setText(f"Ошибка: {str(e)}")
        finally:
            self.window().progress_bar.setValue(0)

    def decrypt_file(self, file_path):
        try:
            seed = self.window().key_input.text()
            if not seed:
                self.label.setText("Введите ключ!")
                return

            random.seed(seed)
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())

            total_size = len(data)
            self.window().progress_bar.setMaximum(total_size)

            # Расшифровываем все данные
            for i in range(len(data)):
                data[i] ^= random.randint(0, 255)
                if i % 1000 == 0:
                    self.window().progress_bar.setValue(i)
                    QApplication.processEvents()

            # Получаем информацию о расширении
            ext_length = int(data[:2].decode())
            original_ext = data[2:2+ext_length].decode()
            
            # Удаляем информацию о расширении из данных
            data = data[2+ext_length:]

            # Создаем путь с оригинальным расширением
            new_path = os.path.splitext(file_path)[0] + original_ext
            
            with open(new_path, 'wb') as f:
                f.write(data)

            os.remove(file_path)
            self.label.setText("Файл расшифрован!")
            self.window().progress_bar.setValue(total_size)

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
        self.key_input.setPlaceholderText("Enter key...")
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
