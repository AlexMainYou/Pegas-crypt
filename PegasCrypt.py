import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QLineEdit, QLabel, QPushButton)
from PyQt6.QtCore import Qt, QMimeData
from PyQt6.QtGui import QPalette, QColor, QDragEnterEvent, QDropEvent
import random

class DropArea(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumSize(300, 200)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
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

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
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

            random.seed(seed)
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())

            for i in range(len(data)):
                data[i] ^= random.randint(0, 255)

            new_path = file_path + '.pegas'
            with open(new_path, 'wb') as f:
                f.write(data)

            os.remove(file_path)
            self.label.setText("Файл зашифрован!")

        except Exception as e:
            self.label.setText(f"Ошибка: {str(e)}")

    def decrypt_file(self, file_path):
        try:
            seed = self.window().key_input.text()
            if not seed:
                self.label.setText("Введите ключ!")
                return

            random.seed(seed)
            with open(file_path, 'rb') as f:
                data = bytearray(f.read())

            for i in range(len(data)):
                data[i] ^= random.randint(0, 255)

            new_path = file_path[:-6]  # Remove .pegas
            with open(new_path, 'wb') as f:
                f.write(data)

            os.remove(file_path)
            self.label.setText("Файл расшифрован!")

        except Exception as e:
            self.label.setText(f"Ошибка: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PEGAS Encryptor")
        self.setMinimumSize(400, 300)

        # Set window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QLineEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 5px;
            }
            QLabel {
                color: #00ff00;
            }
            QPushButton {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #2a2a2a;
            }
        """)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create key input
        key_label = QLabel("Encryption Key:")
        layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter key...")
        layout.addWidget(self.key_input)

        # Create drop area
        self.drop_area = DropArea()
        layout.addWidget(self.drop_area)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Set application-wide dark theme
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
