import os
import secrets
import asyncio
from pathlib import Path

# Требуется установка: pip install textual "cryptography~=42.0"
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    Input,
    RadioSet,
    RadioButton,
    RichLog,
)
from textual.binding import Binding
from textual.reactive import var

# --- СТИЛЬ и КОНСТАНТЫ ---
# CSS стили встроены прямо в код для простоты
RETRO_CSS = """
Screen {
    background: #000000;
    color: #00FF00;
    /* Шрифт настраивается в самом терминале для лучшего эффекта */
}

Header {
    background: #001100;
    text-style: bold;
}

RichLog {
    background: #002200;
    border: solid #00FF00;
    padding: 1;
}

Input {
    background: #002200;
    border: round #33FF33;
}
Input:focus {
    border: round #88FF88;
}

RadioSet {
    padding: 0 1;
}

#status_bar {
    background: #001100;
    padding: 0 1;
    height: 1;
}

/* 
* САМАЯ ГЛАВНАЯ КНОПКА
* - Высота в 4 раза больше стандартной (height: 4)
* - Текст центрирован по вертикали и горизонтали для эффекта "заполнения"
*/
#action_button {
    width: 1fr;
    height: 4;
    background: #002200;
    border: tall #33FF33;
    content-align: center middle;
    text-style: bold;
}
#action_button:hover {
    background: #003300;
    border: tall #88FF88;
}

/* --- Диалог пароля --- */
PasswordDialog {
    align: center middle;
}

#dialog_container {
    width: 50;
    height: auto;
    background: #001100;
    border: thick #00FF00;
    padding: 1 2;
}

#dialog_container Button {
    width: 1fr;
    margin: 1;
}
"""

PREVIEW_SIZE = 4096  # Размер превью в байтах (4 KB)


class PasswordDialog(ModalScreen[str | None]):
    """Модальный экран для безопасного ввода пароля."""

    def __init__(self, prompt: str) -> None:
        self.prompt = prompt
        super().__init__()

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog_container"):
            yield Static(self.prompt, classes="label")
            yield Input(password=True, placeholder="Введите пароль...")
            with Horizontal():
                yield Button("OK", variant="primary", id="ok")
                yield Button("Отмена", id="cancel")
    
    def on_mount(self) -> None:
        self.query_one(Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            password = self.query_one(Input).value
            self.dismiss(password if password else None)
        else:
            self.dismiss(None)
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value if event.value else None)


class CryptoTerminalApp(App):
    """TUI-приложение для шифрования файлов в ретро-стиле."""

    CSS = RETRO_CSS
    BINDINGS = [Binding("ctrl+q", "quit", "Выход")]

    current_file_path = var[Path | None](None)
    is_encrypt_mode = var(True)
    status_text = var("Готов к работе. Введите путь к файлу и нажмите Enter.")
    
    cached_password: str | None = None

    def compose(self) -> ComposeResult:
        yield Header(name="PegasCrypt V6.0")
        with Vertical(id="main_container"):
            yield Static("Путь к файлу:")
            yield Input(placeholder="/path/to/your/file.txt", id="file_path")
            with Horizontal():
                yield Static("Расширение:", classes="label")
                with RadioSet(id="extension_selector"):
                    yield RadioButton(".Pegas", value=True)
                    yield RadioButton(".ALX")
            yield RichLog(id="preview_log", wrap=True, highlight=True, markup=True)
            yield Button("Выберите файл", id="action_button", disabled=True)
        yield Static(self.status_text, id="status_bar")
    
    async def on_mount(self) -> None:
        """Запускается при старте приложения."""
        log = self.query_one(RichLog)
        # ИСПРАВЛЕННАЯ СТРОКА
        log.write("Добро пожаловать в [bold cyan]PegasCrypt V6.0[/bold cyan]!")
        log.write("Введите путь к файлу в поле выше и нажмите [bold]Enter[/bold] для анализа.")

    async def animate_status(self, text: str):
        """Анимация текста в статусной строке."""
        status_bar = self.query_one("#status_bar", Static)
        for i in range(len(text) + 1):
            status_bar.update(text[:i] + "█")
            await asyncio.sleep(0.03)
        status_bar.update(text)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "file_path":
            await self.process_file(event.value)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "action_button":
            if self.is_encrypt_mode:
                await self.encrypt_file()
            else:
                await self.decrypt_file()

    async def process_file(self, file_path_str: str):
        self.reset_state(clear_preview=False)
        log = self.query_one(RichLog)
        log.clear()

        file_path = Path(file_path_str).expanduser().resolve()

        if not file_path.exists() or not file_path.is_file():
            log.write(f"[bold red]ОШИБКА:[/bold red] Файл не найден или это не файл: '{file_path_str}'")
            self.query_one("#action_button", Button).disabled = True
            await self.animate_status("Ошибка: файл не найден.")
            return

        self.current_file_path = file_path
        filename = file_path.name
        file_ext = file_path.suffix.lower()

        if file_ext in ['.alx', '.pegas']:
            self.is_encrypt_mode = False
            self.query_one("#action_button", Button).label = "Расшифровать"
            await self.show_encrypted_preview()
        else:
            self.is_encrypt_mode = True
            self.query_one("#action_button", Button).label = "Зашифровать"
            self.show_unencrypted_preview()
        
        self.query_one("#action_button", Button).disabled = False
        await self.animate_status(f"Анализ файла: {filename}")

    def show_unencrypted_preview(self):
        log = self.query_one(RichLog)
        if not self.current_file_path: return

        try:
            filename = self.current_file_path.name
            filesize = self.current_file_path.stat().st_size
            
            header = f"[bold]Файл:[/bold] {filename}\n[bold]Размер:[/bold] {filesize} байт\n[bold]Режим:[/bold] Шифрование\n"
            header += "-" * 40 + "\n\n"
            
            with open(self.current_file_path, 'rb') as f:
                preview_data = f.read(PREVIEW_SIZE)
            
            try:
                # Используем errors='replace' для безопасного отображения
                text_preview = preview_data.decode('utf-8', errors='replace')
                content = f"[cyan]Содержимое (начало):[/cyan]\n\n{text_preview}"
            except Exception:
                content = "[yellow]Содержимое: Бинарный файл (превью не доступно)[/yellow]"

            log.write(header + content)
        except Exception as e:
            log.write(f"[bold red]Ошибка чтения файла:[/bold red] {e}")

    async def show_encrypted_preview(self):
        
        def handle_password(password: str | None):
            if not password:
                self.reset_state()
                # self.call_from_thread нужен для вызова async метода из sync callback
                self.call_from_thread(self.animate_status, "Предпросмотр отменен.")
                return

            log = self.query_one(RichLog)
            filename = self.current_file_path.name
            filesize = self.current_file_path.stat().st_size
            header = f"[bold]Файл:[/bold] {filename}\n[bold]Размер:[/bold] {filesize} байт\n[bold]Режим:[/bold] Расшифровка\n"
            header += "-" * 40 + "\n\n"

            try:
                preview_data, original_filename = self.get_preview_data(password)
                if preview_data is None:
                    content = "[bold red]>>> ДОСТУП ЗАПРЕЩЕН <<<\n\nНеверный пароль или файл поврежден.[/bold red]"
                    self.query_one("#action_button", Button).disabled = True
                else:
                    self.cached_password = password
                    try:
                        text_preview = preview_data.decode('utf-8', errors='replace')
                        content = f"[bold]Восстановленное имя:[/bold] {original_filename}\n\n"
                        content += f"[cyan]Содержимое (расшифрованное начало):[/cyan]\n\n{text_preview}"
                    except Exception:
                        content = "[yellow]Содержимое: Бинарный файл (расшифрованное начало)[/yellow]"
            except Exception as e:
                content = f"[bold red]Ошибка при предпросмотре:[/bold red] {e}"

            log.write(header + content)

        self.push_screen(PasswordDialog("Пароль для предпросмотра:"), handle_password)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def get_preview_data(self, password: str) -> tuple[bytes | None, str | None]:
        try:
            data = self.current_file_path.read_bytes()
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

    async def encrypt_file(self):
        if not self.current_file_path: return

        async def do_encrypt(password: str | None):
            if not password:
                await self.animate_status("Шифрование отменено.")
                return
            
            try:
                plaintext = self.current_file_path.read_bytes()
                salt = secrets.token_bytes(16)
                key = self.derive_key(password, salt)
                iv = secrets.token_bytes(12)
                
                original_filename_bytes = self.current_file_path.name.encode('utf-8')
                filename_len_bytes = len(original_filename_bytes).to_bytes(2, 'big')

                encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                
                encrypted_data = salt + iv + encryptor.tag + filename_len_bytes + original_filename_bytes + ciphertext

                radio_set = self.query_one(RadioSet)
                extension = ".Pegas" if radio_set.pressed_button.value else ".ALX"
                
                new_file_path = self.current_file_path.with_suffix(extension)
                new_file_path.write_bytes(encrypted_data)

                os.remove(self.current_file_path)
                
                await self.animate_status(f"Успех! Зашифрован как {new_file_path.name}")
                self.reset_state()
            except Exception as e:
                self.query_one(RichLog).write(f"[bold red]Ошибка шифрования:[/bold red]\n{e}")
                await self.animate_status("Ошибка шифрования.")

        self.push_screen(PasswordDialog("Пароль для шифрования:"), do_encrypt)

    async def decrypt_file(self):
        if not self.current_file_path: return

        async def do_decrypt(password: str | None):
            if not password:
                await self.animate_status("Расшифровка отменена.")
                return
            
            log = self.query_one(RichLog)
            try:
                data = self.current_file_path.read_bytes()
                salt, iv, tag = data[0:16], data[16:28], data[28:44]
                filename_len = int.from_bytes(data[44:46], 'big')
                filename_bytes = data[46:46+filename_len]
                ciphertext = data[46+filename_len:]
                original_filename = filename_bytes.decode('utf-8')

                key = self.derive_key(password, salt)
                decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                new_file_path = self.current_file_path.with_name(original_filename)

                if new_file_path.exists():
                    log.write(f"[bold yellow]ПРЕДУПРЕЖДЕНИЕ:[/bold yellow] Файл '{new_file_path.name}' уже существует. Он будет перезаписан.")

                new_file_path.write_bytes(plaintext)
                os.remove(self.current_file_path)
                await self.animate_status(f"Успех! Расшифрован как {new_file_path.name}")
                self.reset_state()
            except (InvalidTag, ValueError, IndexError):
                log.write("[bold red]Ошибка:[/bold red] Расшифровка не удалась. Неверный пароль или файл поврежден!")
                await self.animate_status("Ошибка: неверный пароль.")
                self.cached_password = None
            except Exception as e:
                log.write(f"[bold red]Непредвиденная ошибка:[/bold red]\n{e}")
                await self.animate_status("Непредвиденная ошибка.")
        
        if self.cached_password:
            await do_decrypt(self.cached_password)
        else:
            self.push_screen(PasswordDialog("Пароль для расшифровки:"), do_decrypt)
    
    def reset_state(self, clear_preview=True):
        self.cached_password = None
        self.current_file_path = None
        self.query_one("#action_button", Button).disabled = True
        self.query_one("#action_button", Button).label = "Выберите файл"
        self.query_one("#file_path", Input).value = ""
        
        if clear_preview:
            log = self.query_one(RichLog)
            log.clear()
            log.write("Операция завершена.\n\nВведите путь к следующему файлу...")


if __name__ == "__main__":
    app = CryptoTerminalApp()
    app.run()