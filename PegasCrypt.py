import os
import webbrowser
from threading import Timer
from flask import Flask, render_template_string, request, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

def get_key(password):
    password = password.encode()
    salt = b'salt_'  # В реальном приложении используйте случайную соль
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt(text, password):
    key = get_key(password)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

def decrypt(text, password):
    key = get_key(password)
    f = Fernet(key)
    return f.decrypt(text.encode()).decode()

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    data = request.json
    encrypted = encrypt(data['text'], data['password'])
    return jsonify({'encrypted': encrypted})

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    data = request.json
    try:
        decrypted = decrypt(data['text'], data['password'])
        return jsonify({'decrypted': decrypted})
    except:
        return jsonify({'error': 'Decryption failed. Check your password.'}), 400

def open_browser():
    webbrowser.open_new('http://localhost:9999/')

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypto Web App</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background-color: #000;
            color: #0f0;
            display: flex;
            height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .container {
            display: flex;
            width: 100%;
        }
        .crypto-section {
            flex: 1;
            padding: 20px;
            border: 1px solid #0f0;
            margin-right: 10px;
        }
        .preview-section {
            flex: 1;
            padding: 20px;
            border: 1px solid #0f0;
        }
        input, textarea, button {
            background-color: #000;
            color: #0f0;
            border: 1px solid #0f0;
            padding: 5px;
            margin: 5px 0;
            width: 100%;
        }
        button:hover {
            background-color: #0f0;
            color: #000;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="crypto-section">
            <h2>Crypto Operations</h2>
            <textarea id="input" rows="10" placeholder="Enter text to encrypt/decrypt"></textarea>
            <input type="password" id="password" placeholder="Enter password">
            <button onclick="encrypt()">Encrypt</button>
            <button onclick="decrypt()">Decrypt</button>
            <textarea id="output" rows="10" readonly></textarea>
        </div>
        <div class="preview-section">
            <h2>Preview</h2>
            <div id="preview"></div>
        </div>
    </div>
    <script>
        async function encrypt() {
            const text = document.getElementById('input').value;
            const password = document.getElementById('password').value;
            const response = await fetch('/encrypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({text, password})
            });
            const data = await response.json();
            document.getElementById('output').value = data.encrypted;
        }

        async function decrypt() {
            const text = document.getElementById('input').value;
            const password = document.getElementById('password').value;
            const response = await fetch('/decrypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({text, password})
            });
            const data = await response.json();
            if (data.error) {
                alert(data.error);
            } else {
                document.getElementById('output').value = data.decrypted;
                document.getElementById('preview').innerText = data.decrypted;
            }
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(port=9999)