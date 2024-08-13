import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, async_mode='eventlet')

valid_key = os.getenv('VALID_KEY', b'genuwei')

messages = []
key = os.urandom(16)
iv = os.urandom(16)

connected_users = set()

def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return ct

def decrypt_message(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def check_auth():
    authenticated = session.get('authenticated', False)
    return authenticated

def log_message(message):
    with open('messages.log', 'a') as log_file:
        log_file.write(message + '\n')

@app.route('/')
def home():
    if not check_auth():
        return redirect(url_for('login'))

    decrypted_messages = [decrypt_message(encrypted_message, key, iv) for encrypted_message in messages[::-1]]
    return render_template('index.html', messages=messages[::-1], decrypted_messages=decrypted_messages, connected_users=connected_users)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not check_auth():
        return redirect(url_for('login'))

    message = request.form['message']
    if not message.strip():
        return redirect(url_for('home'))

    username = session.get('username', 'Anonymous')
    full_message = f"{username}: {message}"

    encrypted_message = encrypt_message(full_message, key, iv)
    messages.insert(0, encrypted_message)

    decrypted_message = decrypt_message(encrypted_message, key, iv)

    socketio.emit('new_message', {'message': decrypted_message})

    log_message(decrypted_message)

    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        entered_key = request.form['key']
        entered_key_bytes = entered_key.encode()

        username = request.form.get('username', '')

        if not username:
            error = "Имя пользователя обязательно для заполнения."
        elif entered_key_bytes == valid_key:
            session['authenticated'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = "Неверный ключ. Пожалуйста, попробуйте снова."

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    if check_auth():
        join_room('chat')
        connected_users.add(session['username'])
        emit('user_connected', {'username': session['username']})
        emit('update_online_users', {'users': list(connected_users)})

@socketio.on('disconnect')
def handle_disconnect():
    if check_auth():
        leave_room('chat')
        connected_users.remove(session['username'])
        emit('user_disconnected', {'username': session['username']})
        emit('update_online_users', {'users': list(connected_users)})

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    socketio.run(app, host='26.216.5.64', port=443, debug=True)