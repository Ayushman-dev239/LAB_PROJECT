import hashlib
import os
from datetime import datetime

import bcrypt
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from flask import Flask, request, render_template, redirect, session, send_file, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database2.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
app.secret_key = 'secret_key'
socketio = SocketIO(app)

# Diffie-Hellman parameters
P = 23  # A prime number (should be much larger in production)
G = 5  # A primitive root modulo P


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    private_key = db.Column(db.Integer)  # DH private key
    public_key = db.Column(db.Integer)  # DH public key

    def __init__(self, email, password, username):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.generate_dh_keys()

    def generate_dh_keys(self):
        # Generate private and public keys for Diffie-Hellman
        self.private_key = int.from_bytes(get_random_bytes(4), 'big') % P
        self.public_key = pow(G, self.private_key, P)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.Column(db.String(100))
    is_file = db.Column(db.Boolean, default=False)
    file_name = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))


class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    original_filename = db.Column(db.String(200))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def calculate_shared_key(private_key, other_public_key):
    """Calculate shared secret using Diffie-Hellman"""
    shared_secret = pow(other_public_key, private_key, P)
    # Use SHA-256 to derive a proper key for TDES
    return hashlib.sha256(str(shared_secret).encode()).digest()[:24]


def encrypt_file(file_data, shared_key):
    """Encrypt file using TDES in EAX mode"""
    # Generate a nonce
    nonce = get_random_bytes(16)

    # Create cipher object
    cipher = DES3.new(shared_key, DES3.MODE_EAX, nonce=nonce)

    # Encrypt the data
    ciphertext = cipher.encrypt(file_data)

    # Compute the tag
    tag = cipher.digest()

    # Return nonce, tag, and ciphertext
    return nonce + tag + ciphertext


def decrypt_file(encrypted_data, shared_key):
    """Decrypt file using TDES in EAX mode"""
    try:
        # Extract nonce, tag and ciphertext
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Create cipher object
        cipher = DES3.new(shared_key, DES3.MODE_EAX, nonce=nonce)

        # Decrypt and verify
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)

        return plaintext
    except ValueError as e:
        raise ValueError("Decryption failed: Invalid key or corrupted file")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/loginup')

    return render_template('signup.html')


@app.route('/loginup', methods=['GET', 'POST'])
def loginup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')
    return render_template('login.html')
@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        # Retrieve a list of users to chat with (excluding the current user)
        receivers = User.query.filter(User.id != user.id).all()
        return render_template('dashboard1.html', user=user, receivers=receivers)
    return redirect('/loginup')

@app.route('/logout')
def logout():
    session.pop('name',None)
    return redirect('/loginup')
@app.route('/chat/<receiver_id>')
def chat(receiver_id):
    if 'email' not in session:
        return redirect('/loginup')

    current_user = User.query.filter_by(email=session['email']).first()
    receiver = User.query.get(receiver_id)

    if not receiver:
        return "User not found", 404

    # Create a unique room name for the conversation between these two users
    room = f"room_{min(current_user.id, receiver.id)}_{max(current_user.id, receiver.id)}"

    # Ensure Diffie-Hellman keys are generated for the current user in this chat
    if current_user.private_key is None or current_user.public_key is None:
        current_user.generate_dh_keys()
        db.session.commit()

    # Fetch chat messages in this room
    messages = ChatMessage.query.filter_by(room=room).order_by(ChatMessage.timestamp).all()

    # Retrieve recent files shared in this room
    shared_files = SharedFile.query.filter_by(room=room).order_by(SharedFile.timestamp.desc()).limit(5).all()

    # Render chat template with messages, files, and user information
    return render_template('chat.html', receiver=receiver, messages=messages, room=room, current_user=current_user, shared_files=shared_files)


@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)


@socketio.on('send_message')
def handle_send_message(data):
    if 'email' not in session:
        return redirect('/loginup')

    current_user = User.query.filter_by(email=session['email']).first()
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')
    room = data.get('room')

    if not receiver_id or not message_text:
        return

    # Store message in database
    message = ChatMessage(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        message=message_text,
        room=room
    )
    db.session.add(message)
    db.session.commit()

    # Broadcast the message to all users in the room
    socketio.emit('receive_message', {
        'sender': current_user.username,
        'message': message_text,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'is_file': False
    }, room=room)


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'email' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    try:
        current_user = User.query.filter_by(email=session['email']).first()
        receiver_id = request.form.get('receiver_id')
        room = request.form.get('room')

        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        # Get receiver's public key
        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'success': False, 'error': 'Receiver not found'}), 404

        # Calculate shared key using Diffie-Hellman
        shared_key = calculate_shared_key(current_user.private_key, receiver.public_key)

        # Read and encrypt file
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, shared_key)

        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        encrypted_filename = f"{timestamp}_{hash(str(encrypted_data))}_{file.filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

        # Save encrypted file
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # Create shared file record
        shared_file = SharedFile(
            filename=encrypted_filename,
            original_filename=file.filename,
            sender_id=current_user.id,
            receiver_id=receiver_id,
            room=room
        )
        db.session.add(shared_file)

        # Create chat message for file share
        message = ChatMessage(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            message=f"Shared file: {file.filename}",
            room=room,
            is_file=True,
            file_name=encrypted_filename,
            original_filename=file.filename
        )
        db.session.add(message)
        db.session.commit()

        socketio.emit('receive_message', {
            'sender': current_user.username,
            'message': f"Shared file: {file.filename}",
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_file': True
        }, room=room)

        return jsonify({'success': True, 'message': 'File uploaded successfully'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/download_file/<int:file_id>')
def download_file(file_id):
    if 'email' not in session:
        return 'Unauthorized', 401

    try:
        current_user = User.query.filter_by(email=session['email']).first()
        shared_file = SharedFile.query.get(file_id)

        if not shared_file:
            return 'File not found', 404

        # Verify user is part of the conversation
        if shared_file.sender_id != current_user.id and shared_file.receiver_id != current_user.id:
            return 'Unauthorized', 401

        # Get the other user's public key
        other_user_id = shared_file.sender_id if current_user.id == shared_file.receiver_id else shared_file.receiver_id
        other_user = User.query.get(other_user_id)

        # Calculate shared key
        shared_key = calculate_shared_key(current_user.private_key, other_user.public_key)

        # Read encrypted file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], shared_file.filename)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        try:
            decrypted_data = decrypt_file(encrypted_data, shared_key)
        except ValueError as e:
            return str(e), 400

        # Create temporary file for download
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{shared_file.original_filename}')
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)

        return send_file(
            temp_path,
            as_attachment=True,
            download_name=shared_file.original_filename,
            max_age=0
        )

    except Exception as e:
        return str(e), 500

    finally:
        # Clean up temporary file
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)


# [Previous route handlers remain the same...]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)