import hashlib
import os
from datetime import datetime

import bcrypt
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from flask import Flask, request, render_template, redirect, session, send_file, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
import hashlib
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from flask import Flask, jsonify, send_file
from flask_socketio import emit
from flask import Flask, request, render_template, redirect, session, send_file, jsonify, after_this_request

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database2.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
app.secret_key = 'secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket

# Diffie-Hellman parameters
P = 23  # A prime number (should be much larger in production)
G = 5  # A primitive root modulo P


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    private_key = db.Column(db.String(64))  # Store as hex string
    public_key = db.Column(db.String(64))  # Store as hex string

    # DH public key

    def __init__(self, email, password, username):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.generate_dh_keys()

    def generate_dh_keys(self):
        # Generate private key (32 bytes for security)
        private_bytes = get_random_bytes(32)
        self.private_key = private_bytes.hex()
        # Calculate public key
        private_int = int.from_bytes(private_bytes, 'big')
        public_int = pow(G, private_int, P)
        self.public_key = hex(public_int)[2:]  # Remove '0x' prefix

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


def calculate_shared_key(private_key_hex, other_public_key_hex):
    """Calculate shared secret using Diffie-Hellman with hex strings"""
    try:
        # Convert hex strings to integers
        private_int = int.from_bytes(bytes.fromhex(private_key_hex), 'big')
        other_public_int = int(other_public_key_hex, 16)

        # Calculate shared secret
        shared_secret = pow(other_public_int, private_int, P)

        # Derive encryption key using SHA-256
        shared_key = hashlib.sha256(str(shared_secret).encode()).digest()[:24]
        return shared_key
    except Exception as e:
        print(f"Error calculating shared key: {str(e)}")
        raise ValueError(f"Failed to calculate shared key: {str(e)}")



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
    try:
        if 'email' not in session:
            return {'error': 'Unauthorized'}, 401

        current_user = User.query.filter_by(email=session['email']).first()
        if not current_user:
            return {'error': 'User not found'}, 404

        receiver_id = data.get('receiver_id')
        message_text = data.get('message')
        room = data.get('room')

        if not all([receiver_id, message_text, room]):
            return {'error': 'Missing required data'}, 400

        # Store message in database
        message = ChatMessage(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            message=message_text,
            room=room,
            timestamp=datetime.utcnow()
        )
        db.session.add(message)
        db.session.commit()

        # Emit message to room
        response_data = {
            'sender_id': current_user.id,
            'sender': current_user.username,
            'message': message_text,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_file': False
        }

        emit('receive_message', response_data, room=room)
        return {'success': True}

    except Exception as e:
        db.session.rollback()
        print(f"Error in handle_send_message: {str(e)}")
        return {'error': str(e)}, 500


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        current_user = User.query.filter_by(email=session['email']).first()
        receiver_id = request.form.get('receiver_id')
        room = request.form.get('room')
        file = request.files['file']

        if not all([current_user, receiver_id, room, file.filename]):
            return jsonify({'error': 'Missing required data'}), 400

        # Get receiver using new SQLAlchemy style
        receiver = db.session.get(User, receiver_id)
        if not receiver:
            return jsonify({'error': 'Receiver not found'}), 404

        # Calculate shared key using hex strings
        shared_key = calculate_shared_key(
            current_user.private_key,
            receiver.public_key
        )

        # Read and encrypt file
        file_data = file.read()
        encrypted_data = encrypt_file(file_data, shared_key)

        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        file_hash = hashlib.md5(encrypted_data).hexdigest()[:10]
        encrypted_filename = f"{timestamp}_{file_hash}_{file.filename}"
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

        # Create chat message
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

        # Emit message
        socketio.emit('receive_message', {
            'sender': current_user.username,
            'message': f"Shared file: {file.filename}",
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_file': True,
            'file_id': shared_file.id
        }, room=room)

        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'file_id': shared_file.id
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error in upload_file: {str(e)}")
        return jsonify({'error': str(e)}), 500


app.route('/download_file/<int:file_id>')


def pad_data(data):
    """Pad the data to be multiple of 8 (required for DES3)"""
    padding_length = 8 - (len(data) % 8)
    padded_data = data + bytes([padding_length] * padding_length)
    return padded_data


def unpad_data(padded_data):
    """Remove PKCS7 padding"""
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


def encrypt_file(file_data, shared_key):
    """Encrypt file using TDES in CBC mode with proper padding"""
    try:
        # Generate IV
        iv = get_random_bytes(8)  # DES3 uses 8-byte IV

        # Pad the data (PKCS7)
        block_size = 8
        padding_length = block_size - (len(file_data) % block_size)
        padded_data = file_data + bytes([padding_length] * padding_length)

        # Create cipher
        cipher = DES3.new(shared_key, DES3.MODE_CBC, iv)

        # Encrypt
        encrypted_data = cipher.encrypt(padded_data)

        # Return IV + encrypted data
        return iv + encrypted_data
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")


def decrypt_file(encrypted_data, shared_key):
    """Decrypt file using TDES in CBC mode"""
    try:
        if len(encrypted_data) < 8:  # Need at least IV (8 bytes)
            raise ValueError("Encrypted data is too short")

        # Extract IV and ciphertext
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]

        # Create cipher
        cipher = DES3.new(shared_key, DES3.MODE_CBC, iv)

        # Decrypt
        padded_plaintext = cipher.decrypt(ciphertext)

        # Remove padding
        padding_length = padded_plaintext[-1]
        if padding_length > 8:
            raise ValueError("Invalid padding")
        plaintext = padded_plaintext[:-padding_length]

        return plaintext
    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")


@app.route('/download_file/<int:file_id>')
def download_file(file_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        current_user = User.query.filter_by(email=session['email']).first()
        if not current_user:
            return jsonify({'error': 'Current user not found'}), 404

        # Use SQLAlchemy 2.0 style queries
        chat_message = db.session.get(ChatMessage, file_id)
        shared_file = None if chat_message else db.session.get(SharedFile, file_id)

        if not chat_message and not shared_file:
            return jsonify({'error': 'File not found'}), 404

        file_record = chat_message or shared_file
        filename = getattr(file_record, 'file_name', None) or file_record.filename
        original_filename = file_record.original_filename
        sender_id = file_record.sender_id
        receiver_id = file_record.receiver_id

        if current_user.id not in (sender_id, receiver_id):
            return jsonify({'error': 'Unauthorized access'}), 401

        other_user_id = sender_id if current_user.id == receiver_id else receiver_id
        other_user = db.session.get(User, other_user_id)

        if not other_user:
            return jsonify({'error': 'Other user not found'}), 404

        # Calculate shared key using hex strings
        shared_key = calculate_shared_key(
            current_user.private_key,
            other_user.public_key
        )

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on server'}), 404

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        try:
            decrypted_data = decrypt_file(encrypted_data, shared_key)

            # Create temp file
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, f'temp_{datetime.now().strftime("%Y%m%d_%H%M%S")}_{original_filename}')

            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)

            @after_this_request
            def remove_file(response):
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception as e:
                    print(f"Error removing temp file: {e}")
                return response

            return send_file(
                temp_path,
                as_attachment=True,
                download_name=original_filename,
                max_age=0
            )

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return jsonify({'error': f'Failed to decrypt file: {str(e)}'}), 400

    except Exception as e:
        print(f"Download error: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)