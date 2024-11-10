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
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket

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

        # Get receiver's public key
        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'error': 'Receiver not found'}), 404

        # Calculate shared key and encrypt file
        shared_key = calculate_shared_key(current_user.private_key, receiver.public_key)
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

        # Emit file message to room
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


def download_file(file_id):
    if 'email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Get current user and file info
        current_user = User.query.filter_by(email=session['email']).first()
        chat_message = ChatMessage.query.filter_by(id=file_id, is_file=True).first()

        if not chat_message:
            # Try finding in SharedFile if not in ChatMessage
            shared_file = SharedFile.query.get(file_id)
            if not shared_file:
                return jsonify({'error': 'File not found'}), 404
            filename = shared_file.filename
            original_filename = shared_file.original_filename
            sender_id = shared_file.sender_id
            receiver_id = shared_file.receiver_id
        else:
            filename = chat_message.file_name
            original_filename = chat_message.original_filename
            sender_id = chat_message.sender_id
            receiver_id = chat_message.receiver_id

        # Verify user is part of the conversation
        if current_user.id not in (sender_id, receiver_id):
            return jsonify({'error': 'Unauthorized access'}), 401

        # Get the other user's public key
        other_user_id = sender_id if current_user.id == receiver_id else receiver_id
        other_user = User.query.get(other_user_id)

        if not other_user:
            return jsonify({'error': 'Other user not found'}), 404

        # Calculate shared key
        shared_key = calculate_shared_key(current_user.private_key, other_user.public_key)

        # Verify file exists
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on server'}), 404

        # Read and decrypt file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        try:
            # Decrypt the file
            decrypted_data = decrypt_file(encrypted_data, shared_key)

            # Create a temporary file for the decrypted content
            temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, f'temp_{original_filename}')

            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)

            # Send the file
            return send_file(
                temp_path,
                as_attachment=True,
                download_name=original_filename,
                max_age=0
            )

        except ValueError as e:
            print(f"Decryption error: {str(e)}")
            return jsonify({'error': 'Failed to decrypt file'}), 400

    except Exception as e:
        print(f"Download error: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up temporary file
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass


# Update the decrypt_file function to handle errors better
def decrypt_file(encrypted_data, shared_key):
    """Decrypt file using TDES in EAX mode"""
    try:
        if len(encrypted_data) < 32:  # Minimum length for nonce (16) + tag (16)
            raise ValueError("Encrypted data is too short")

        # Extract nonce and tag
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Create cipher object
        cipher = DES3.new(shared_key, DES3.MODE_EAX, nonce=nonce)

        # Decrypt and verify
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
        except ValueError:
            raise ValueError("Decryption failed: File may be corrupted or key is incorrect")

        return plaintext

    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")


# Update the encrypt_file function to match
def encrypt_file(file_data, shared_key):
    """Encrypt file using TDES in EAX mode"""
    try:
        # Generate a nonce
        nonce = get_random_bytes(16)

        # Create cipher object
        cipher = DES3.new(shared_key, DES3.MODE_EAX, nonce=nonce)

        # Encrypt the data
        ciphertext = cipher.encrypt(file_data)

        # Get the MAC tag
        tag = cipher.digest()

        # Combine nonce, tag, and ciphertext
        return nonce + tag + ciphertext

    except Exception as e:
        print(f"Encryption error: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

# [Previous route handlers remain the same...]

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)