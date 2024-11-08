from flask import Flask, request, render_template,redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_socketio import SocketIO, emit, join_room
import random
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database2.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
socketio = SocketIO(app)
P = 23  # A prime number
G = 5   # A primitive root modulo P

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(100),nullable=False)
    email = db.Column(db.String(100),unique=True)
    password = db.Column(db.String(100))
    def __init__(self,email,password,username):
        self.username=username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    room = db.Column(db.String(100))

    # DH Key Exchange Model
class DHKeyExchange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    public_key = db.Column(db.String(1000))
    private_key = db.Column(db.String(1000))
    shared_secret = db.Column(db.String(1000))
    room = db.Column(db.String(100))


def generate_private_key():
    return random.randint(1, P - 1)

def generate_public_key(private_key):
    return pow(G, private_key, P)

def generate_shared_secret(private_key, other_public_key):
     return pow(other_public_key, private_key, P)




with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
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

@app.route('/loginup',methods=['GET','POST'])
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

    # Create a unique room name for these two users
    room = f"room_{min(current_user.id, receiver.id)}_{max(current_user.id, receiver.id)}"

    # Generate DH keys if not already existing
    dh_keys = DHKeyExchange.query.filter_by(user_id=current_user.id, room=room).first()
    if not dh_keys:
        private_key = generate_private_key()
        public_key = generate_public_key(private_key)
        dh_keys = DHKeyExchange(
            user_id=current_user.id,
            public_key=str(public_key),
            private_key=str(private_key),
            room=room
        )
        db.session.add(dh_keys)
        db.session.commit()

    messages = ChatMessage.query.filter_by(room=room).order_by(ChatMessage.timestamp).all()
    return render_template('chat.html', receiver=receiver, messages=messages, room=room, current_user=current_user)

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)


@socketio.on('send_message')
def handle_message(data):
    if 'email' not in session:
        return

    current_user = User.query.filter_by(email=session['email']).first()
    room = data['room']

    # Get DH keys
    sender_dh = DHKeyExchange.query.filter_by(user_id=current_user.id, room=room).first()
    receiver_dh = DHKeyExchange.query.filter_by(room=room).filter(
        DHKeyExchange.user_id != current_user.id
    ).first()

    if sender_dh and receiver_dh:
        # Generate shared secret if not already done
        if not sender_dh.shared_secret:
            shared_secret = generate_shared_secret(
                int(sender_dh.private_key),
                int(receiver_dh.public_key)
            )
            sender_dh.shared_secret = str(shared_secret)
            db.session.commit()

        # In a real application, you would use this shared secret for message encryption
        message = ChatMessage(
            sender_id=current_user.id,
            receiver_id=data['receiver_id'],
            message=data['message'],
            room=room
        )
        db.session.add(message)
        db.session.commit()

        emit('receive_message', {
            'sender': current_user.username,
            'message': data['message'],
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }, room=room)


if __name__=='__main__':
    app.run(debug=True)