from flask import Flask, request, render_template,redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

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
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard1.html', user=user)

    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('name',None)
    return redirect('/loginup')


if __name__=='__main__':
    app.run(debug=True)