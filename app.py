from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_cors import CORS
import os
import requests

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure Flask app
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///missed_calls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SMSAPI_KEY'] = 'LEUn7C6fUtmy5u72UkbuxkkCU0ZeJVrW1RiFS6C4'
app.config['SMSAPI_SENDER'] = 'MissCallApp'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    missed_calls = db.relationship('MissedCall', backref='user', lazy=True)

class MissedCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    call_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    caller_number = db.Column(db.String(15), nullable=False)
    responded = db.Column(db.Boolean, default=False)
    message_sent = db.Column(db.String(160))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_sms(phone_number, message):
    try:
        # SMSAPI.bg endpoint
        sms_url = 'https://api.smsapi.bg/send'
        
        payload = {
            'to': phone_number,
            'message': message,
            'sender': app.config['SMSAPI_SENDER']
        }
        
        headers = {
            'Authorization': f'Bearer {app.config["SMSAPI_KEY"]}',
            'Content-Type': 'application/json'
        }

        response = requests.post(sms_url, json=payload, headers=headers)
        print(f"SMS API Response: {response.text}")  # Debug log
        
        if response.status_code == 200:
            return True, "SMS sent successfully"
        else:
            return False, f"SMS failed: {response.text}"

    except Exception as e:
        print(f"SMS Error: {str(e)}")  # Debug log
        return False, str(e)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, phone_number=phone_number)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    missed_calls = MissedCall.query.filter_by(user_id=current_user.id).order_by(MissedCall.call_time.desc()).all()
    return render_template('dashboard.html', missed_calls=missed_calls)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/test', methods=['GET'])
def test_connection():
    print("Test connection received!")
    return jsonify({'status': 'success', 'message': 'Connection successful!'})

@app.route('/api/test-sms', methods=['POST'])
def test_sms():
    try:
        data = request.json
        phone_number = data.get('phone_number')
        message = data.get('message', 'Test message from MissCall App')

        success, response_message = send_sms(phone_number, message)
        
        if success:
            return jsonify({'status': 'success', 'message': response_message}), 200
        else:
            return jsonify({'status': 'error', 'message': response_message}), 500

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/missed-call', methods=['POST'])
def handle_missed_call():
    print("Received data:", request.json)
    try:
        data = request.json
        missed_call = MissedCall(
            user_id=data['user_id'],
            caller_number=data['caller_number'],
            call_time=datetime.strptime(data['call_time'], '%Y-%m-%d %H:%M:%S')
        )
        
        # Send SMS to the caller
        message = "Sorry I missed your call. I'll get back to you as soon as possible."
        success, sms_response = send_sms(missed_call.caller_number, message)
        
        if success:
            missed_call.message_sent = message
        
        db.session.add(missed_call)
        db.session.commit()
        print("Successfully saved to database")
        
        return jsonify({
            'status': 'success',
            'sms_status': 'sent' if success else 'failed',
            'sms_message': sms_response
        }), 200
        
    except Exception as e:
        print("Error:", str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/list-calls', methods=['GET'])
def list_calls():
    missed_calls = MissedCall.query.order_by(MissedCall.call_time.desc()).all()
    calls_list = []
    for call in missed_calls:
        calls_list.append({
            'id': call.id,
            'user_id': call.user_id,
            'caller_number': call.caller_number,
            'call_time': call.call_time.strftime('%Y-%m-%d %H:%M:%S'),
            'responded': call.responded,
            'message_sent': call.message_sent
        })
    return jsonify(calls_list)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)