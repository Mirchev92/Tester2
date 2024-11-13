from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_cors import CORS
import os
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure Flask app
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///missed_calls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Sinch Configuration
app.config['SINCH_SERVICE_PLAN_ID'] = 'e64d3dd7c1ea419abc8d24a3ea18f898'
app.config['SINCH_API_TOKEN'] = '427214e99b1f4b7a8c0fbd99927647be'
app.config['SINCH_SENDER'] = 'MissCall'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Add rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

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

def send_sinch_sms(phone_number, message):
    try:
        # Format phone number (remove + if present and ensure it starts with 359)
        formatted_phone = phone_number.replace('+', '')
        if not formatted_phone.startswith('359'):
            formatted_phone = '359' + formatted_phone.lstrip('0')

        url = f"https://us.sms.api.sinch.com/xms/v1/{app.config['SINCH_SERVICE_PLAN_ID']}/batches"
        
        payload = {
            "from": app.config['SINCH_SENDER'],
            "to": [formatted_phone],
            "body": message
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {app.config['SINCH_API_TOKEN']}"
        }

        # Debug prints
        print("Attempting to send SMS with:")
        print(f"URL: {url}")
        print(f"Payload: {payload}")
        
        response = requests.post(url, json=payload, headers=headers)
        
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Text: {response.text}")
        
        if response.status_code == 201:
            print(f"Message sent successfully: {response.json()}")
            return True, "Message sent successfully"
        else:
            return False, f"Failed to send message: {response.text}"
            
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        return False, str(e)

# Add password validation function
def is_password_valid(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""

# Update app configuration
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),  # Session expires after 1 day
    SESSION_COOKIE_SECURE=True,  # Cookies only sent over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax'  # Protect against CSRF
)

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
        
        # Add password validation
        is_valid, error_message = is_password_valid(password)
        if not is_valid:
            flash(error_message)
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')
        new_user = User(username=username, password=hashed_password, phone_number=phone_number)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate limiting for login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)  # Enable remember me
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

# API Routes
@app.route('/api/test', methods=['GET'])
def test_connection():
    print("Test connection received!")
    return jsonify({'status': 'success', 'message': 'Connection successful!'})

@app.route('/api/test-route')
def test_route():
    return jsonify({'message': 'Test route works!'})

@app.route('/api/check-user/<username>')
def check_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({
            'id': user.id,
            'username': user.username,
            'phone_number': user.phone_number
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/fix-user-ids')
def fix_user_ids():
    try:
        # Get damirche's numeric ID
        user = User.query.filter_by(username='damirche').first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Update all missed calls
        calls = MissedCall.query.filter_by(user_id='damirche').all()
        for call in calls:
            call.user_id = user.id
        
        db.session.commit()
        return jsonify({'message': f'Updated {len(calls)} calls'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-sms', methods=['POST'])
def test_sms():
    try:
        data = request.json
        if not data or 'phone_number' not in data:
            return jsonify({'status': 'error', 'message': 'Phone number required'}), 400

        phone_number = data['phone_number']
        message = data.get('message', 'Test message from MissCall App')
        
        print(f"Testing SMS to {phone_number}: {message}")
        success, response_message = send_sinch_sms(phone_number, message)
        
        if success:
            return jsonify({'status': 'success', 'message': response_message}), 200
        else:
            return jsonify({'status': 'error', 'message': response_message}), 500

    except Exception as e:
        print(f"Error in test_sms: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/missed-call', methods=['POST'])
def handle_missed_call():
    print("Received data:", request.json)
    try:
        data = request.json
        
        # If user_id is username, get the numeric ID
        user_id = data['user_id']
        if isinstance(user_id, str) and not user_id.isdigit():
            user = User.query.filter_by(username=user_id).first()
            if user:
                user_id = user.id
            else:
                return jsonify({'error': 'User not found'}), 404

        missed_call = MissedCall(
            user_id=user_id,
            caller_number=data['caller_number'],
            call_time=datetime.strptime(data['call_time'], '%Y-%m-%d %H:%M:%S')
        )
        
        # Send SMS to the caller
        message = "Sorry I missed your call. I'll get back to you as soon as possible."
        success, sms_response = send_sinch_sms(missed_call.caller_number, message)
        
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