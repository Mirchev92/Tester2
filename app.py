from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
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
import logging

# Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static')
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
migrate = Migrate(app, db)  # Add this line
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
    sms_enabled = db.Column(db.Boolean, default=True)
    sms_template = db.Column(db.Text, default='Здравейте, пропуснах обаждането ви. Ще се свържа с вас при първа възможност.')
    working_hours_start = db.Column(db.String(5), default='09:00')
    working_hours_end = db.Column(db.String(5), default='18:00')
    working_days = db.Column(db.String(100), default='Monday,Tuesday,Wednesday,Thursday,Friday')
    off_hours_message = db.Column(db.Text, default='Здравейте, в момента сме извън работно време. Ще се свържем с вас през работния ден.')
    vacation_mode = db.Column(db.Boolean, default=False)
    vacation_message = db.Column(db.Text, default='Здравейте, в момента съм в отпуск. Ще се свържа с вас след завръщането си.')

class MissedCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    call_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    caller_number = db.Column(db.String(15), nullable=False)
    responded = db.Column(db.Boolean, default=False)
    message_sent = db.Column(db.String(160))

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    name = db.Column(db.String(100))
    location = db.Column(db.String(200))
    last_job = db.Column(db.String(500))
    status = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_sinch_sms(phone_number, message_type='default'):
    user = current_user
    
    # Check if SMS is enabled
    if not user.sms_enabled:
        return False, "SMS service is disabled"
        
    # Check vacation mode
    if user.vacation_mode:
        message = user.vacation_message
    else:
        # Check working hours and days
        now = datetime.now()
        current_time = now.strftime("%H:%M")
        current_day = now.strftime("%A")
        
        if (current_day not in user.working_days.split(',') or 
            current_time < user.working_hours_start or 
            current_time > user.working_hours_end):
            message = user.off_hours_message
        else:
            message = user.sms_template
    
    # Send the SMS using Sinch
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

def is_saved_customer(phone_number):
    return Customer.query.filter_by(phone_number=phone_number).first() is not None

@app.route('/dashboard')
def dashboard():
    # Assuming you have SQLAlchemy models for MissedCall and Customer
    missed_calls = db.session.query(
        MissedCall, 
        Customer.name.label('customer_name')
    ).outerjoin(
        Customer, 
        MissedCall.caller_number == Customer.phone_number
    ).all()
    
    # Format the results
    formatted_calls = []
    for call, customer_name in missed_calls:
        call_dict = {
            'id': call.id,
            'call_time': call.call_time,
            'caller_number': call.caller_number,
            'message_sent': call.message_sent,
            'responded': call.responded,
            'is_saved_customer': customer_name is not None,
            'customer_name': customer_name
        }
        formatted_calls.append(call_dict)

    return render_template('dashboard.html', missed_calls=formatted_calls)

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

@app.route('/api/update-response', methods=['POST'])
@login_required
def update_response():
    try:
        data = request.json
        call_id = data.get('call_id')
        responded = data.get('responded', False)
        
        # Get the call and verify it belongs to the current user
        call = MissedCall.query.filter_by(id=call_id, user_id=current_user.id).first()
        if not call:
            return jsonify({'status': 'error', 'message': 'Call not found'}), 404
        
        # Update the response status
        call.responded = responded
        db.session.commit()
        
        # Calculate new response rate
        total_calls = MissedCall.query.filter_by(user_id=current_user.id).count()
        responded_calls = MissedCall.query.filter_by(user_id=current_user.id, responded=True).count()
        new_response_rate = round((responded_calls / total_calls * 100), 1) if total_calls > 0 else 0
        
        return jsonify({
            'status': 'success',
            'new_response_rate': new_response_rate
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/customers')
@login_required
def customers():
    print("Accessing customers route")  # Debug print
    try:
        customers = Customer.query.filter_by(user_id=current_user.id).order_by(Customer.last_updated.desc()).all()
        print(f"Found {len(customers)} customers")  # Debug print
        return render_template('customerinfo.html', customers=customers)
    except Exception as e:
        print(f"Error in customers route: {str(e)}")
        return str(e), 500

@app.route('/api/add-customer', methods=['POST'])
@login_required
def add_customer():
    try:
        data = request.json
        customer = Customer(
            user_id=current_user.id,
            phone_number=data['phone_number'],
            name=data.get('name', ''),
            location=data.get('location', ''),
            last_job=data.get('last_job', ''),
            status=data.get('status', 'New'),
            notes=data.get('notes', '')
        )
        db.session.add(customer)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Customer added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/customer/<int:customer_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_customer(customer_id):
    print(f"Handling {request.method} request for customer {customer_id}")  # Debug print
    
    if request.method == 'GET':
        try:
            customer = Customer.query.filter_by(
                id=customer_id,
                user_id=current_user.id
            ).first()
            
            if not customer:
                return jsonify({'error': 'Customer not found'}), 404
                
            return jsonify({
                'id': customer.id,
                'phone_number': customer.phone_number,
                'name': customer.name,
                'location': customer.location,
                'last_job': customer.last_job,
                'status': customer.status,
                'notes': customer.notes
            })
        except Exception as e:
            print(f"Error in GET: {str(e)}")
            return jsonify({'error': str(e)}), 500
            
    elif request.method == 'PUT':
        try:
            customer = Customer.query.filter_by(
                id=customer_id,
                user_id=current_user.id
            ).first()
            
            if not customer:
                return jsonify({'success': False, 'error': 'Customer not found'}), 404

            data = request.json
            customer.name = data.get('name', customer.name)
            customer.location = data.get('location', customer.location)
            customer.last_job = data.get('last_job', customer.last_job)
            customer.status = data.get('status', customer.status)
            customer.notes = data.get('notes', customer.notes)
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Customer updated successfully'})
        except Exception as e:
            db.session.rollback()
            print(f"Error in PUT: {str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500
            
    elif request.method == 'DELETE':
        try:
            print(f"Processing DELETE request for customer {customer_id}")  # Debug print
            
            customer = Customer.query.filter_by(
                id=customer_id,
                user_id=current_user.id
            ).first()
            
            if not customer:
                print(f"Customer {customer_id} not found")
                return jsonify({'success': False, 'error': 'Customer not found'}), 404

            print(f"Found customer {customer_id}, attempting delete")  # Debug print
            
            db.session.delete(customer)
            db.session.commit()
            
            print(f"Successfully deleted customer {customer_id}")  # Debug print
            
            return jsonify({
                'success': True,
                'message': 'Customer deleted successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            error_msg = f"Error deleting customer {customer_id}: {str(e)}"
            print(error_msg)  # Debug print
            return jsonify({
                'success': False,
                'error': error_msg
            }), 500

    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/sms-settings', methods=['GET', 'POST'])
@login_required
def sms_settings():
    if request.method == 'POST':
        try:
            # Update SMS settings
            current_user.sms_enabled = 'sms_enabled' in request.form
            current_user.sms_template = request.form.get('sms_template', '')
            
            # Update working hours
            current_user.working_hours_start = request.form.get('working_hours_start', '09:00')
            current_user.working_hours_end = request.form.get('working_hours_end', '18:00')
            
            # Update working days
            working_days = request.form.getlist('working_days')
            current_user.working_days = ','.join(working_days) if working_days else 'Monday,Tuesday,Wednesday,Thursday,Friday'
            
            # Update messages
            current_user.off_hours_message = request.form.get('off_hours_message', '')
            current_user.vacation_mode = 'vacation_mode' in request.form
            current_user.vacation_message = request.form.get('vacation_message', '')
            
            db.session.commit()
            flash('Настройките са запазени успешно!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Грешка при запазване на настройките: {str(e)}', 'error')
            
        return redirect(url_for('sms_settings'))
    
    return render_template('sms-settings.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("\nRegistered Routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule.rule}")
    app.run(debug=True)