from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, session, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, UTC, timezone, timedelta
from flask_cors import CORS
import os
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import timedelta
import logging
from functools import wraps
import random
import string
import psutil
from logging.handlers import RotatingFileHandler
from sqlalchemy import or_
import pytz
from colorama import init, Fore
import atexit 
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, FloatField, DateField
from wtforms.validators import DataRequired, Optional
from sqlalchemy import inspect
from models import db, User, MissedCall, Customer, UserActivity, UserQuota, Case, Activity, CreateCaseForm, GalleryItem, FavoriteSpecialist, Review, BusinessTier, BusinessProfile, PointsTransaction, initialize_business_tiers, Notification
from werkzeug.utils import secure_filename
from PIL import Image
import uuid
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_mail import Mail, Message
from email_handler import send_custom_email
from dotenv import load_dotenv
load_dotenv()
from config import config

# Initialize colorama
try:
    # Initialize colorama with stop on exit
    init(autoreset=True)
    atexit.register(lambda: init(False))  # Ensure proper cleanup on exit
except Exception as e:
    print(f"Warning: Colorama initialization failed: {e}")

    # Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='static')
CORS(app)

app.config.from_object(config[os.getenv('FLASK_ENV', 'development')])

def ensure_upload_dirs():
    """Ensure all required upload directories exist"""
    base_upload_dir = os.path.join(app.static_folder, 'uploads')
    subdirs = ['profile_pics', 'gallery']
    
    for subdir in subdirs:
        full_path = os.path.join(base_upload_dir, subdir)
        if not os.path.exists(full_path):
            os.makedirs(full_path)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = 'static/uploads'
def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file, subfolder):
    """Helper function to save and process uploaded images"""
    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(file.filename)[1])
        
        # Create path relative to uploads folder (without 'uploads/' prefix)
        relative_path = os.path.join(subfolder, filename).replace('\\', '/')
        
        # Full system path for saving the file
        absolute_path = os.path.join(app.static_folder, 'uploads', relative_path)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(absolute_path), exist_ok=True)
        
        try:
            # Save and optimize image
            image = Image.open(file)
            image = image.convert('RGB')
            image.thumbnail((800, 800))
            image.save(absolute_path, optimize=True, quality=85)
            
            # Return path without 'uploads/' prefix
            return relative_path
        except Exception as e:
            app.logger.error(f"Error saving image: {str(e)}")
            return None
    return None
# Add this decorator function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in first')
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('You do not have admin privileges')
            if current_user.user_type == 'business':
                return redirect(url_for('business_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        return f(*args, **kwargs)
    return decorated_function
    
# OAuth
app.config['GOOGLE_OAUTH_CLIENT_ID'] = 'your-google-client-id'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = 'your-google-client-secret'
app.config['FACEBOOK_OAUTH_CLIENT_ID'] = 'your-facebook-client-id'
app.config['FACEBOOK_OAUTH_CLIENT_SECRET'] = 'your-facebook-client-secret'

google_bp = make_google_blueprint(scope=['profile', 'email'])
facebook_bp = make_facebook_blueprint(scope=['email'])
app.register_blueprint(google_bp, url_prefix='/login')
app.register_blueprint(facebook_bp, url_prefix='/login')
# Configure Flask app
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///missed_calls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Sinch Configuration
app.config['SINCH_SERVICE_PLAN_ID'] = 'e64d3dd7c1ea419abc8d24a3ea18f898'
app.config['SINCH_API_TOKEN'] = '427214e99b1f4b7a8c0fbd99927647be'
app.config['SINCH_SENDER'] = 'MissCall'

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-specific-password'

mail = Mail(app)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Simplified rate limiter configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
def fix_image_paths():
    """Fix and standardize image paths in the database"""
    try:
        # Fix profile pictures
        users = User.query.all()
        for user in users:
            if user.profile_picture:
                # Standardize path format
                path = user.profile_picture.replace('\\', '/').replace('\\\\', '/')
                
                # Remove any 'uploads/' prefix
                if path.startswith('uploads/'):
                    path = path[8:]  # Remove 'uploads/'
                
                # Ensure proper subfolder prefix
                if not path.startswith('profile_pics/'):
                    path = f'profile_pics/{os.path.basename(path)}'
                
                user.profile_picture = path

        # Fix gallery items
        gallery_items = GalleryItem.query.all()
        for item in gallery_items:
            if item.image_path:
                # Standardize path format
                path = item.image_path.replace('\\', '/').replace('\\\\', '/')
                
                # Remove any 'uploads/' prefix
                if path.startswith('uploads/'):
                    path = path[8:]  # Remove 'uploads/'
                
                # Ensure proper subfolder prefix
                if not path.startswith('gallery/'):
                    path = f'gallery/{os.path.basename(path)}'
                
                item.image_path = path

        db.session.commit()
        app.logger.info("Successfully fixed image paths in database")
    except Exception as e:
        app.logger.error(f"Error fixing image paths: {str(e)}")
        db.session.rollback()
@app.route('/admin/review/<int:review_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_review(review_id):
    try:
        review = Review.query.get_or_404(review_id)
        
        # Store info for recalculating specialist's rating
        specialist_id = review.specialist_id
        
        # Delete the review
        db.session.delete(review)
        
        # Recalculate specialist's rating
        specialist = User.query.get(specialist_id)
        remaining_reviews = Review.query.filter_by(specialist_id=specialist_id).all()
        
        if remaining_reviews:
            total_rating = sum(review.rating for review in remaining_reviews)
            specialist.rating = round(total_rating / len(remaining_reviews), 1)
            specialist.reviews_count = len(remaining_reviews)
        else:
            specialist.rating = 0
            specialist.reviews_count = 0
            
        db.session.commit()
        
        # Log the action
        activity = UserActivity(
            user_id=current_user.id,
            action='delete_review',
            details=f'Deleted review for specialist {specialist.username}'
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Review deleted successfully',
            'new_rating': specialist.rating,
            'new_count': specialist.reviews_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
@app.route('/admin/specialists')
@login_required
@admin_required
def admin_specialists():
    try:
        specialists = User.query.filter_by(user_type='business').all()
        
        # Format specialists data
        formatted_specialists = []
        for specialist in specialists:
            # Count completed cases
            completed_cases = Case.query.filter_by(
                specialist_id=specialist.id,
                status='completed'
            ).count()
            
            # Calculate response rate
            total_cases = Case.query.filter_by(specialist_id=specialist.id).count()
            response_rate = (completed_cases / total_cases * 100) if total_cases > 0 else 0
            
            specialist_data = {
                'id': specialist.id,
                'username': specialist.username,
                'profile_picture': specialist.profile_picture,
                'specialization': specialist.specialization or 'Not specified',
                'location': specialist.location or 'Location not specified',
                'working_hours': f"{specialist.working_hours_start} - {specialist.working_hours_end}",
                'working_days': specialist.working_days,
                'is_online': specialist.is_online,
                'rating': specialist.rating or 0,
                'reviews_count': specialist.reviews_count or 0,
                'completed_jobs': completed_cases,
                'response_rate': round(response_rate, 1)
            }
            formatted_specialists.append(specialist_data)
            
        return render_template(
            'Business_User/admin_specialists.html',
            specialists=formatted_specialists
        )
        
    except Exception as e:
        app.logger.error(f"Error in admin specialists view: {str(e)}")
        flash('Error loading specialists', 'error')
        return redirect(url_for('admin_dashboard'))
                
@app.route('/create-guest-case', methods=['GET', 'POST'])
def create_guest_case():
    if request.method == 'POST':
        try:
            original_email = request.form['email'].lower().strip()  # Normalize email
            
            # Direct email check - most strict
            existing_user = User.query.filter_by(email=original_email).first()
            
            if existing_user:
                flash('An account with this email already exists. Please login or use a different email.')
                return redirect(url_for('customer_login'))
            
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            temp_username = f'guest_{timestamp}'
            temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            hashed_password = generate_password_hash(temp_password)

            guest_user = User(
                username=temp_username,
                password=hashed_password,
                email=original_email,  # Store the original email directly
                phone_number='pending',
                is_guest=True,
                user_type='customer',
                sms_enabled=False
            )

            db.session.add(guest_user)
            db.session.commit()

            email_content = f'Login details:\nUsername: {temp_username}\nPassword: {temp_password}'
            email_sent = send_custom_email(
                app,
                original_email,
                'MissCall Account',
                email_content
            )

            if not email_sent:
                print("Email failed but user created")

            login_user(guest_user)
            return redirect(url_for('customer_create_case'))

        except Exception as e:
            db.session.rollback()
            print(f"Error details: {str(e)}")
            app.logger.error(f"Error creating guest user: {str(e)}")
            flash('Error creating guest account. Please try again.')
            return redirect(url_for('create_guest_case'))

    return render_template('Customer_User/guest_case_form.html')

@app.route('/login/<provider>/<user_type>')
def social_login(provider, user_type):
    if user_type not in ['business', 'customer']:
        return redirect(url_for('index'))
        
    if provider == 'google':
        if not google.authorized:
            session['intended_user_type'] = user_type  # Store intended user type
            return redirect(url_for('google.login'))
            
        resp = google.get('/oauth2/v1/userinfo')
        assert resp.ok, resp.text
        user_info = resp.json()
        
        # Check if user exists
        user = User.query.filter_by(
            social_id=user_info['id'],
            social_provider='google'
        ).first()
        
        if not user:
            # Create new user with specified user type
            user = User(
                username=user_info['email'].split('@')[0],
                email=user_info['email'],
                social_id=user_info['id'],
                social_provider='google',
                phone_number='pending',
                user_type=user_type
            )
            db.session.add(user)
            db.session.commit()
            
    elif provider == 'facebook':
        if not facebook.authorized:
            session['intended_user_type'] = user_type  # Store intended user type
            return redirect(url_for('facebook.login'))
            
        resp = facebook.get('/me?fields=id,email,name')
        assert resp.ok, resp.text
        user_info = resp.json()
        
        # Check if user exists
        user = User.query.filter_by(
            social_id=user_info['id'],
            social_provider='facebook'
        ).first()
        
        if not user:
            # Create new user with specified user type
            user = User(
                username=user_info.get('email', '').split('@')[0] or f"fb_{user_info['id']}",
                email=user_info.get('email'),
                social_id=user_info['id'],
                social_provider='facebook',
                phone_number='pending',
                user_type=user_type
            )
            db.session.add(user)
            db.session.commit()
    
    if user:
        login_user(user)
        if user.user_type == 'business':
            return redirect(url_for('business_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
            
    return redirect(url_for('index'))

@app.route('/login/google')
def google_login():
    # Store the user type from the referrer URL
    referrer = request.referrer
    user_type = 'customer'  # default
    if referrer and 'business' in referrer:
        user_type = 'business'
    session['intended_user_type'] = user_type

    if not google.authorized:
        return redirect(url_for('google.login'))
        
    resp = google.get('/oauth2/v1/userinfo')
    assert resp.ok, resp.text
    user_info = resp.json()
    
    user = User.query.filter_by(social_id=user_info['id'], 
                              social_provider='google').first()
    if not user:
        user = User(
            username=user_info['email'].split('@')[0],
            email=user_info['email'],
            social_id=user_info['id'],
            social_provider='google',
            phone_number='pending',
            user_type=session.get('intended_user_type', 'customer')
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    if user.user_type == 'business':
        return redirect(url_for('business_dashboard'))
    return redirect(url_for('customer_dashboard'))

@app.route('/login/facebook')
def facebook_login():
    # Store the user type from the referrer URL
    referrer = request.referrer
    user_type = 'customer'  # default
    if referrer and 'business' in referrer:
        user_type = 'business'
    session['intended_user_type'] = user_type

    if not facebook.authorized:
        return redirect(url_for('facebook.login'))
        
    resp = facebook.get('/me?fields=id,email,name')
    assert resp.ok, resp.text
    user_info = resp.json()
    
    user = User.query.filter_by(social_id=user_info['id'], 
                              social_provider='facebook').first()
    if not user:
        user = User(
            username=user_info.get('email', '').split('@')[0] or f"fb_{user_info['id']}",
            email=user_info.get('email'),
            social_id=user_info['id'],
            social_provider='facebook',
            phone_number='pending',
            user_type=session.get('intended_user_type', 'customer')
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    if user.user_type == 'business':
        return redirect(url_for('business_dashboard'))
    return redirect(url_for('customer_dashboard'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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
# Update mail configuration in app.py
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='d.mirchev92@gmail.com',
    MAIL_PASSWORD='lcer ihib cgnn hhyw',
    MAIL_ASCII_ATTACHMENTS=False,  # Allow non-ASCII characters
    MAIL_DEFAULT_CHARSET='utf-8'   # Set UTF-8 as default charset
)






# Routes
@app.route('/')
def index():
    # If user is authenticated, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if current_user.user_type == 'business':
            return redirect(url_for('business_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
    # Otherwise show the index page
    return render_template('business_user/business_index.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    return redirect(url_for('business_login'))

@app.route('/business/login', methods=['GET', 'POST'])
def business_login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('business_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            if user.user_type == 'business':
                return redirect(url_for('business_dashboard'))
            return redirect(url_for('customer_dashboard'))
            
        flash('Invalid username or password')
        return redirect(url_for('business_login'))  # Stay on business login
    
    return render_template('Business_User/business_login.html')

@app.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    if current_user.is_authenticated:
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, user_type='customer').first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            activity = Activity(
                user_id=user.id,
                action='login',
                description='Customer logged in'
            )
            db.session.add(activity)
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('customer_dashboard')
            return redirect(next_page)
            
        flash('Invalid username or password')
        return redirect(url_for('customer_login'))
    
    return render_template('Customer_User/Customer_login.html')

@app.route('/customer/api/favorite/<int:specialist_id>', methods=['POST', 'DELETE'])
@login_required
def handle_favorite(specialist_id):
    if current_user.user_type != 'customer':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        if request.method == 'POST':
            # Check if already favorite
            existing = FavoriteSpecialist.query.filter_by(
                customer_id=current_user.id,
                specialist_id=specialist_id
            ).first()
            
            if not existing:
                favorite = FavoriteSpecialist(
                    customer_id=current_user.id,
                    specialist_id=specialist_id
                )
                db.session.add(favorite)
                db.session.commit()
            
            return jsonify({'message': 'Added to favorites', 'status': True})
            
        elif request.method == 'DELETE':
            FavoriteSpecialist.query.filter_by(
                customer_id=current_user.id,
                specialist_id=specialist_id
            ).delete()
            db.session.commit()
            return jsonify({'message': 'Removed from favorites', 'status': False})
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error handling favorite: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Your existing routes remain unchanged
def calculate_response_rate(specialist_id):
    # Implement response rate calculation logic here
    return 0  # Placeholder return

        
@app.route('/update-guest-phone', methods=['POST'])
@login_required
def update_guest_phone():
    if not current_user.is_guest:
        return jsonify({'error': 'Not a guest user'}), 403
        
    phone_number = request.form.get('phone_number')
    if phone_number:
        current_user.phone_number = phone_number
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Phone number required'}), 400

@app.route('/api/specialist/<int:specialist_id>/profile')
@login_required
def get_specialist_profile(specialist_id):
    try:
        specialist = User.query.filter_by(
            id=specialist_id,
            user_type='business'
        ).first_or_404()
        
        # Get gallery items
        gallery_items = GalleryItem.query.filter_by(
            user_id=specialist_id
        ).order_by(GalleryItem.created_at.desc()).all()
        
        # Format gallery items with correct paths
        gallery_data = [{
            'image_path': item.image_path,  # Just the filename, path is constructed in frontend
            'description': item.description
        } for item in gallery_items]
        
        # Format profile picture URL
        profile_picture = specialist.profile_picture if specialist.profile_picture else None
        
        return jsonify({
            'id': specialist.id,
            'username': specialist.username,
            'profile_picture': profile_picture,  # Just the filename
            'specialization': specialist.specialization or 'Not specified',
            'location': specialist.location or 'Location not specified',
            'working_hours': f"{specialist.working_hours_start} - {specialist.working_hours_end}",
            'working_days': specialist.working_days,
            'years_experience': specialist.years_experience or 0,
            'rating': specialist.rating or 0,
            'reviews_count': specialist.reviews_count or 0,
            'bio': specialist.bio,
            'gallery_items': gallery_data
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching specialist profile: {str(e)}")
        return jsonify({'error': 'Error fetching profile data'}), 500

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        session.clear()
    return redirect(url_for('index'))

def is_saved_customer(phone_number):
    return Customer.query.filter_by(phone_number=phone_number).first() is not None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']
        user_type = request.form.get('user_type', 'business')

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('Business_User/business_register.html' if user_type == 'business' 
                                else 'Customer_User/Customer_register.html')

        try:
            # Create logs directory if it doesn't exist
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            # Validate password
            is_valid, msg = is_password_valid(password)
            if not is_valid:
                flash(msg)
                return render_template('Business_User/business_register.html' if user_type == 'business' 
                                    else 'Customer_User/Customer_register.html')

            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username, 
                password=hashed_password, 
                phone_number=phone_number, 
                user_type=user_type
            )
            
            db.session.add(new_user)
            db.session.flush()  # Get the user ID without committing

            # If it's a business user, set up their Basic tier subscription
            if user_type == 'business':
                category = request.form.get('category')
                if not category:
                    flash('Please select a category')
                    return render_template('Business_User/business_register.html')

                # Get the Basic tier
                basic_tier = BusinessTier.query.filter_by(name='Basic').first()
                if not basic_tier:
                    flash('Error setting up business profile')
                    return render_template('Business_User/business_register.html')

                # Create business profile with Basic tier
                business_profile = BusinessProfile(
                    user_id=new_user.id,
                    tier_id=basic_tier.id,
                    points_balance=basic_tier.initial_points,
                    selected_category=category
                )
                db.session.add(business_profile)

                # Record the initial points transaction
                points_transaction = PointsTransaction(
                    user_id=new_user.id,
                    amount=basic_tier.initial_points,
                    transaction_type='subscription',
                    description='Initial points from Basic tier subscription'
                )
                db.session.add(points_transaction)

            db.session.commit()
            
            # Update users log file
            update_users_log()
            
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error in registration: {str(e)}")
            flash('Registration failed')
            
    # GET request - show appropriate registration form
    user_type = request.args.get('user_type', 'business')
    return render_template('Business_User/business_register.html' if user_type == 'business' 
                         else 'Customer_User/Customer_register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        app.logger.info(f"User type: {current_user.user_type}")

        if current_user.user_type == 'business':
            return redirect(url_for('business_dashboard'))
        
        elif current_user.user_type == 'customer':
            app.logger.info("Rendering customer dashboard")
            return redirect(url_for('customer_dashboard'))
        else:
            app.logger.error(f"Invalid user type: {current_user.user_type}")
            return redirect(url_for('login'))

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        raise  # This will show the full error in development

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
        print("Found user:", user.username)
        print("Found user type:", user.user_type)
        return jsonify({
            'id': user.id,
            'username': user.username,
            'phone_number': user.phone_number
        })
    else:
        print("No user found")
        return jsonify({'error': 'User not found'}), 404
    
    
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
            return jsonify({'error': 'User not found'})
        
        # Update all missed calls
        calls = MissedCall.query.filter_by(user_id='damirche').all()
        for call in calls:
            call.user_id = user.id
        
        db.session.commit()
        return jsonify({'message': f'Updated {len(calls)} calls'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

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
    return render_template('business_user/business_about.html')

@app.route('/customer/register')
def customer_register():
    return redirect(url_for('register', user_type='customer'))

@app.route('/customers')
@login_required
def customers():
    print("Accessing customers route")  # Debug print
    try:
        customers = Customer.query.filter_by(user_id=current_user.id).order_by(Customer.last_updated.desc()).all()
        print(f"Found {len(customers)} customers")  # Debug print
        return render_template('business_user/business_customerinfo.html', customers=customers)
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
            # Track old values for logging
            old_settings = {
                'sms_enabled': current_user.sms_enabled,
                'template': current_user.sms_template,
                'working_hours': f"{current_user.working_hours_start}-{current_user.working_hours_end}",
                'vacation_mode': current_user.vacation_mode
            }
            
            # Update settings
            current_user.sms_enabled = 'sms_enabled' in request.form
            current_user.sms_template = request.form.get('sms_template', '')
            current_user.working_hours_start = request.form.get('working_hours_start', '09:00')
            current_user.working_hours_end = request.form.get('working_hours_end', '18:00')
            current_user.working_days = ','.join(request.form.getlist('working_days'))
            current_user.off_hours_message = request.form.get('off_hours_message', '')
            current_user.vacation_mode = 'vacation_mode' in request.form
            current_user.vacation_message = request.form.get('vacation_message', '')
            
            # Log the settings change
            log_user_activity(
                current_user.id,
                'settings_change',
                f'Changed settings from {old_settings} to new values'
            )
            
            db.session.commit()
            flash('Settings saved successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving settings: {str(e)}', 'error')
            
        return redirect(url_for('sms_settings'))
    
    return render_template('business_user/business_sms-settings.html')

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('business_user/business_admin.html', users=users)

@app.route('/api/admin/update-user', methods=['POST'])
@login_required
@admin_required
def admin_update_user():
    try:
        data = request.json
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        if data['setting'] == 'sms_enabled':
            user.sms_enabled = data['value']
        elif data['setting'] == 'is_admin':
            user.is_admin = data['value']
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password():
    try:
        data = request.json
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Generate a random password
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256:600000')
        
        db.session.commit()
        return jsonify({'success': True, 'new_password': new_password})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/delete-user', methods=['POST'])
@login_required
@admin_required
def admin_delete_user():
    try:
        data = request.json
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        db.session.delete(user)
        db.session.commit()
        
        # Update users log file
        update_users_log()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/statistics', methods=['GET'])
@login_required
@admin_required
def get_statistics():
    try:
        # Update to use timezone-aware datetime
        five_minutes_ago = datetime.now(UTC) - timedelta(minutes=5)
        
        stats = {
            'total_users': User.query.count(),
            'users_by_status': {
                'active': User.query.filter(User.last_seen > five_minutes_ago).count(),
                'inactive': User.query.filter(
                    or_(User.last_seen <= five_minutes_ago, User.last_seen.is_(None))
                ).count()
            },
            'total_calls': MissedCall.query.count(),
            'total_sms_sent': MissedCall.query.filter(MissedCall.message_sent.isnot(None)).count()
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/user-activity/', methods=['GET'])
@app.route('/api/admin/user-activity/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user_activity(user_id=None):
    try:
        # Base query
        query = db.session.query(
            UserActivity, 
            User.username
        ).join(
            User, 
            UserActivity.user_id == User.id
        )
        
        # If user_id is provided, filter for that user
        if user_id is not None:
            query = query.filter(UserActivity.user_id == user_id)
            
        # Get the activities, ordered by most recent first
        activities = query.order_by(
            UserActivity.timestamp.desc()
        ).limit(100).all()
        
        # Format the response
        activity_list = [{
            'username': username,
            'action': activity.action,
            'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'details': activity.details
        } for activity, username in activities]
        
        return jsonify(activity_list)
        
    except Exception as e:
        app.logger.error(f"Error getting user activity: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/templates', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_templates():
    if request.method == 'POST':
        data = request.json
        user = User.query.get(data['user_id'])
        if user:
            user.sms_template = data['template']
            user.off_hours_message = data['off_hours_message']
            user.vacation_message = data['vacation_message']
            db.session.commit()
            return jsonify({'success': True})
    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/admin/quotas', methods=['POST'])
@login_required
@admin_required
def update_quota():
    data = request.json
    quota = UserQuota.query.filter_by(user_id=data['user_id']).first()
    if quota:
        quota.monthly_sms_limit = data['new_limit']
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'User quota not found'}), 404

@app.route('/api/admin/system-health')
@login_required
@admin_required
def system_health():
    try:
        health_data = {
            'database_size': get_db_size(),
            'sms_service_status': check_sinch_status(),
            'recent_errors': get_recent_errors(),
            'system_load': {
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent
            }
        }
        return jsonify(health_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_db_size():
    try:
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        return os.path.getsize(db_path) / (1024 * 1024)  # Size in MB
    except:
        return 0

def check_sinch_status():
    try:
        response = requests.get(f"https://us.sms.api.sinch.com/xms/v1/{app.config['SINCH_SERVICE_PLAN_ID']}/batches", 
                              headers={"Authorization": f"Bearer {app.config['SINCH_API_TOKEN']}"})
        return response.status_code == 200
    except:
        return False

def get_recent_errors():
    # This would typically connect to your logging system
    # For now, return the last 5 errors from the application log
    try:
        with open('app.log', 'r') as f:
            errors = [line for line in f if 'ERROR' in line]
            return errors[-5:]
    except:
        return []

def setup_logging(app):
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    try:
        # Set up file handler with a less restrictive lock
        file_handler = RotatingFileHandler(
            'logs/misscall.log',
            maxBytes=10240,
            backupCount=10,
            delay=True
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        
        # Remove any existing handlers to avoid duplicates
        for handler in app.logger.handlers[:]:
            app.logger.removeHandler(handler)
            
        app.logger.addHandler(file_handler)

        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        app.logger.addHandler(console_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('MissCall startup')
        
    except Exception as e:
        print(f"Error setting up logging: {str(e)}")
        # Fallback to basic logging if file logging fails
        logging.basicConfig(level=logging.INFO)

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    app.logger.error(f'Unhandled Exception: {str(e)}')
    return render_template('errors/500.html'), 500

@app.before_request
def before_request():
    if current_user.is_authenticated:
        try:
            # Create timezone-aware current time in UTC
            current_time = datetime.now(UTC)
            
            # If last_seen is None, just update it and return
            if current_user.last_seen is None:
                current_user.last_seen = current_time
                db.session.commit()
                return
            
            # Ensure last_seen is timezone-aware
            if current_user.last_seen.tzinfo is None:
                # Convert naive datetime to UTC
                current_user.last_seen = pytz.UTC.localize(current_user.last_seen)
            
            # Now both datetimes are timezone-aware, we can safely subtract
            time_difference = (current_time - current_user.last_seen).total_seconds()
            
            # Update last_seen
            current_user.last_seen = current_time
            db.session.commit()
            
            # Check for timeout (5 minutes = 300 seconds)
            if time_difference > 300:
                logout_user()
                return redirect(url_for('login'))
                
        except Exception as e:
            app.logger.error(f"Error in before_request: {str(e)}")
            # Prevent the error from breaking the application
            pass

def log_user_activity(user_id, action, details=None):
    try:
        activity = UserActivity(
            user_id=user_id,
            action=action,
            details=details
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error logging user activity: {str(e)}")
        db.session.rollback()


@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    if current_user.user_type != 'customer':
        return redirect(url_for('login'))
    
    try:
        active_cases = 0  # Replace with actual query when Cases model exists
        completed_cases = 0
        recent_activities = []
        total_specialists = User.query.filter_by(user_type='business').count()

        return render_template('Customer_User/Customer_dashboard.html',
                             active_cases=active_cases,
                             completed_cases=completed_cases,
                             total_specialists=total_specialists,
                             recent_activities=recent_activities)
    except Exception as e:
        app.logger.error(f"Customer dashboard error: {str(e)}")
        return render_template('errors/500.html'), 500



@app.route('/customer/browse_specialist')
@login_required
def customer_browse_specialist():
    # Get favorites for current user
    favorite_ids = [f.specialist_id for f in FavoriteSpecialist.query.filter_by(customer_id=current_user.id).all()]
    
    # Get all specialists
    specialists = User.query.filter_by(user_type='business').all()
    
    # Sort specialists: favorites first, then others
    sorted_specialists = sorted(specialists, key=lambda s: (s.id not in favorite_ids))
    
    formatted_specialists = []
    for specialist in sorted_specialists:
        # Debug profile picture path
        app.logger.debug(f"Processing specialist {specialist.username} with profile picture: {specialist.profile_picture}")
        
        # Handle profile picture path
        profile_pic_url = None
        if specialist.profile_picture:
            # Ensure the path is relative to static/uploads
            if not specialist.profile_picture.startswith('uploads/'):
                profile_pic_url = f"uploads/{specialist.profile_picture}"
            else:
                profile_pic_url = specialist.profile_picture
                
        specialist_data = {
            'id': specialist.id,
            'username': specialist.username,
            'profile_picture': profile_pic_url,
            'specialization': specialist.specialization or 'Not specified',
            'location': specialist.location or 'Location not specified',
            'working_hours': f"{specialist.working_hours_start} - {specialist.working_hours_end}",
            'is_online': specialist.is_online,
            'rating': specialist.rating or 0,
            'reviews_count': specialist.reviews_count or 0,
            'completed_jobs': Case.query.filter_by(specialist_id=specialist.id, status='completed').count(),
            'response_rate': calculate_response_rate(specialist.id),
            'is_favorite': specialist.id in favorite_ids  # Add favorite status
        }
        formatted_specialists.append(specialist_data)

    return render_template('Customer_User/Customer_browse_specialist.html',
                         specialists=formatted_specialists)

@app.route('/customer/my_cases')
@login_required
def customer_my_cases():
    # Your existing code remains unchanged
    if current_user.user_type != 'customer':
        return redirect(url_for('login'))
    
    try:
        cases = Case.query.filter_by(customer_id=current_user.id)\
                         .order_by(Case.created_at.desc())\
                         .all()
        
        app.logger.debug(f"Found {len(cases)} cases for user {current_user.id}")
        
        return render_template('Customer_User/Customer_my_cases.html', cases=cases)
    except Exception as e:
        app.logger.error(f"Error fetching cases: {str(e)}")
        flash('Error loading cases', 'error')
        return render_template('Customer_User/Customer_my_cases.html', cases=[])


@app.route('/customer/create-case', methods=['GET', 'POST'])
@login_required
def customer_create_case():
    if current_user.user_type != 'customer':
        return redirect(url_for('login'))

    form = CreateCaseForm()
    
    # Get all specialists and their specializations
    specialists = User.query.filter_by(user_type='business').all()
    specializations = db.session.query(User.specialization)\
        .filter(User.user_type == 'business')\
        .filter(User.specialization.isnot(None))\
        .distinct()\
        .all()
    
    # Update form choices
    form.specialist.choices = [('', 'Select Specialist')] + [
        (str(s.id), f"{s.username} - {s.specialization or 'No specialization'}")
        for s in specialists
    ]
    form.specialization.choices = [('', 'Select Specialization')] + [
        (s[0], s[0]) for s in specializations if s[0]
    ]

    # Handle specialist from URL parameters
    specialist_id = request.args.get('specialist_id')
    specialist = None
    if specialist_id:
        specialist = User.query.filter_by(
            id=specialist_id,
            user_type='business'
        ).first()
        if specialist:
            form.specialist.data = str(specialist.id)
            form.specialization.data = specialist.specialization

    if form.validate_on_submit():
        try:
            # Print debug info
            print(f"Specialist data: {form.specialist.data}")
            print(f"Creating case with status: {'requested' if form.specialist.data else 'pending'}")

            # Check if a specialist was selected and validate their tier limit
            if form.specialist.data:
                specialist = User.query.get(form.specialist.data)
                if specialist and specialist.business_profile:
                    max_budget = specialist.business_profile.tier.max_budget_limit
                    if form.budget.data > max_budget:
                        flash(f'Selected specialist cannot accept cases over {max_budget} BGN due to their tier limit.', 'error')
                        return render_template('Customer_User/Customer_create_case.html', 
                                            form=form, 
                                            specialist=specialist)

            new_case = Case(
                customer_id=current_user.id,
                specialist_id=None,  # Must be None initially
                requested_specialists=form.specialist.data if form.specialist.data else None,
                title=form.title.data,
                description=form.description.data,
                category=form.specialization.data,
                status='requested' if form.specialist.data else 'pending',
                budget=form.budget.data,
                timeline=form.timeline.data,
                location=form.location.data,
                preferred_date=form.preferred_date.data if form.timeline.data == 'planned' else None
            )

            db.session.add(new_case)
            db.session.commit()

            flash('Case created successfully!', 'success')
            return redirect(url_for('customer_my_cases'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating case: {str(e)}")
            flash(f'Error creating case: {str(e)}', 'error')
            return render_template('Customer_User/Customer_create_case.html', 
                                form=form, 
                                specialist=specialist)

    return render_template('Customer_User/Customer_create_case.html', 
                         form=form, 
                         specialist=specialist)

@app.route('/customer/api/case/<int:case_id>/close', methods=['POST'])
@login_required
def close_case(case_id):
    try:
        case = Case.query.get_or_404(case_id)
        
        # Verify the case belongs to current user
        if case.customer_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Update case status
        case.status = 'completed'
        case.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Case closed successfully'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error closing case: {str(e)}")
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/business/dashboard')
@login_required
def business_dashboard():
    if current_user.user_type != 'business':
        flash('Access denied. Business access only.')
        return redirect(url_for('login'))
        
    try:
        # Get business profile and tier
        business_profile = BusinessProfile.query.filter_by(user_id=current_user.id).first()
        if not business_profile:
            flash('Business profile not found.', 'error')
            return redirect(url_for('login'))

        # Get assigned and completed cases
        assigned_and_completed = Case.query.filter(
            Case.specialist_id == current_user.id,
            Case.status.in_(['assigned', 'completed', 'declined'])  # Only get relevant statuses
        ).order_by(Case.created_at.desc()).all()
        
        # Calculate total budget from completed cases only
        total_budget = sum(case.budget for case in assigned_and_completed if case.status == 'completed' and case.budget is not None)
        
        # Get pending cases that match the business user's criteria
        pending_cases_query = Case.query.filter(
            Case.status == 'pending',
            Case.specialist_id.is_(None),  # Not yet assigned
            Case.budget <= business_profile.tier.max_budget_limit  # Within budget limit
        )
        
        # Make category filter optional
        if business_profile.selected_category:
            pending_cases_query = pending_cases_query.filter(
                db.or_(
                    Case.category == business_profile.selected_category,
                    Case.category == '',
                    Case.category.is_(None)
                )
            )
            
        # Make location filter optional
        if current_user.location:
            pending_cases_query = pending_cases_query.filter(
                db.or_(
                    Case.location == current_user.location,
                    Case.location.is_(None)
                )
            )
            
        pending_cases = pending_cases_query.order_by(Case.created_at.desc()).all()

        # Organize cases by status
        assigned_cases = [case for case in assigned_and_completed if case.status == 'assigned']
        completed_cases = [case for case in assigned_and_completed if case.status == 'completed']
        declined_cases = [case for case in assigned_and_completed if case.status == 'declined']
        
        # Calculate completion rate
        try:
            completion_rate = (float(len(completed_cases)) / float(len(assigned_and_completed)) * 100.0) if len(assigned_and_completed) > 0 else 0.0
            completion_rate = round(float(completion_rate), 1)
        except (TypeError, ZeroDivisionError):
            completion_rate = 0.0
        
        return render_template(
            'Business_User/business_dashboard.html',
            assigned_cases=assigned_cases,
            pending_cases=pending_cases,
            declined_cases=declined_cases,
            completed_cases=len(completed_cases),  # Now passing just the count
            total_cases=len(assigned_and_completed),
            active_cases=len(assigned_cases),
            available_cases=len(pending_cases),
            completion_rate=completion_rate,
            total_budget=total_budget  # Add total budget to template context
        )
    except Exception as e:
        app.logger.error(f"Error in business dashboard: {str(e)}")
        flash('Error loading dashboard', 'error')
        return render_template(
            'Business_User/business_dashboard.html',
            assigned_cases=[],
            pending_cases=[],
            declined_cases=[],
            completed_cases=0,
            total_cases=0,
            active_cases=0,
            available_cases=0,
            completion_rate=0.0,
            total_budget=0.0  # Add default total budget
        )

@app.route('/business/cases')
@login_required
def business_cases():
    if current_user.user_type != 'business':
        flash('Access denied. Business access only.')
        return redirect(url_for('login'))
        
    try:
        # Get business profile and tier
        business_profile = BusinessProfile.query.filter_by(user_id=current_user.id).first()
        if not business_profile:
            flash('Business profile not found.', 'error')
            return redirect(url_for('login'))
        
        # Get assigned and completed cases
        assigned_and_completed = Case.query.filter(
            Case.specialist_id == current_user.id,
            Case.status.in_(['assigned', 'completed', 'declined'])  # Only get relevant statuses
        ).order_by(Case.created_at.desc()).all()
        
        # Get pending cases that match the business user's criteria
        pending_cases_query = Case.query.filter(
            Case.status == 'pending',
            Case.specialist_id.is_(None),  # Not yet assigned
            Case.budget <= business_profile.tier.max_budget_limit  # Within budget limit
        )
        
        # Make category filter optional
        if business_profile.selected_category:
            pending_cases_query = pending_cases_query.filter(
                db.or_(
                    Case.category == business_profile.selected_category,
                    Case.category == '',
                    Case.category.is_(None)
                )
            )
            
        # Make location filter optional
        if current_user.location:
            pending_cases_query = pending_cases_query.filter(
                db.or_(
                    Case.location == current_user.location,
                    Case.location.is_(None)
                )
            )
            
        pending_cases = pending_cases_query.order_by(Case.created_at.desc()).all()

        # Organize cases by status
        assigned_cases = [case for case in assigned_and_completed if case.status == 'assigned']
        declined_cases = [case for case in assigned_and_completed if case.status == 'declined']
        completed_cases = [case for case in assigned_and_completed if case.status == 'completed']
        
        return render_template('Business_User/business_cases.html',
                           assigned_cases=assigned_cases,
                           pending_cases=pending_cases,
                           declined_cases=declined_cases,
                           completed_cases=completed_cases)

    except Exception as e:
        app.logger.error(f"Error in business cases: {str(e)}")
        flash('An error occurred while loading cases.', 'error')
        return render_template('Business_User/business_cases.html',
                           assigned_cases=[],
                           pending_cases=[],
                           declined_cases=[],
                           completed_cases=[],
                           total_cases=0,
                           active_cases=0,
                           available_cases=0,
                           completion_rate=0.0)

@app.route('/business/settings', methods=['GET', 'POST'])
@login_required
def business_settings():
    if current_user.user_type != 'business':
        return redirect(url_for('login'))
        
    try:
        # Ensure business profile exists
        ensure_business_profile(current_user)
        
        if request.method == 'POST':
            current_user.name = request.form.get('name')
            current_user.specialization = request.form.get('specialization')
            current_user.location = request.form.get('location')
            current_user.working_hours_start = request.form.get('working_hours_start')
            current_user.working_hours_end = request.form.get('working_hours_end')
            current_user.working_days = ','.join(request.form.getlist('working_days'))
            current_user.phone_number = request.form.get('phone_number')
            current_user.bio = request.form.get('bio')
            current_user.years_experience = request.form.get('years_experience')

            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    profile_pic_path = save_image(file, 'profile_pics')
                    if profile_pic_path:
                        if current_user.profile_picture:
                            old_pic_path = os.path.join(app.static_folder, 'uploads', current_user.profile_picture)
                            if os.path.exists(old_pic_path):
                                os.remove(old_pic_path)
                        current_user.profile_picture = profile_pic_path

            # Handle gallery uploads
            if 'gallery_images[]' in request.files:
                gallery_files = request.files.getlist('gallery_images[]')
                gallery_descriptions = request.form.getlist('gallery_descriptions[]')
                
                # Check user's tier and current gallery count
                is_basic_tier = current_user.business_profile.tier.name == 'Basic'
                current_gallery_count = GalleryItem.query.filter_by(user_id=current_user.id).count()
                
                # Calculate how many more images can be uploaded
                remaining_slots = 5 - current_gallery_count if is_basic_tier else float('inf')
                
                if is_basic_tier and len(gallery_files) > remaining_slots:
                    flash(f'You have reached the image upload limit for Basic tier accounts (maximum 5 images). Available uploads remaining: {remaining_slots}.', 'warning')
                    gallery_files = gallery_files[:remaining_slots]
                    gallery_descriptions = gallery_descriptions[:remaining_slots]
                
                for file, description in zip(gallery_files, gallery_descriptions):
                    if file and file.filename:
                        image_path = save_image(file, 'gallery')
                        if image_path:
                            gallery_item = GalleryItem(
                                user_id=current_user.id,
                                image_path=image_path,
                                description=description
                            )
                            db.session.add(gallery_item)

            db.session.commit()
            if not (is_basic_tier and len(gallery_files) > remaining_slots):
                flash('Settings updated successfully!', 'success')
            return redirect(url_for('business_settings'))
            
    except Exception as e:
        db.session.rollback()
        print(f"Error updating settings: {str(e)}")
        flash(f'Error updating settings: {str(e)}', 'error')
        return redirect(url_for('business_settings'))
        
    # Get user's gallery items for display
    gallery_items = GalleryItem.query.filter_by(user_id=current_user.id).order_by(GalleryItem.created_at.desc()).all()
    return render_template('Business_User/business_settings.html', gallery_items=gallery_items)

def ensure_business_profile(user):
    """Ensure user has a business profile with proper tier setup"""
    if user.user_type == 'business' and not user.business_profile:
        # Get or create Basic tier
        basic_tier = BusinessTier.query.filter_by(name='Basic').first()
        if not basic_tier:
            basic_tier = BusinessTier(
                name='Basic',
                price=150.0,
                initial_points=200,
                max_categories=1,
                max_portfolio_images=5,
                max_budget_limit=700.0,
                has_sms=False
            )
            db.session.add(basic_tier)
            db.session.flush()

        # Create business profile
        business_profile = BusinessProfile(
            user_id=user.id,
            tier_id=basic_tier.id,
            points_balance=basic_tier.initial_points,
            selected_category=None  # User can set this later
        )
        db.session.add(business_profile)
        db.session.commit()

@app.route('/customer/api/review', methods=['POST'])
@login_required
def submit_review():
    if current_user.user_type != 'customer':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        data = request.json
        specialist_id = data.get('specialist_id')
        rating = data.get('rating')
        comment = data.get('comment')
        
        # Validate input
        if not all([specialist_id, rating, comment]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Convert rating to integer
        try:
            rating = int(rating)
            if not 1 <= rating <= 5:
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Invalid rating value'}), 400
            
        # Check if specialist exists
        specialist = User.query.filter_by(id=specialist_id, user_type='business').first()
        if not specialist:
            return jsonify({'error': 'Specialist not found'}), 404

        # Check if user already has a review for this specialist
        existing_review = Review.query.filter_by(
            customer_id=current_user.id,
            specialist_id=specialist_id
        ).first()

        if existing_review:
            # Update existing review
            existing_review.rating = rating
            existing_review.comment = comment
            
            # Recalculate specialist's average rating
            all_reviews = Review.query.filter_by(specialist_id=specialist_id).all()
            if all_reviews:
                total_rating = sum(review.rating for review in all_reviews)
                specialist.rating = round(total_rating / len(all_reviews), 1)
            else:
                specialist.rating = 0
                specialist.reviews_count = 0
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Review updated successfully'
            })
        else:
            # Create new review
            review = Review(
                customer_id=current_user.id,
                specialist_id=specialist_id,
                rating=rating,
                comment=comment
            )
            
            db.session.add(review)
            
            # Recalculate specialist's average rating including the new review
            all_reviews = Review.query.filter_by(specialist_id=specialist_id).all()
            total_rating = sum(review.rating for review in all_reviews) + rating
            specialist.rating = round(total_rating / (len(all_reviews) + 1), 1)
            specialist.reviews_count = len(all_reviews) + 1
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Review submitted successfully'
            })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting review: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add this new route right after the submit_review route
@app.route('/customer/api/review/<int:specialist_id>', methods=['GET'])
@login_required
def get_user_review(specialist_id):
    try:
        review = Review.query.filter_by(
            customer_id=current_user.id,
            specialist_id=specialist_id
        ).first()
        
        if review:
            return jsonify({
                'exists': True,
                'rating': review.rating,
                'comment': review.comment
            })
        return jsonify({'exists': False})
        
    except Exception as e:
        app.logger.error(f"Error fetching user review: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/customer/api/reviews/<int:specialist_id>', methods=['GET'])
def get_specialist_reviews(specialist_id):
    try:
        reviews = Review.query.filter_by(specialist_id=specialist_id)\
            .order_by(Review.created_at.desc())\
            .all()
            
        return jsonify([{
            'id': r.id,
            'rating': r.rating,
            'comment': r.comment,
            'customer_name': r.customer.username,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for r in reviews])
        
    except Exception as e:
        app.logger.error(f"Error fetching reviews: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/business/gallery/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_gallery_item(item_id):
    try:
        gallery_item = GalleryItem.query.get_or_404(item_id)
        
        # Verify ownership
        if gallery_item.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Delete the image file
        file_path = os.path.join(current_app.root_path, 'static', gallery_item.image_path)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        db.session.delete(gallery_item)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/business/cases/<int:case_id>/accept', methods=['POST'])
@login_required
def accept_case(case_id):
    if current_user.user_type != 'business':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        case = Case.query.get_or_404(case_id)
        
        # Check if case is already assigned to another specialist
        if case.specialist_id is not None and case.specialist_id != current_user.id:
            return jsonify({'success': False, 'message': 'Case already assigned to another specialist'}), 400
            
        # Check if case is already accepted (but allow accepting declined cases)
        if case.status == 'assigned':
            return jsonify({'success': False, 'message': 'Case is already accepted'}), 400

        # Calculate required points
        required_points = int(case.budget / 10) + 1  # 1 point per 10 BGN + 1 point for acceptance

        # Check if user has sufficient points
        if not current_user.business_profile or current_user.business_profile.points_balance < required_points:
            return jsonify({'success': False, 'message': 'Insufficient points'}), 400

        # Check if case budget exceeds user's tier limit
        if case.budget > current_user.business_profile.tier.max_budget_limit:
            return jsonify({'success': False, 'message': 'Case budget exceeds your tier limit'}), 400

        # Check if case category matches user's selected category or is empty/null
        if (case.category and 
            current_user.business_profile.selected_category and 
            case.category != current_user.business_profile.selected_category):
            return jsonify({'success': False, 'message': 'Case category does not match your specialization'}), 400

        # Deduct points
        points_transaction = PointsTransaction(
            user_id=current_user.id,
            amount=-required_points,
            transaction_type='case_acceptance',
            case_id=case.id,
            description=f'Points deducted for accepting case: {case.title}'
        )
        current_user.business_profile.points_balance -= required_points

        # Update case
        case.specialist_id = current_user.id
        case.status = 'assigned'
        case.accepted_at = datetime.now(UTC)  # Set accepted_at timestamp
        
        # Add both transaction and case update to session
        db.session.add(points_transaction)
        db.session.commit()

        # Send notification to client
        notification = Notification(
            user_id=case.client_id,
            title='Case Accepted',
            message=f'Your case "{case.title}" has been accepted by a specialist.',
            type='case_accepted'
        )
        db.session.add(notification)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Case accepted successfully',
            'points_deducted': required_points,
            'new_balance': current_user.business_profile.points_balance
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error accepting case: {str(e)}")
        return jsonify({'success': False, 'message': 'Error accepting case'}), 500

@app.route('/business/cases/<int:case_id>/decline', methods=['POST'])
@login_required
def decline_case(case_id):
    if current_user.user_type != 'business':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
        
    try:
        case = Case.query.get_or_404(case_id)
        
        # Check if case can be declined
        if case.specialist_id is not None and case.specialist_id != current_user.id:
            return jsonify({'success': False, 'message': 'Case already assigned to another specialist'}), 400
            
        # Update case status
        case.status = 'declined'
        case.specialist_id = current_user.id
        case.declined_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Case declined successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error declining case: {str(e)}")
        return jsonify({'success': False, 'message': 'Error declining case'}), 500

@app.route('/business/cases/<int:case_id>')
@login_required
def view_case(case_id):
    if current_user.user_type != 'business':
        flash('Access denied. Business access only.')
        return redirect(url_for('login'))
        
    try:
        case = Case.query.get_or_404(case_id)
        
        # Check if user has access to this case
        if case.specialist_id != current_user.id and case.status != 'pending':
            flash('You do not have permission to view this case.', 'error')
            return redirect(url_for('business_cases'))
            
        return render_template('Business_User/view_case.html', case=case)
        
    except Exception as e:
        app.logger.error(f"Error viewing case: {str(e)}")
        flash('Error viewing case details', 'error')
        return redirect(url_for('business_cases'))

@app.route('/business/cases/<int:case_id>/complete', methods=['POST'])
@login_required
def complete_case(case_id):
    if current_user.user_type != 'business':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    try:
        case = Case.query.get_or_404(case_id)
        
        # Verify the case belongs to current user
        if case.specialist_id != current_user.id:
            return jsonify({'success': False, 'message': 'You can only complete cases assigned to you'}), 403
            
        # Update case status
        case.status = 'completed'
        case.completed_at = datetime.now(UTC)
        db.session.commit()
        
        # Send notification to client
        notification = Notification(
            user_id=case.customer_id,
            title='Case Completed',
            message=f'Your case "{case.title}" has been marked as completed by the specialist.',
            type='case_completed'
        )
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Case marked as completed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error completing case: {str(e)}")
        return jsonify({'success': False, 'message': 'Error completing case'}), 500

@app.route('/api/missed-call', methods=['POST'])
def handle_missed_call():
    try:
        data = request.json
        caller_number = data.get('caller_number')
        user_id = data.get('user_id')
        
        if not caller_number or not user_id:
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Create new missed call record
        missed_call = MissedCall(
            user_id=user_id,
            caller_number=caller_number,
            call_time=datetime.now(UTC),
            responded=False
        )
        
        db.session.add(missed_call)
        db.session.commit()
        
        # Get the user's SMS template
        user = User.query.get(user_id)
        if user and user.sms_template:
            # Send SMS using the user's template
            send_sinch_sms(caller_number, user.sms_template)
            
            # Update the message_sent field
            missed_call.message_sent = datetime.now(UTC)
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Missed call recorded successfully',
            'call_id': missed_call.id
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error handling missed call: {str(e)}")
        return jsonify({'error': str(e)}), 500

with app.app_context():
    ensure_upload_dirs()
    fix_image_paths()
    initialize_business_tiers()  # Initialize business tiers

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_upload_dirs()  # Add this line
    print("\n" + "=" * 70)
    print(Fore.GREEN + "Server is running on: http://127.0.0.1:5000" + Fore.RESET)
    print("=" * 70 + "\n")
    app.run(debug=True)