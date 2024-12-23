from flask_login import UserMixin
from datetime import datetime, UTC
from sqlalchemy import inspect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, FloatField, DateField
from wtforms.validators import DataRequired, Optional

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=True)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    social_id = db.Column(db.String(64), unique=True, nullable=True)
    social_provider = db.Column(db.String(20), nullable=True)
    is_guest = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='customer')  # 'business' or 'customer'
    is_admin = db.Column(db.Boolean, default=False)
    missed_calls = db.relationship('MissedCall', backref='user', lazy=True)
    sms_enabled = db.Column(db.Boolean, default=True)
    sms_template = db.Column(db.Text, default='Здравейте, пропуснах обаждането ви. Ще се свъжа с вас при първа възможност.')
    working_hours_start = db.Column(db.String(5), default='09:00')
    working_hours_end = db.Column(db.String(5), default='18:00')
    working_days = db.Column(db.String(100), default='Monday,Tuesday,Wednesday,Thursday,Friday')
    name = db.Column(db.String(100))
    profile_picture = db.Column(db.String(255))  # Store the file path
    bio = db.Column(db.Text)                     # Professional bio/description
    years_experience = db.Column(db.Integer)     # Years of professional experience
    rating = db.Column(db.Float, default=0.0)    # Average rating (existing)
    reviews_count = db.Column(db.Integer, default=0)  # Number of reviews (existing)
    
    # Relationship with gallery items
    gallery_items = db.relationship('GalleryItem', backref='user', lazy=True, cascade='all, delete-orphan')

    # Business profile relationship
    business_profile = db.relationship('BusinessProfile', backref='user', lazy=True, uselist=False)

    off_hours_message = db.Column(db.Text, default='Здравейте, в момента сме извън работно време. Ще се свържем с вас през работния ден.')
    vacation_mode = db.Column(db.Boolean, default=False)
    vacation_message = db.Column(db.Text, default='Здравейте, в момента съм в отпуск. Ще се свържа с вас след завръщането си.')
    last_login = db.Column(db.DateTime)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime(timezone=True))
    specialization = db.Column(db.String(100))
    location = db.Column(db.String(100))
    cases_as_specialist = db.relationship('Case', backref='specialist', lazy=True, foreign_keys='Case.specialist_id')
    cases_as_customer = db.relationship('Case', backref='customer', lazy=True, foreign_keys='Case.customer_id')

    def set_last_seen(self):
        """Helper method to set last_seen with proper timezone"""
        self.last_seen = datetime.now(UTC)

    def get_points_balance(self):
        """Get current points balance for business users"""
        if self.business_profile:
            return self.business_profile.points_balance
        return 0

    def can_accept_case(self, case):
        """Check if user can accept a case based on points and tier restrictions"""
        if not self.business_profile:
            return False, "Not a business user"
            
        required_points = (case.budget / 10) + 1  # 1 point per 10 BGN + 1 point for acceptance
        
        if self.business_profile.points_balance < required_points:
            return False, "Insufficient points"
            
        if case.budget > self.business_profile.tier.max_budget_limit:
            return False, "Case budget exceeds tier limit"
            
        if case.category != self.business_profile.selected_category:
            return False, "Case category doesn't match specialist category"
            
        return True, "Can accept case"

    def deduct_points(self, points, case_id, description):
        """Deduct points from user's balance"""
        if not self.business_profile or self.business_profile.points_balance < points:
            return False
            
        transaction = PointsTransaction(
            user_id=self.id,
            amount=-points,
            transaction_type='case_acceptance',
            case_id=case_id,
            description=description
        )
        
        self.business_profile.points_balance -= points
        db.session.add(transaction)
        db.session.commit()
        return True

class GalleryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)  # Path to the image file
    description = db.Column(db.Text)                        # Description of the work
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    order_index = db.Column(db.Integer, default=0)          # For custom ordering of gallery items

    def __repr__(self):
        return f'<GalleryItem {self.id} - {self.image_path}>'

class MissedCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    call_time = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_updated = db.Column(db.DateTime(timezone=True), 
                           default=lambda: datetime.now(UTC), 
                           onupdate=lambda: datetime.now(UTC))

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    details = db.Column(db.Text)
    
    # Add relationship to User model
    user = db.relationship('User', backref='activities')

class UserQuota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    monthly_sms_limit = db.Column(db.Integer, default=1000)
    sms_sent_this_month = db.Column(db.Integer, default=0)
    reset_date = db.Column(db.DateTime)

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    specialist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # possible values: 'pending', 'assigned', 'completed', 'declined'
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    accepted_at = db.Column(db.DateTime(timezone=True), nullable=True)  # Track when case was accepted
    category = db.Column(db.String(50))
    budget = db.Column(db.Float)
    timeline = db.Column(db.String(20))
    preferred_date = db.Column(db.DateTime(timezone=True), nullable=True)
    location = db.Column(db.String(200))
    requested_specialists = db.Column(db.String(500))

    def close_case(self):
        self.status = 'completed'
        self.updated_at = datetime.now(UTC)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))

class CreateCaseForm(FlaskForm):
    title = StringField('Case Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    specialist = SelectField('Specialist', choices=[], validators=[Optional()])
    specialization = SelectField('Specialization', choices=[], validators=[Optional()])
    budget = FloatField('Budget', validators=[DataRequired()])
    timeline = SelectField('Timeline', 
        choices=[
            ('urgent', 'Urgent (Within 24 hours)'),
            ('soon', 'Soon (2-3 days)'),
            ('flexible', 'Flexible (Within a week)'),
            ('planned', 'Planned (Specific date)')
        ],
        validators=[DataRequired()]
    )
    preferred_date = DateField('Preferred Date', validators=[Optional()])
    location = StringField('Location', validators=[DataRequired()])

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    specialist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    
    # Relationships
    customer = db.relationship('User', foreign_keys=[customer_id], backref='reviews_given')
    specialist = db.relationship('User', foreign_keys=[specialist_id], backref='reviews_received')

    def __repr__(self):
        return f'<Review {self.id} - {self.rating} stars>'

class FavoriteSpecialist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    specialist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))

    __table_args__ = (
        db.UniqueConstraint('customer_id', 'specialist_id', name='unique_favorite'),
    )

class BusinessTier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)  # e.g., 'Basic', 'Premium', 'Pro'
    price = db.Column(db.Float, nullable=False)  # Price in BGN
    initial_points = db.Column(db.Integer, nullable=False)  # Points given at subscription
    max_categories = db.Column(db.Integer, nullable=False)  # Number of categories allowed
    max_portfolio_images = db.Column(db.Integer, nullable=False)  # Maximum portfolio images
    max_budget_limit = db.Column(db.Float, nullable=False)  # Maximum case budget visible
    has_sms = db.Column(db.Boolean, default=False)  # Access to SMS feature

def initialize_business_tiers():
    """Initialize the basic business tier if it doesn't exist"""
    basic_tier = BusinessTier.query.filter_by(name='Basic').first()
    if not basic_tier:
        basic_tier = BusinessTier(
            name='Basic',
            price=150.0,  # 150 BGN
            initial_points=200,  # 200 points on subscription
            max_categories=1,  # Can select only one category
            max_portfolio_images=5,  # Up to 5 portfolio images
            max_budget_limit=700.0,  # Can see cases up to 700 BGN
            has_sms=False  # No SMS functionality
        )
        db.session.add(basic_tier)
        try:
            db.session.commit()
            print("Basic tier initialized successfully")
        except Exception as e:
            db.session.rollback()
            print(f"Error initializing basic tier: {str(e)}")
            raise

class PointsTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)  # Positive for additions, negative for deductions
    transaction_type = db.Column(db.String(50), nullable=False)  # 'subscription', 'case_acceptance', 'purchase'
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    description = db.Column(db.String(255))

class BusinessProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tier_id = db.Column(db.Integer, db.ForeignKey('business_tier.id'), nullable=False)
    points_balance = db.Column(db.Integer, default=0)
    selected_category = db.Column(db.String(100))
    subscription_start_date = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_points_notification = db.Column(db.DateTime(timezone=True))

    # Relationships
    tier = db.relationship('BusinessTier', backref='business_profiles')
    points_transactions = db.relationship('PointsTransaction', backref='business_profile', 
                                        primaryjoin="foreign(PointsTransaction.user_id) == BusinessProfile.user_id")

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50))  # e.g., 'case_update', 'points_alert', 'system'
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    link = db.Column(db.String(255))  # Optional link to related content