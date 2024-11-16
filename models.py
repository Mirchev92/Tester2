from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    
    # SMS Settings
    sms_enabled = db.Column(db.Boolean, default=True)
    sms_template = db.Column(db.Text, default='Здравейте, пропуснах обаждането ви. Ще се свържа с вас при първа възможност.')
    working_hours_start = db.Column(db.String(5), default='09:00')
    working_hours_end = db.Column(db.String(5), default='18:00')
    working_days = db.Column(db.String(100), default='Monday,Tuesday,Wednesday,Thursday,Friday')
    off_hours_message = db.Column(db.Text, default='Здравейте, в момента сме извън работно време. Ще се свържем с вас през работния ден.')
    vacation_mode = db.Column(db.Boolean, default=False)
    vacation_message = db.Column(db.Text, default='Здравейте, в момента съм в отпуск. Ще се свържа с вас след завръщането си.')
    
    # SMS Templates
    confirmation_template = db.Column(db.Text)
    followup_template = db.Column(db.Text)
    
    # Notification Settings
    notifications_enabled = db.Column(db.Boolean, default=False)
    notification_phone = db.Column(db.String(20))

class MissedCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    call_time = db.Column(db.DateTime, nullable=False)
    responded = db.Column(db.Boolean, default=False)
    message_sent = db.Column(db.String(160), nullable=True)