from app import app, db
from models import BusinessTier, initialize_business_tiers

with app.app_context():
    initialize_business_tiers()
