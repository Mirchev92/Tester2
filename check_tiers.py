from app import app, db
from models import BusinessTier

with app.app_context():
    basic_tier = BusinessTier.query.filter_by(name='Basic').first()
    if basic_tier:
        print(f"Basic Tier found:")
        print(f"Name: {basic_tier.name}")
        print(f"Price: {basic_tier.price} BGN")
        print(f"Initial Points: {basic_tier.initial_points}")
        print(f"Max Categories: {basic_tier.max_categories}")
        print(f"Max Portfolio Images: {basic_tier.max_portfolio_images}")
        print(f"Max Budget Limit: {basic_tier.max_budget_limit} BGN")
        print(f"Has SMS: {basic_tier.has_sms}")
    else:
        print("Basic Tier not found")
