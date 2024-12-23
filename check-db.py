from app import app, db
from models import BusinessTier, Case, User, BusinessProfile

with app.app_context():
    # Query all tiers
    tiers = BusinessTier.query.all()

    
    # Query all cases and their statuses
    print("\nCase Status Summary:")
    print("-" * 50)
    cases = Case.query.all()
    print("\nAll Cases:")
    for case in cases:
        specialist = User.query.get(case.specialist_id) if case.specialist_id else None
        customer = User.query.get(case.customer_id)
        print(f"ID: {case.id}")
        print(f"Title: {case.title}")
        print(f"Status: {case.status}")
        print(f"Budget: {case.budget} BGN")
        print(f"Category: {case.category}")
        print(f"Customer: {customer.username if customer else 'Unknown'}")
        print(f"Specialist: {specialist.username if specialist else 'Unassigned'}")
        if specialist:
            business_profile = BusinessProfile.query.filter_by(user_id=specialist.id).first()
            if business_profile:
                print(f"Specialist Tier: {business_profile.tier.name}")
                print(f"Tier Budget Limit: {business_profile.tier.max_budget_limit} BGN")
        print("-" * 30)