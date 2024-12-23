"""add_case_columns

Revision ID: b53d1ce28660
Revises: e1e357d284cf
Create Date: 2024-11-21 19:38:40.422083

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b53d1ce28660'
down_revision = 'e1e357d284cf'
branch_labels = None
depends_on = None


def upgrade():
    # Check existing columns first
    inspector = sa.inspect(op.get_bind())
    existing_columns = [col['name'] for col in inspector.get_columns('case')]
    
    with op.batch_alter_table('case', schema=None) as batch_op:
        # Add columns only if they don't exist
        if 'title' not in existing_columns:
            batch_op.add_column(sa.Column('title', sa.String(length=200), nullable=False, server_default=''))
        if 'budget' not in existing_columns:
            batch_op.add_column(sa.Column('budget', sa.Float(), nullable=True))
        if 'timeline' not in existing_columns:
            batch_op.add_column(sa.Column('timeline', sa.String(length=20), nullable=True))
        if 'preferred_date' not in existing_columns:
            batch_op.add_column(sa.Column('preferred_date', sa.DateTime(), nullable=True))
        if 'location' not in existing_columns:
            batch_op.add_column(sa.Column('location', sa.String(length=200), nullable=True))

def downgrade():
    with op.batch_alter_table('case', schema=None) as batch_op:
        for column in ['location', 'preferred_date', 'timeline', 'budget', 'title']:
            batch_op.drop_column(column)