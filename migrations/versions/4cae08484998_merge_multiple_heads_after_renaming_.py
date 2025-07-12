"""Merge multiple heads after renaming metadata

Revision ID: 4cae08484998
Revises: e168feb8ddba, performance_metrics_001
Create Date: 2025-06-13 17:30:42.678251

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4cae08484998'
down_revision = ('e168feb8ddba', 'performance_metrics_001')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
