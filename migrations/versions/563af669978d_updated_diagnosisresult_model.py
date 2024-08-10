from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '563af669978d'
down_revision = 'f82b532b7975'
branch_labels = None
depends_on = None

def upgrade():
    # Create the 'severity_levels' enum type
    severity_levels_enum = postgresql.ENUM('low', 'medium', 'high', name='severity_levels')
    severity_levels_enum.create(op.get_bind())

    # Modify the table to add the new columns and drop the old ones
    with op.batch_alter_table('diagnosis_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parasite_name', sa.String(length=50), nullable=False))
        batch_op.add_column(sa.Column('average_confidence', sa.Float(), nullable=False))
        batch_op.add_column(sa.Column('count', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('severity_level', sa.Enum('low', 'medium', 'high', name='severity_levels'), nullable=False))
        batch_op.drop_column('parasite_detected')
        batch_op.drop_column('wbc_count')

def downgrade():
    # Modify the table to revert the changes
    with op.batch_alter_table('diagnosis_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wbc_count', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('parasite_detected', sa.Boolean(), nullable=False))
        batch_op.drop_column('severity_level')
        batch_op.drop_column('count')
        batch_op.drop_column('average_confidence')
        batch_op.drop_column('parasite_name')

    # Drop the 'severity_levels' enum type
    severity_levels_enum = postgresql.ENUM('low', 'medium', 'high', name='severity_levels')
    severity_levels_enum.drop(op.get_bind())
