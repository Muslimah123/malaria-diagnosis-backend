"""Initial migration

Revision ID: 7c273af41151
Revises: 
Create Date: 2024-09-14 17:57:59.861124

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c273af41151'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('metadata',
    sa.Column('meta_id', sa.Integer(), nullable=False),
    sa.Column('entity_id', sa.Integer(), nullable=False),
    sa.Column('entity_type', sa.Enum('user', 'patient', 'visit', 'image', 'diagnosis_result', name='entity_types'), nullable=False),
    sa.Column('key', sa.String(length=50), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('meta_id')
    )
    op.create_table('patients',
    sa.Column('patient_id', sa.String(length=10), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=True),
    sa.Column('age', sa.Integer(), nullable=False),
    sa.Column('gender', sa.Enum('male', 'female', 'other', name='gender_types'), nullable=False),
    sa.Column('address', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('patient_id')
    )
    op.create_table('users',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('password', sa.String(length=255), nullable=False),
    sa.Column('role', sa.Enum('admin', 'doctor', 'lab_technician', 'researcher', name='user_roles'), nullable=False),
    sa.Column('email_confirmed', sa.Boolean(), nullable=True),
    sa.Column('email_confirmed_at', sa.DateTime(), nullable=True),
    sa.Column('google_id', sa.String(length=120), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('user_id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('google_id')
    )
    op.create_table('visits',
    sa.Column('visit_id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.String(length=10), nullable=False),
    sa.Column('visit_date', sa.DateTime(), nullable=False),
    sa.Column('reason', sa.String(length=255), nullable=True),
    sa.Column('symptoms', sa.Text(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('status', sa.Enum('pending', 'in_progress', 'completed', name='visit_status'), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['patient_id'], ['patients.patient_id'], ),
    sa.PrimaryKeyConstraint('visit_id')
    )
    op.create_table('images',
    sa.Column('image_id', sa.Integer(), nullable=False),
    sa.Column('visit_id', sa.Integer(), nullable=False),
    sa.Column('file_path', sa.String(length=255), nullable=False),
    sa.Column('smear_type', sa.Enum('thick', 'thin', name='smear_types'), nullable=False),
    sa.Column('test_type', sa.Enum('Giemsa', 'Wright', 'Field', name='test_types'), nullable=False),
    sa.Column('processing_status', sa.Enum('queued', 'processing', 'completed', 'failed', name='processing_status'), nullable=True),
    sa.Column('upload_date', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['visit_id'], ['visits.visit_id'], ),
    sa.PrimaryKeyConstraint('image_id')
    )
    op.create_table('diagnosis_results',
    sa.Column('result_id', sa.Integer(), nullable=False),
    sa.Column('visit_id', sa.Integer(), nullable=False),
    sa.Column('image_id', sa.Integer(), nullable=False),
    sa.Column('parasite_name', sa.String(length=50), nullable=False),
    sa.Column('average_confidence', sa.Float(), nullable=False),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('severity_level', sa.Enum('low', 'medium', 'high', name='severity_levels'), nullable=False),
    sa.Column('status', sa.Enum('positive', 'negative', 'inconclusive', name='result_status'), nullable=False),
    sa.Column('result_date', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['image_id'], ['images.image_id'], ),
    sa.ForeignKeyConstraint(['visit_id'], ['visits.visit_id'], ),
    sa.PrimaryKeyConstraint('result_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('diagnosis_results')
    op.drop_table('images')
    op.drop_table('visits')
    op.drop_table('users')
    op.drop_table('patients')
    op.drop_table('metadata')
    # ### end Alembic commands ###
