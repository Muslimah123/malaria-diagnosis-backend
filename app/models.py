# models.py

from .database import db
import datetime
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.exc import IntegrityError
from sqlalchemy import Enum, Index, text
from sqlalchemy.dialects.postgresql import TSVECTOR

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'doctor', 'lab_technician', 'researcher', name='user_roles'), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmed_at = db.Column(db.DateTime)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    backup_codes = db.relationship('BackupCode', backref='user', lazy='dynamic')
    remembered_devices = db.relationship('RememberedDevice', backref='user', lazy='dynamic')

    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_role', 'role'),
        Index('idx_user_google_id', 'google_id'),
    )

class BackupCode(db.Model):
    __tablename__ = 'backup_codes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    code = db.Column(db.String(8), nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        Index('idx_backup_code_user_id', 'user_id'),
    )

class RememberedDevice(db.Model):
    __tablename__ = 'remembered_devices'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    token = db.Column(db.String(64), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        Index('idx_remembered_device_user_id', 'user_id'),
        Index('idx_remembered_device_token', 'token'),
    )

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    participant_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    last_message = db.Column(db.String(255))
    last_message_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.utcnow)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('chats_initiated', lazy='dynamic'))
    participant = db.relationship('User', foreign_keys=[participant_id], backref=db.backref('chats_received', lazy='dynamic'))
    messages = db.relationship('Message', back_populates='chat', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_chat_user_id', 'user_id'),
        Index('idx_chat_participant_id', 'participant_id'),
        Index('idx_chat_last_message_time', 'last_message_time'),
    )

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    chat = db.relationship('Chat', back_populates='messages')
    sender = db.relationship('User', backref=db.backref('messages_sent', lazy='dynamic'))

    __table_args__ = (
        Index('idx_message_chat_id', 'chat_id'),
        Index('idx_message_sender_id', 'sender_id'),
        Index('idx_message_timestamp', 'timestamp'),
    )

class Patient(db.Model):
    __tablename__ = 'patients'
    patient_id = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.Enum('male', 'female', 'other', name='gender_types'), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    visits = db.relationship('Visit', back_populates='patient', cascade='all, delete-orphan')
    search_vector = db.Column(TSVECTOR)

    @declared_attr
    def __table_args__(cls):
        return (
            db.UniqueConstraint('patient_id', name='unique_patient_id'),
            Index('idx_patient_name', 'name'),
            Index('idx_patient_email', 'email'),
            Index('idx_patient_created_at', 'created_at'),
            Index('idx_patient_search_vector', 'search_vector', postgresql_using='gin'),
        )

    def __init__(self, **kwargs):
        super(Patient, self).__init__(**kwargs)
        if not self.patient_id:
            self.patient_id = self.generate_patient_id()

    @staticmethod
    def generate_patient_id():
        prefix = 'PID'
        with db.session.no_autoflush:
            last_patient = db.session.query(Patient).order_by(Patient.patient_id.desc()).first()
            if last_patient:
                last_id = int(last_patient.patient_id[len(prefix):])
                new_id = last_id + 1
            else:
                new_id = 1
            return f'{prefix}{new_id:02d}'

    @classmethod
    def update_search_vectors(cls):
        stmt = text("""
            UPDATE patients
            SET search_vector = to_tsvector('english', 
                coalesce(name, '') || ' ' || 
                coalesce(email, '') || ' ' || 
                coalesce(address, '') || ' ' || 
                coalesce(cast(age as text), '') || ' ' || 
                coalesce(gender, '')
            )
        """)
        db.session.execute(stmt)
        db.session.commit()

class Visit(db.Model):
    __tablename__ = 'visits'
    visit_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(10), db.ForeignKey('patients.patient_id'), nullable=False)
    visit_date = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    reason = db.Column(db.String(255))
    symptoms = db.Column(db.Text)
    notes = db.Column(db.Text)
    status = db.Column(db.Enum('pending', 'in_progress', 'completed', name='visit_status'), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    patient = db.relationship('Patient', back_populates='visits')
    images = db.relationship('Image', back_populates='visit', cascade='all, delete-orphan')
    diagnosis_results = db.relationship('DiagnosisResult', back_populates='visit', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_visit_patient_id', 'patient_id'),
        Index('idx_visit_date', 'visit_date'),
        Index('idx_visit_status', 'status'),
    )

class Image(db.Model):
    __tablename__ = 'images'
    image_id = db.Column(db.Integer, primary_key=True)
    visit_id = db.Column(db.Integer, db.ForeignKey('visits.visit_id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    smear_type = db.Column(db.Enum('thick', 'thin', name='smear_types'), nullable=False)
    test_type = db.Column(db.Enum('Giemsa', 'Wright', 'Field', name='test_types'), nullable=False)
    processing_status = db.Column(db.Enum('queued', 'processing', 'completed', 'failed', name='processing_status'), default='queued')
    upload_date = db.Column(db.DateTime, server_default=db.func.now())
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    visit = db.relationship('Visit', back_populates='images')
    diagnosis_results = db.relationship('DiagnosisResult', back_populates='image', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_image_visit_id', 'visit_id'),
        Index('idx_image_processing_status', 'processing_status'),
        Index('idx_image_upload_date', 'upload_date'),
    )

class DiagnosisResult(db.Model):
    __tablename__ = 'diagnosis_results'
    result_id = db.Column(db.Integer, primary_key=True)
    visit_id = db.Column(db.Integer, db.ForeignKey('visits.visit_id'), nullable=False)
    image_id = db.Column(db.Integer, db.ForeignKey('images.image_id'), nullable=True)
    parasite_name = db.Column(db.String(50), nullable=True)
    average_confidence = db.Column(db.Float, nullable=True)
    count = db.Column(db.Integer, nullable=False)
    severity_level = db.Column(db.String(50), nullable=True)
    status = db.Column(db.Enum('positive', 'negative', 'inconclusive', name='result_status'), nullable=True)
    result_date = db.Column(db.DateTime, server_default=db.func.now())
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    parasite_density = db.Column(db.Float, nullable=True)
    total_wbcs = db.Column(db.Integer, nullable=True)
    wbc_count = db.Column(db.Integer, nullable=True)

    visit = db.relationship('Visit', back_populates='diagnosis_results')
    image = db.relationship('Image', back_populates='diagnosis_results')

    __table_args__ = (
        Index('idx_diagnosis_visit_id', 'visit_id'),
        Index('idx_diagnosis_image_id', 'image_id'),
        Index('idx_diagnosis_result_date', 'result_date'),
        Index('idx_diagnosis_status', 'status'),
    )

class Metadata(db.Model):
    __tablename__ = 'metadata'
    meta_id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.Integer, nullable=False)
    entity_type = db.Column(db.Enum('user', 'patient', 'visit', 'image', 'diagnosis_result', name='entity_types'), nullable=False)
    key = db.Column(db.String(50), nullable=False)
    value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    __table_args__ = (
        Index('idx_metadata_entity', 'entity_id', 'entity_type'),
        Index('idx_metadata_key', 'key'),
    )

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic'))

    __table_args__ = (
        Index('idx_notification_user_id', 'user_id'),
        Index('idx_notification_read', 'read'),
    )

# Add this at the end of the file to create the trigger function and trigger
db.event.listen(Patient.__table__, 'after_create', db.DDL('''
    CREATE FUNCTION patient_search_vector_update() RETURNS trigger AS $$
    BEGIN
        NEW.search_vector := to_tsvector('english', 
            coalesce(NEW.name, '') || ' ' || 
            coalesce(NEW.email, '') || ' ' || 
            coalesce(NEW.address, '') || ' ' || 
            coalesce(cast(NEW.age as text), '') || ' ' || 
            coalesce(NEW.gender, '')
        );
        RETURN NEW;
    END
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER patient_search_vector_update 
    BEFORE INSERT OR UPDATE ON patients
    FOR EACH ROW EXECUTE FUNCTION patient_search_vector_update();
'''))

# Add this function to update existing records' search vectors
def update_all_patient_search_vectors():
    db.session.execute(text("""
        UPDATE patients
        SET search_vector = to_tsvector('english', 
            coalesce(name, '') || ' ' || 
            coalesce(email, '') || ' ' || 
            coalesce(address, '') || ' ' || 
            coalesce(cast(age as text), '') || ' ' || 
            coalesce(gender, '')
        )
    """))
    db.session.commit()

# Function to perform full-text search on patients
def search_patients(query):
    return Patient.query.filter(Patient.search_vector.match(query)).all()

# Partition the Visit table by year
db.event.listen(Visit.__table__, 'after_create', db.DDL('''
    ALTER TABLE visits PARTITION BY RANGE (visit_date);

    CREATE TABLE visits_2023 PARTITION OF visits
        FOR VALUES FROM ('2023-01-01') TO ('2024-01-01');

    CREATE TABLE visits_2024 PARTITION OF visits
        FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');

    -- Add more partitions as needed for future years
'''))

# Function to create a new partition for the next year
def create_next_year_partition():
    next_year = datetime.datetime.now().year + 1
    db.session.execute(text(f'''
        CREATE TABLE visits_{next_year} PARTITION OF visits
            FOR VALUES FROM ('{next_year}-01-01') TO ('{next_year+1}-01-01');
    '''))
    db.session.commit()

# Add this function to create indexes on partitioned tables
def create_partition_indexes():
    current_year = datetime.datetime.now().year
    for year in range(current_year - 1, current_year + 2):  # Create indexes for last year, current year, and next year
        db.session.execute(text(f'''
            CREATE INDEX IF NOT EXISTS idx_visits_{year}_patient_id ON visits_{year} (patient_id);
            CREATE INDEX IF NOT EXISTS idx_visits_{year}_visit_date ON visits_{year} (visit_date);
            CREATE INDEX IF NOT EXISTS idx_visits_{year}_status ON visits_{year} (status);
        '''))
    db.session.commit()

# Function to optimize tables (for PostgreSQL)
def optimize_tables():
    tables = ['users', 'patients', 'visits', 'images', 'diagnosis_results', 'metadata', 'notifications']
    for table in tables:
        db.session.execute(text(f"VACUUM ANALYZE {table};"))
    db.session.commit()

# Function to update table statistics
def update_table_statistics():
    db.session.execute(text("ANALYZE;"))
    db.session.commit()

# Add these lines at the end of the file to ensure all model changes are reflected in the database
def initialize_models(app):
    with app.app_context():
        db.create_all()
        update_all_patient_search_vectors()
        create_partition_indexes()
        optimize_tables()
        update_table_statistics()