from . import db
import datetime
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.exc import IntegrityError


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'doctor', 'lab_technician', name='user_roles'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

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

    @declared_attr
    def _table_args(cls):
        return (db.UniqueConstraint('patient_id', name='unique_patient_id'),)

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


class Image(db.Model):
    __tablename__ = 'images'
    image_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(10), db.ForeignKey('patients.patient_id'), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    smear_type = db.Column(db.Enum('thick', 'thin', name='smear_types'), nullable=False)
    test_type = db.Column(db.Enum('Giemsa', 'Wright', 'Field', name='test_types'), nullable=False)
    status = db.Column(db.Enum('queued', 'preprocessing', 'preprocessed', 'processed', name='image_status'), nullable=False)
    upload_date = db.Column(db.DateTime, server_default=db.func.now())
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

# class DiagnosisResult(db.Model):
#     __tablename__ = 'diagnosis_results'
#     result_id = db.Column(db.Integer, primary_key=True)
#     image_id = db.Column(db.Integer, db.ForeignKey('images.image_id'), nullable=False)
#     parasite_detected = db.Column(db.Boolean, nullable=False)
#     confidence = db.Column(db.Float, nullable=False)
#     #wbc_count = db.Column(db.Integer, nullable=False)
#     parasite_detected_count = db.Column(db.Integer, db.Foreign)
#     severity = db.Column(db.Enum('mild', 'moderate', 'severe', name='result_severity'), nullable=False)
#     status = db.Column(db.Enum('positive', 'negative', 'inconclusive', name='result_status'), nullable=False)
#     result_date = db.Column(db.DateTime, server_default=db.func.now())
#     created_at = db.Column(db.DateTime, server_default=db.func.now())
#     updated_at = db.Column(db.DateTime, onupdate=db.func.now())

class DiagnosisResult(db.Model):
    __tablename__ = 'diagnosis_results'
    result_id = db.Column(db.Integer, primary_key=True)
    image_id = db.Column(db.Integer, db.ForeignKey('images.image_id'), nullable=False)
    parasite_name = db.Column(db.String(50), nullable=False)
    average_confidence = db.Column(db.Float, nullable=False)
    count = db.Column(db.Integer, nullable=False)
    severity_level = db.Column(db.Enum('low', 'medium', 'high', name='severity_levels'), nullable=False)
    status = db.Column(db.Enum('positive', 'negative', 'inconclusive', name='result_status'), nullable=False)
    result_date = db.Column(db.DateTime, server_default=db.func.now())
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

class Metadata(db.Model):
    __tablename__ = 'metadata'
    meta_id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.Integer, nullable=False)
    entity_type = db.Column(db.Enum('user', 'patient', 'image', 'diagnosis_result', name='entity_types'), nullable=False)
    key = db.Column(db.String(50), nullable=False)
    value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
