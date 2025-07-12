from flask import Blueprint, request, jsonify, url_for, redirect, session
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from app.models import db, User, Patient, Image,Visit, DiagnosisResult, Metadata, Notification,Chat,Message, BackupCode, RememberedDevice,search_patients, update_all_patient_search_vectors,create_next_year_partition,optimize_tables,update_table_statistics
from datetime import timedelta, datetime
from app.schemas import UserSchema, PatientSchema, ImageSchema, DiagnosisResultSchema, MetadataSchema,VisitSchema,NotificationSchema,ChatSchema, MessageSchema, BackupCodeSchema, RememberedDeviceSchema
from app.utils import save_image
from app.socket_events import send_processing_update
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from marshmallow import EXCLUDE, ValidationError
from sqlalchemy import select
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
from flask import render_template
from google.oauth2 import id_token
from google.auth.transport import requests
from .extensions import mail, oauth
from flask import redirect, url_for, flash
from sqlalchemy import func
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file
import hmac
import hashlib
from flask import request, abort
# from .celery_worker import process_images_batch
from flask import current_app,request
from flask_socketio import emit
from .socket_events import socketio
import logging
from flask import jsonify
from sqlalchemy import func
import pyotp
import qrcode
import io
import base64
from app.processing.Updated_Helpers import process_images, MODEL_PATH
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
from .utils import optimize_query, monitor_query_performance, cache_query, create_materialized_view
from .database_management import refresh_patient_summary_view
from sqlalchemy.sql import text
import psycopg2
import json




api = Blueprint('api', __name__)

# JWT setup
def init_jwt(app):
    app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY') 
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    jwt = JWTManager(app)
    return jwt
ph=PasswordHasher()
# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Helper functions
def generate_backup_codes(user, num_codes=8):
    for _ in range(num_codes):
        code = secrets.token_hex(4)  # 8-character hexadecimal code
        backup_code = BackupCode(user_id=user.user_id, code=code)
        db.session.add(backup_code)
    db.session.commit()

def verify_backup_code(user, code):
    backup_code = BackupCode.query.filter_by(user_id=user.user_id, code=code, used=False).first()
    if backup_code:
        backup_code.used = True
        db.session.commit()
        return True
    return False

def generate_remember_token():
    return secrets.token_urlsafe(48)

def remember_device(user):
    token = generate_remember_token()
    expiry = datetime.utcnow() + timedelta(days=30)  # Remember for 30 days
    remembered_device = RememberedDevice(user_id=user.user_id, token=token, expiry=expiry)
    db.session.add(remembered_device)
    db.session.commit()
    return token

def verify_remember_token(user, token):
    remembered_device = RememberedDevice.query.filter_by(user_id=user.user_id, token=token).first()
    if remembered_device and remembered_device.expiry > datetime.utcnow():
        return True
    return False
# Schemas
user_schema = UserSchema()
patient_schema = PatientSchema()
patients_schema = PatientSchema(many=True)
image_schema = ImageSchema()
images_schema = ImageSchema(many=True)
diagnosis_result_schema = DiagnosisResultSchema()
diagnosis_results_schema = DiagnosisResultSchema(many=True)
metadata_schema = MetadataSchema()
metadata_items_schema = MetadataSchema(many=True)
visit_schema = VisitSchema()
visits_schema = VisitSchema(many=True)
notification_schema = NotificationSchema()
notifications_schema = NotificationSchema(many=True)
chat_schema = ChatSchema()
chats_schema = ChatSchema(many=True)
message_schema = MessageSchema()
messages_schema = MessageSchema(many=True)
backup_code_schema = BackupCodeSchema()
backup_codes_schema = BackupCodeSchema(many=True)
remembered_device_schema = RememberedDeviceSchema()
remembered_devices_schema = RememberedDeviceSchema(many=True)

@api.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    try:
        if 'google_token' in data:
            # This is a Google OAuth user
            google_user_info = verify_google_token(data['google_token'])
            if not google_user_info:
                return jsonify({'message': 'Invalid Google token'}), 400
            
            existing_user = User.query.filter_by(email=google_user_info['email']).first()
            if existing_user:
                return jsonify({'message': 'User already exists!'}), 400
            
            new_user = User(
                username=google_user_info['name'],
                email=google_user_info['email'],
                password=None,
                role='doctor',  # Default role is doctor
                email_confirmed=True,
                email_confirmed_at=datetime.now(),
                mfa_secret=pyotp.random_base32(),
                mfa_enabled=False
            )
        else:
            # This is a regular user
            hashed_password = ph.hash(data['password'])
            new_user = User(
                username=data['username'],
                email=data['email'],
                password=hashed_password,
                role=data['role'],
                email_confirmed=False,
                mfa_secret=pyotp.random_base32(),
                mfa_enabled=False
            )
        
        db.session.add(new_user)
        db.session.commit()

        # Create notification for admins
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.user_id, f"New user {new_user.username} has been registered")
        
        if 'google_token' not in data:
            # Send verification email for non-OAuth users
            token = generate_confirmation_token(new_user.email)
            confirm_url = url_for('api.confirm_email', token=token, _external=True)
            html = render_template('email/activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(new_user.email, subject, html)
            message = 'User registered successfully! Please check your email to verify your account before logging in.'
        else:
            message = 'User registered successfully!'

        # Generate MFA setup data
        totp = pyotp.TOTP(new_user.mfa_secret)
        qr_code = totp.provisioning_uri(new_user.email, issuer_name="MalariaAI")
        
        return jsonify({
            'message': message,
            'email_sent': 'google_token' not in data,
            'require_mfa_setup': True,
            'user_id': new_user.user_id,
            'mfa_secret': new_user.mfa_secret,
            'qr_code': qr_code
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"Error during registration: {str(e)}")
        return jsonify({'message': 'An error occurred during registration. Please try again.'}), 500


@api.route('/send-verification-email', methods=['POST'])
def send_verification_email():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('api.confirm_email', token=token, _external=True)
    html = render_template('email/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(user.email, subject, html)
    
    return jsonify({'message': 'Verification email sent successfully'}), 200

@api.route('/confirm-email/<token>')
def confirm_email(token):
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    try:
        email = confirm_token(token)
    except:
        # Redirect to frontend with an error message
        return redirect(f"{frontend_url}/login?error=invalid_token")

    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(f"{frontend_url}/login?error=user_not_found")

    if user.email_confirmed:
        # If email is already confirmed, redirect to the success page
        return redirect(f"{frontend_url}/email-verification-success")

    # If email is not confirmed, confirm it
    user.email_confirmed = True
    user.email_confirmed_at = datetime.now()
    db.session.add(user)
    db.session.commit()

    # Generate a JWT token after email confirmation
    access_token = create_access_token(identity={'user_id': user.user_id, 'email': user.email})

    # Redirect to the frontend with the token (e.g., for MFA setup)
    return redirect(f"{frontend_url}/email-verification-success?token={access_token}")

@api.route('/login', methods=['GET'])
def login_page():
    # Render your login page or return a response
    return jsonify({"message": "Please log in"}), 200

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
    return serializer.dumps(email, salt=os.environ.get('SECURITY_PASSWORD_SALT'))

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
    try:
        email = serializer.loads(
            token,
            salt=os.environ.get('SECURITY_PASSWORD_SALT'),
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=os.environ.get('MAIL_DEFAULT_SENDER')
    )
    mail.send(msg)

@api.route('/login/google')
def google_login():
    redirect_uri = url_for('api.google_authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@api.route('/login/google/authorize')
def google_authorize():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()
    
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(
            username=user_info['name'],
            email=user_info['email'],
            google_id=user_info['sub'],  # This is the Google user ID
            password=None,
            role='doctor',  # users will have the option to choose their role 
            email_confirmed=True,
            email_confirmed_at=datetime.now()
        )
        db.session.add(user)
        db.session.commit()
    elif not user.google_id:
        user.google_id = user_info['sub']
        db.session.commit()
    
    access_token = create_access_token(identity={'email': user.email, 'role': user.role})
    return jsonify(access_token=access_token)
    
@api.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    
    # Handle Google OAuth
    if 'google_token' in data:
        google_user_info = verify_google_token(data['google_token'])
        if not google_user_info:
            return jsonify({'message': 'Invalid Google token'}), 401
        user = User.query.filter_by(email=google_user_info['email']).first()
    
    # Handle regular email/password login
    else:
        user = User.query.filter_by(email=data['email']).first()
        if not user or not ph.verify(user.password, data['password']):
            return jsonify({'message': 'Invalid credentials!'}), 401
        if not user.email_confirmed:
            return jsonify({'message': 'Please confirm your email before logging in.'}), 401

    if not user:
        return jsonify({'message': 'User not found!'}), 401

    # Enforce MFA setup if the user hasn't set it up yet
    if not user.mfa_enabled:
        return jsonify({'require_mfa_setup': True, 'user_id': user.user_id}), 200

    # If MFA is enabled, verify MFA token or backup code
    if user.mfa_enabled:
        remember_token = request.cookies.get('remember_token')
        
        # Check for remember_token to skip MFA for remembered devices
        if remember_token and verify_remember_token(user, remember_token):
            access_token = create_access_token(identity={'user_id': user.user_id, 'email': user.email, 'role': user.role})
            return jsonify({'access_token': access_token, 'message': 'Login successful, device remembered'}), 200

        # Otherwise, require MFA token or backup code
        mfa_token = data.get('mfa_token')
        backup_code = data.get('backup_code')

        if not mfa_token and not backup_code:
            return jsonify({'message': 'MFA token or backup code required', 'require_mfa': True, 'user_id': user.user_id}), 200

        if mfa_token:
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(mfa_token):
                return jsonify({'message': 'Invalid MFA token'}), 401
        elif backup_code:
            if not verify_backup_code(user, backup_code):
                return jsonify({'message': 'Invalid backup code'}), 401

        # Handle the remember device option
        if data.get('remember_device'):
            remember_token = remember_device(user)
            response = jsonify({'message': 'Device remembered for future logins'})
            response.set_cookie('remember_token', remember_token, httponly=True, secure=True, max_age=30*24*60*60)  # 30 days
            return response

    # Generate access token for successful login
    access_token = create_access_token(identity={'user_id': user.user_id, 'email': user.email, 'role': user.role})
    return jsonify({'access_token': access_token, 'message': 'Login successful'}), 200

@api.route('/enable-mfa', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def enable_mfa():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()

    if user.mfa_enabled:
        return jsonify({'message': 'MFA is already enabled'}), 400

    # Generate MFA secret
    user.mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(user.email, issuer_name="MalariaAI")

    # Generate QR code as an image
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Convert QR code to image
    img = qr.make_image(fill='black', back_color='white')

    # Convert image to base64
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    # Generate backup codes
    generate_backup_codes(user)
    
    db.session.commit()

    backup_codes = backup_codes_schema.dump(user.backup_codes)

    return jsonify({
        'qr_code': f"data:image/png;base64,{qr_code_base64}",
        'secret': user.mfa_secret,
        'backup_codes': backup_codes,
        'message': 'MFA setup initiated. Please verify with a token to complete setup.'
    }), 200

@api.route('/verify-mfa', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def verify_mfa():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    token = request.json.get('token')
    
    if not token:
        return jsonify({'message': 'Token is required'}), 400
    
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(token):
        user.mfa_enabled = True
        db.session.commit()
        access_token = create_access_token(identity={'user_id': user.user_id, 'email': user.email, 'role': user.role})

        return jsonify({'message': 'MFA verified successfully', 'access_token': access_token}), 200


    else:
        return jsonify({'message': 'Invalid token'}), 400

@api.route('/disable-mfa', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def disable_mfa():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    
    if not user.mfa_enabled:
        return jsonify({'message': 'MFA is not enabled'}), 400
    
    # Require password re-entry for security
    password = request.json.get('password')
    if not password or not ph.verify(user.password, password):
        return jsonify({'message': 'Invalid password'}), 401
    
    user.mfa_enabled = False
    user.mfa_secret = None
    BackupCode.query.filter_by(user_id=user.user_id).delete()
    db.session.commit()
    
    return jsonify({'message': 'MFA disabled successfully'}), 200
@api.route('/check-mfa-status', methods=['GET'])
@jwt_required()
def check_mfa_status():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    return jsonify({
        'isMFASetup': user.mfa_enabled,
        'email': user.email
    }), 200
@api.route('/generate-backup-codes', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def generate_new_backup_codes():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    
    if not user.mfa_enabled:
        return jsonify({'message': 'MFA is not enabled'}), 400
    
    # Clear existing backup codes
    BackupCode.query.filter_by(user_id=user.user_id).delete()
    
    # Generate new backup codes
    generate_backup_codes(user)
    
    new_codes = backup_codes_schema.dump(user.backup_codes)
    
    return jsonify({'message': 'New backup codes generated', 'backup_codes': new_codes}), 200

@api.route('/reset-password', methods=['POST'])
@limiter.limit("3 per hour")
def reset_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Don't reveal whether a user exists
        return jsonify({'message': 'If a user with this email exists, a password reset link has been sent.'}), 200
    
    # Generate a unique token for password reset
    token = generate_confirmation_token(user.email)
    
    # Send password reset email
    frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
    # reset_url = url_for('api.confirm_password_reset', token=token, _external=True)
    reset_url = f"{frontend_url}/reset-password?token={token}"
    html = render_template('email/reset_password.html', reset_url=reset_url)
    subject = "Password Reset Request"
    send_email(user.email, subject, html)
    
    return jsonify({'message': 'If a user with this email exists, a password reset link has been sent.'}), 200

@api.route('/confirm-password-reset/<token>', methods=['POST'])
@limiter.limit("3 per hour")
def confirm_password_reset(token):
    try:
        email = confirm_token(token)
    except:
        return jsonify({'message': 'Invalid or expired token'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    new_password = request.json.get('new_password')
    if not new_password:
        return jsonify({'message': 'New password is required'}), 400
    
    # If MFA is enabled, require MFA token or backup code
    if user.mfa_enabled:
        mfa_token = request.json.get('mfa_token')
        backup_code = request.json.get('backup_code')
        
        if not mfa_token and not backup_code:
            return jsonify({'message': 'MFA token or backup code required'}), 400
        
        if mfa_token:
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(mfa_token):
                return jsonify({'message': 'Invalid MFA token'}), 401
        elif backup_code:
            if not verify_backup_code(user, backup_code):
                return jsonify({'message': 'Invalid backup code'}), 401
    
    # Reset password
    user.password = ph.hash(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200

# Helper function to verify Google token
def verify_google_token(token):
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), os.environ.get('GOOGLE_CLIENT_ID'))
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        return idinfo
    except ValueError:
        return None

@api.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Hello, {current_user["email"]}. This is a protected route.'})

@api.route('/user/profile', methods=['GET'])
@jwt_required()
def user_profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    user_data = user_schema.dump(user)
    return jsonify(user_data)
    
@api.route('/patients', methods=['POST'])
@jwt_required()
@monitor_query_performance
def create_patient():
    data = request.get_json()
    try:
        # Create the patient
        new_patient = patient_schema.load(data, session=db.session, unknown=EXCLUDE)
        db.session.add(new_patient)
        db.session.commit()

        # Attempt to update search vector
        try:
            db.session.execute(text(f"""
                UPDATE patients
                SET search_vector = to_tsvector('english', 
                    coalesce(name, '') || ' ' ||
                    coalesce(email, '') || ' ' ||
                    coalesce(address, '') || ' ' ||
                    coalesce(cast(age as text), '') || ' ' ||
                    coalesce(gender::text, 'unknown')  -- Adjust 'unknown' to your valid gender enum
                )
                WHERE patient_id = '{new_patient.patient_id}'
            """))
            db.session.commit()
        except Exception as e:
            logging.error(f"Failed to update search vector: {str(e)}")
            # Optionally rollback only if this specific query fails
            db.session.rollback()

        # Attempt to create notifications for admins
        try:
            admin_users = User.query.filter_by(role='admin').all()
            for admin in admin_users:
                create_notification(admin.user_id, f"New patient registered: {new_patient.name}")
        except Exception as e:
            logging.error(f"Failed to create notification: {str(e)}")

        return jsonify({'message': 'Patient created successfully!', 'patient': patient_schema.dump(new_patient)}), 201
    
    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"An error occurred during patient creation: {str(e)}")
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

@api.route('/patients/search', methods=['GET'])
@jwt_required()
def search_patients_route():
    query = request.args.get('query', '')
    patients = search_patients(query)
    return jsonify(patients_schema.dump(patients)), 200


@api.route('/patients', methods=['GET'])
@jwt_required()
@monitor_query_performance
def get_patients():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 10, type=int)
    status_filter = request.args.get('status', 'all')
    search_term = request.args.get('search', '')

    logging.info(f"Fetching patients for page {page} with limit {per_page}, status: {status_filter}, search: {search_term}")

    try:
        # Refresh the materialized view (if needed)
        refresh_patient_summary_view()

        # Construct the query with optional filtering and searching
        query = f"""
        SELECT patient_id, name, email, age, gender, address, created_at, latest_visit_id, latest_diagnosis_status
        FROM patient_summary
        WHERE 1 = 1
        """

        # Apply search term filter if provided
        if search_term:
            query += f" AND (name ILIKE '%{search_term}%' OR email ILIKE '%{search_term}%')"

        # Apply status filter if provided and not 'all'
        if status_filter != 'all':
            query += f" AND latest_diagnosis_status = '{status_filter}'"

        # Add pagination and ordering
        query += f" ORDER BY created_at DESC LIMIT {per_page} OFFSET {(page - 1) * per_page}"

        logging.info(f"Executing query with search and filter: {query}")
        
        result = db.session.execute(text(query))

        patients_data = []
        for row in result:
            patient_dict = {
                'patient_id': row[0],
                'name': row[1],
                'email': row[2],
                'age': row[3],
                'gender': row[4],
                'address': row[5],
                'created_at': row[6],
                'latest_visit_id': row[7],
                'status': row[8] if row[8] else 'pending'
            }

            if not row[7]:
                patient_dict['status'] = 'no_visit'
            
            patients_data.append(patient_dict)

        logging.info(f"Query returned {len(patients_data)} rows for page {page}")

        # Get total count for pagination without the limit and offset
        count_query = """
        SELECT COUNT(*) 
        FROM patient_summary
        WHERE 1 = 1
        """
        if search_term:
            count_query += f" AND (name ILIKE '%{search_term}%' OR email ILIKE '%{search_term}%')"
        if status_filter != 'all':
            count_query += f" AND latest_diagnosis_status = '{status_filter}'"
        
        total_count = db.session.execute(text(count_query)).scalar()
        total_pages = (total_count + per_page - 1) // per_page

        return jsonify({
            'patients': patients_data,
            'totalPages': total_pages,
            'page': page,
            'per_page': per_page,
            'total': total_count
        })

    except Exception as e:
        logging.error(f"Error fetching patients: {e}")
        return jsonify({"error": "Failed to fetch patients."}), 500

@api.route('/patients/<string:patient_id>', methods=['GET'])
@jwt_required()
def get_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    patient_data = patient_schema.dump(patient)
    
    visits = Visit.query.filter_by(patient_id=patient_id).order_by(Visit.visit_date.desc()).all()
    visits_data = visits_schema.dump(visits)
    
    for visit in visits_data:
        images = Image.query.filter_by(visit_id=visit['visit_id']).all()
        visit['images'] = images_schema.dump(images)
        
        diagnosis_results = DiagnosisResult.query.filter_by(visit_id=visit['visit_id']).all()
        visit['diagnosis_results'] = diagnosis_results_schema.dump(diagnosis_results)
    
    patient_data['visits'] = visits_data
    
    return jsonify(patient_data)

from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError

@api.route('/patients/<string:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    print(f"Received update request for patient {patient_id}")

    data = request.get_json()
    print(f"Received data for update: {data}")

    # Remove patient_id from the data if it exists
    data.pop('patient_id', None)

    # Fetch the patient from the database
    patient = Patient.query.get_or_404(patient_id)

    try:
        # Ensure the schema is passed the session for deserialization
        updated_patient = patient_schema.load(data, instance=patient, session=db.session, partial=True)
        print(f"Deserialized and validated data: {updated_patient}")

        # Commit the changes
        db.session.commit()

        # Update the search vector for the updated patient
        db.session.execute(text(f"""
            UPDATE patients
            SET search_vector = to_tsvector('english', 
                coalesce(name, '') || ' ' ||
                coalesce(email, '') || ' ' ||
                coalesce(address, '') || ' ' ||
                coalesce(cast(age as text), '') || ' ' ||
                coalesce(gender::text, 'unknown')
            )
            WHERE patient_id = '{patient_id}'
        """))
        db.session.commit()

        # Notify admins of the update
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.user_id, f"Patient updated: {updated_patient.name}")

        # Return the updated patient data
        return jsonify({
            'message': 'Patient updated successfully!',
            'patient': patient_schema.dump(updated_patient)
        }), 200

    except ValidationError as e:
        db.session.rollback()
        print(f"Validation error: {e.messages}")
        return jsonify({'message': 'Validation error', 'errors': e.messages}), 400
    except IntegrityError as e:
        db.session.rollback()
        print(f"Integrity error: {str(e)}")
        return jsonify({'message': 'Database integrity error', 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error updating patient: {str(e)}")
        return jsonify({'message': 'An unexpected error occurred', 'error': str(e)}), 500



@api.route('/patients/<string:patient_id>', methods=['DELETE'])
@jwt_required()
def delete_patient(patient_id):
    patient = Patient.query.filter_by(patient_id=patient_id).first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404

    try:
        # Delete the patient from the database
        db.session.delete(patient)
        db.session.commit()

        # Notify admins of the deletion
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.user_id, f"Patient deleted: {patient.name}")

        return jsonify({'message': 'Patient deleted successfully!'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting patient: {str(e)}")  # Log the error
        return jsonify({'message': 'An unexpected error occurred', 'error': str(e)}), 500



@api.route('/patients/influx', methods=['GET'])
@jwt_required()
def get_patient_influx():
    try:
        # Get the current date and 7 days before
        today = datetime.now().date()
        start_date = today - timedelta(days=6)

        # Query to get the number of new patients per day over the past week
        influx_query = db.session.execute(text("""
            SELECT 
                DATE(created_at) as day, 
                COUNT(*) as new_patients
            FROM patients
            WHERE created_at >= :start_date AND created_at < :end_date
            GROUP BY day
            ORDER BY day
        """), {'start_date': start_date, 'end_date': today + timedelta(days=1)})
        
        influx_data = [
            {"day": str(row[0]), "new_patients": row[1]}
            for row in influx_query
        ]

        return jsonify({"influx_data": influx_data}), 200

    except Exception as e:
        logging.error(f"Error fetching patient influx data: {e}")
        return jsonify({"message": "An error occurred while fetching patient influx data"}), 500

@api.route('/maintenance/create_next_year_partition', methods=['POST'])
@jwt_required()
def create_next_year_partition_route():
    try:
        create_next_year_partition()
        return jsonify({'message': 'Next year partition created successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

@api.route('/maintenance/optimize_tables', methods=['POST'])
@jwt_required()
def optimize_tables_route():
    try:
        optimize_tables()
        update_table_statistics()
        return jsonify({'message': 'Tables optimized and statistics updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
@api.route('/patients/<string:patient_id>/visits', methods=['POST'])
@jwt_required()
def create_visit(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    data = request.get_json()
    new_visit = Visit(
        patient_id=patient_id,
        visit_date=datetime.utcnow(),
        reason=data.get('reason'),
        symptoms=data.get('symptoms'),
        notes=data.get('notes')
    )
    db.session.add(new_visit)
    db.session.commit()
    # Create notification for doctors
    admin_users = User.query.filter_by(role='admin').all()
    for admin in admin_users:
        create_notification(admin.user_id, f"New visit created for patient: {patient.name}")
    return jsonify({'visit_id': new_visit.visit_id, 'message': 'New visit created'}), 201
@api.route('/patients/<string:patient_id>/visits', methods=['GET'])
@jwt_required()
def get_patient_visits(patient_id):
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 10, type=int)
    
    visits = Visit.query.filter_by(patient_id=patient_id).order_by(Visit.visit_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    visits_data = []
    for visit in visits.items:
        visit_data = {
            'visit_id': visit.visit_id,
            'visit_date': visit.visit_date.isoformat(),
            'image_count': len(visit.images),
            'diagnosis_status': 'Pending' if any(image.processing_status != 'completed' for image in visit.images) else 'Complete',
            'diagnosis_results': [{'parasite_name': result.parasite_name, 'status': result.status} for result in visit.diagnosis_results]
        }
        visits_data.append(visit_data)
    
    return jsonify({
        'visits': visits_data,
        'total_pages': visits.pages,
        'current_page': page,
        'total_visits': visits.total
    }), 200
@api.route('/visits/<int:visit_id>', methods=['PUT'])
@jwt_required()
def update_visit(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    data = request.get_json()
    
    for key, value in data.items():
        if hasattr(visit, key):
            setattr(visit, key, value)
    
    db.session.commit()
    return jsonify({'message': 'Visit updated successfully', 'visit': visit_schema.dump(visit)}), 200

@api.route('/visits/<int:visit_id>', methods=['DELETE'])
@jwt_required()
def delete_visit(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    db.session.delete(visit)
    db.session.commit()
    return jsonify({'message': 'Visit deleted successfully'}), 200

@api.route('/visits/<int:visit_id>/status', methods=['GET'])
@jwt_required()
def get_visit_status(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    images = Image.query.filter_by(visit_id=visit_id).all()
    
    image_statuses = [{'image_id': img.image_id, 'status': img.processing_status} for img in images]
    
    return jsonify({
        'visit_id': visit_id,
        'visit_status': visit.status,
        'image_statuses': image_statuses
    }), 200

from app.performance_monitor import (
    track_performance, PerformanceTracker, track_db_query,
    PerformanceMetric, get_performance_stats
)
from flask import g
import time

# Update the upload_visit_images route
  
@api.route('/visits/<int:visit_id>/images', methods=['POST'])
@jwt_required()
@track_performance(metric_type='upload')
def upload_visit_images(visit_id):
    # Track upload start time from frontend (if provided)
    upload_start_client = request.form.get('upload_start_time')
    if upload_start_client:
        client_upload_time = time.time() - (float(upload_start_client) / 1000)
        g.client_upload_time = client_upload_time
    
    visit = Visit.query.get_or_404(visit_id)

    if 'images' not in request.files:
        return jsonify({"error": "No images provided"}), 400

    images = request.files.getlist('images')
    
    # Track file sizes
    total_file_size = sum(image.content_length for image in images if image.content_length)
    g.total_file_size = total_file_size
    g.num_images = len(images)
    
    existing_images_count = Image.query.filter_by(visit_id=visit_id).count()

    # Updated maximum limit from 5 to 10 images
    if len(images) + existing_images_count > 10:
        return jsonify({"error": f"Maximum 10 images allowed per visit. This visit already has {existing_images_count} images."}), 400

    smear_types = request.form.getlist('smear_type')
    test_types = request.form.getlist('test_type')

    if len(smear_types) != len(images) or len(test_types) != len(images):
        return jsonify({"error": "Mismatch in number of smear types or test types"}), 400

    uploaded_images = []

    try:
        with PerformanceTracker("image_saving"):
            for idx, image in enumerate(images):
                if not allowed_file(image.filename):
                    logging.warning(f"Rejected file: {image.filename}")
                    continue
                
                logging.info(f"Processing image: {image.filename}, {image.content_type}, {image.content_length}")
                
                # Track individual image save time
                with PerformanceTracker(f"save_image_{idx}"):
                    file_path = save_image(image, current_app.config['UPLOAD_FOLDER'])
                
                if file_path:
                    new_image = Image(
                        visit_id=visit_id,
                        file_path=file_path,
                        smear_type=smear_types[idx],
                        test_type=test_types[idx],
                        processing_status='queued'
                    )
                    db.session.add(new_image)
                    uploaded_images.append(new_image)
                    logging.info(f"Successfully processed and saved image: {image.filename}")
                else:
                    logging.warning(f"Failed to save image: {image.filename}")

        if uploaded_images:
            with PerformanceTracker("database_commit"):
                db.session.commit()
            
            # Mark upload end time
            g.upload_end = time.time()
            
            # Save performance metrics
            if hasattr(g, 'request_id'):
                metric = PerformanceMetric.query.filter_by(request_id=g.request_id).first()
                if metric:
                    metric.visit_id = visit_id
                    metric.file_size = total_file_size
                    metric.num_images = len(uploaded_images)
                    metric.metadata = {
                        'client_upload_time': getattr(g, 'client_upload_time', None),
                        'operation_times': getattr(g, 'operation_times', {})
                    }
                    db.session.commit()

            new_total_image_count = existing_images_count + len(uploaded_images)

            return jsonify({
                "message": f"{len(uploaded_images)} images uploaded successfully.",
                "total_images": new_total_image_count,
                "performance": {
                    "upload_time": g.upload_end - g.upload_start,
                    "request_id": g.request_id
                }
            }), 201
        else:
            return jsonify({"error": "No valid images were uploaded. Allowed formats are PNG, JPG, JPEG, and GIF."}), 400

    except Exception as e:
        current_app.logger.error(f"Error uploading images: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Error uploading images: {str(e)}"}), 500

@api.route('/visits/<int:visit_id>/initiate-diagnosis', methods=['POST'])
@jwt_required()
@track_performance(metric_type='processing')
def initiate_diagnosis(visit_id):
    g.processing_start = time.time()
    
    try:
        visit = Visit.query.get_or_404(visit_id)

        # Track database query time
        with PerformanceTracker("fetch_images"):
            images = Image.query.filter_by(visit_id=visit_id).all()

        if len(images) < 5:
            return jsonify({"error": "At least 5 images are required to start the diagnosis"}), 400

        # Check for existing overall diagnosis
        existing_diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
        if existing_diagnosis:
            return jsonify({
                "message": "Diagnosis has already been performed for this visit",
                "diagnosis": diagnosis_result_schema.dump(existing_diagnosis)
            }), 200

        image_paths = [os.path.abspath(image.file_path) for image in images]
        api_url = current_app.config.get('EXTERNAL_ML_API_URL', 'http://localhost:5002/diagnose')

        # Call external model API
        with PerformanceTracker("model_inference"):
            current_app.logger.info(f"Calling external API at {api_url} with {len(image_paths)} images")
            response = requests.post(api_url, json={'image_paths': image_paths})
            if response.status_code != 200:
                return jsonify({"error": f"Diagnosis API request failed: {response.text}"}), 500
            result = response.json()

        current_app.logger.info(f"Received API response: {result}")

        # Calculate totals using WHO methodology
        total_parasites = 0
        total_wbcs = 0
        
        for detection in result['detections']:
            total_parasites += detection.get('parasite_count', 0)
            total_wbcs += detection.get('white_blood_cells_detected', 0)

        # WHO Formula: Parasites/μL = (Number of parasites counted × 8000) / Number of white cells counted
        if total_wbcs == 0:
            return jsonify({"error": "No white blood cells detected for density calculation"}), 400
            
        parasite_density = (total_parasites * 8000) / total_wbcs
        
        # Validate counting criteria according to WHO SOP
        counting_valid = validate_who_counting_criteria(total_parasites, total_wbcs)
        if not counting_valid['valid']:
            current_app.logger.warning(f"WHO counting criteria not met: {counting_valid['message']}")
        
        severity_level = classify_severity(parasite_density)
        status = 'positive' if result['status'] in ['POSITIVE', 'POS'] else 'negative'

        parasite_info = result.get('most_probable_parasite', result.get('parasite name', {}))
        parasite_type = parasite_info.get('type') if parasite_info else None
        confidence = parasite_info.get('confidence', 0) * 100 if parasite_info else 0

        with PerformanceTracker("save_diagnosis_results"):
            # Save overall diagnosis
            overall_diagnosis = DiagnosisResult(
                visit_id=visit_id,
                image_id=None,
                parasite_name=parasite_type,
                average_confidence=confidence,
                count=total_parasites,
                severity_level=severity_level,
                status=status,
                parasite_density=round(parasite_density, 1),  # Round to 1 decimal place per WHO
                total_wbcs=total_wbcs
            )
            db.session.add(overall_diagnosis)

            # Save individual diagnoses and metadata
            for image, detection in zip(images, result['detections']):
                image_diagnosis = DiagnosisResult(
                    visit_id=visit_id,
                    image_id=image.image_id,
                    count=detection.get('parasite_count', 0),
                    wbc_count=detection.get('white_blood_cells_detected', 0)
                )
                db.session.add(image_diagnosis)

                metadata = Metadata(
                    entity_id=image.image_id,
                    entity_type='image',
                    key='detection_data',
                    value=json.dumps(detection)
                )
                db.session.add(metadata)

                image.processing_status = 'completed'

            visit.status = 'completed'
            db.session.commit()

        # Mark processing end time
        g.processing_end = time.time()
        processing_time = g.processing_end - g.processing_start

        # Notify doctors
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.user_id, f"Diagnosis results ready for visit ID: {visit_id}")

        # Fetch all diagnoses
        saved_overall = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
        saved_individual = DiagnosisResult.query.filter(
            DiagnosisResult.visit_id == visit_id,
            DiagnosisResult.image_id != None
        ).all()

        # Save performance metrics
        if hasattr(g, 'request_id'):
            metric = PerformanceMetric.query.filter_by(request_id=g.request_id).first()
            if metric:
                metric.visit_id = visit_id
                metric.processing_time = processing_time
                metric.metadata = {
                    'num_images': len(images),
                    'model_confidence': confidence,
                    'parasite_count': total_parasites,
                    'total_wbcs': total_wbcs,
                    'parasite_density': parasite_density,
                    'counting_validation': counting_valid,
                    'operation_times': getattr(g, 'operation_times', {})
                }
                db.session.commit()

        return jsonify({
            "message": "Diagnosis process completed successfully",
            "overall_diagnosis": diagnosis_result_schema.dump(saved_overall),
            "image_diagnoses": diagnosis_results_schema.dump(saved_individual),
            "summary": {
                "dominant_parasite": parasite_type,
                "average_confidence": confidence,
                "total_parasites": total_parasites,
                "parasite_density": round(parasite_density, 1),
                "severity": severity_level,
                "total_wbcs": total_wbcs,
                "counting_validation": counting_valid
            },
            "performance": {
                "processing_time": processing_time,
                "request_id": g.request_id
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        import traceback
        current_app.logger.error(f"Error initiating diagnosis: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": f"Error initiating diagnosis: {str(e)}"}), 500


def validate_who_counting_criteria(parasite_count, wbc_count):
    """
    Validate counting meets WHO SOP MM-09 criteria
    """
    if parasite_count >= 100 and wbc_count >= 200:
        return {
            "valid": True,
            "message": f"Valid: {parasite_count} parasites in {wbc_count} WBCs (≥100 parasites in ≥200 WBCs)",
            "method": "high_parasitemia"
        }
    elif parasite_count <= 99 and wbc_count >= 500:
        return {
            "valid": True,
            "message": f"Valid: {parasite_count} parasites in {wbc_count} WBCs (≤99 parasites in ≥500 WBCs)",
            "method": "low_parasitemia"
        }
    else:
        return {
            "valid": False,
            "message": f"Invalid count: {parasite_count} parasites, {wbc_count} WBCs. WHO requires either ≥100 parasites in ≥200 WBCs OR ≤99 parasites in ≥500 WBCs",
            "method": "insufficient_count"
        }


def classify_severity(parasite_density):
    """
    Classify severity according to WHO guidelines
    """
    if parasite_density < 1000:
        return "Mild"
    elif 1000 <= parasite_density <= 10000:
        return "Moderate"
    else:
        return "Severe"


# New endpoint for performance analytics
@api.route('/analytics/performance', methods=['GET'])
@jwt_required()
def get_performance_analytics():
    """Get performance analytics data"""
    endpoint = request.args.get('endpoint')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Convert date strings to datetime objects
    if start_date:
        start_date = datetime.fromisoformat(start_date)
    if end_date:
        end_date = datetime.fromisoformat(end_date)
    
    stats = get_performance_stats(endpoint, start_date, end_date)
    
    if not stats:
        return jsonify({"message": "No performance data available"}), 404
    
    # Get recent metrics for chart
    recent_metrics = PerformanceMetric.query.filter(
        PerformanceMetric.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).order_by(PerformanceMetric.timestamp.desc()).limit(100).all()
    
    return jsonify({
        "statistics": stats,
        "recent_metrics": [m.to_dict() for m in recent_metrics],
        "endpoints": {
            "upload": "/visits/<visit_id>/images",
            "diagnosis": "/visits/<visit_id>/initiate-diagnosis"
        }
    })


# New endpoint for real-time performance monitoring
@api.route('/analytics/performance/realtime', methods=['GET'])
@jwt_required()
def get_realtime_performance():
    """Get real-time performance metrics"""
    # Get metrics from the last 5 minutes
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    
    metrics = PerformanceMetric.query.filter(
        PerformanceMetric.timestamp >= five_minutes_ago
    ).order_by(PerformanceMetric.timestamp.desc()).all()
    
    # Calculate current stats
    if metrics:
        upload_times = [m.upload_time for m in metrics if m.upload_time and m.endpoint.endswith('/images')]
        processing_times = [m.processing_time for m in metrics if m.processing_time and m.endpoint.endswith('/initiate-diagnosis')]
        
        current_stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "upload": {
                "avg": sum(upload_times) / len(upload_times) if upload_times else 0,
                "count": len(upload_times)
            },
            "processing": {
                "avg": sum(processing_times) / len(processing_times) if processing_times else 0,
                "count": len(processing_times)
            },
            "total_requests": len(metrics),
            "error_count": len([m for m in metrics if m.status_code != 200])
        }
    else:
        current_stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "upload": {"avg": 0, "count": 0},
            "processing": {"avg": 0, "count": 0},
            "total_requests": 0,
            "error_count": 0
        }
    
    return jsonify(current_stats)
def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    is_allowed = '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    if not is_allowed:
        logging.warning(f"Rejected file: {filename}")
    return is_allowed
@api.route('/visits/<int:visit_id>/image-count', methods=['GET'])
@jwt_required()
def get_visit_image_count(visit_id):
    count = Image.query.filter_by(visit_id=visit_id).count()
    return jsonify({"count": count}), 200



import requests
import os


@api.route('/analytics/client-metrics', methods=['POST'])
@jwt_required()
def receive_client_metrics():
    """Receive and correlate client-side performance metrics with server metrics"""
    try:
        data = request.get_json()
        client_metrics = data.get('clientMetrics')
        server_request_id = data.get('serverRequestId')
        
        if not client_metrics:
            return jsonify({'error': 'No client metrics provided'}), 400
        
        # Find the corresponding server metric if request ID provided
        server_metric = None
        if server_request_id:
            server_metric = PerformanceMetric.query.filter_by(
                request_id=server_request_id
            ).first()
        
        # Create a correlated metric entry
        correlated_metric = PerformanceMetric(
            endpoint=f"client-{client_metrics.get('type', 'unknown')}",
            method='CLIENT',
            request_id=client_metrics.get('id'),
            user_id=get_jwt_identity().get('user_id'),
            visit_id=client_metrics.get('metadata', {}).get('visitId'),
            total_time=client_metrics.get('duration', 0) / 1000,  # Convert to seconds
            status_code=200 if client_metrics.get('status') == 'success' else 500,
            metadata={
                'client_metrics': client_metrics,
                'server_request_id': server_request_id,
                'steps': client_metrics.get('steps', []),
                'marks': dict(client_metrics.get('marks', {})) if hasattr(client_metrics.get('marks', {}), 'items') else {},
                'correlation': {
                    'has_server_metric': server_metric is not None,
                    'server_upload_time': server_metric.upload_time if server_metric else None,
                    'server_processing_time': server_metric.processing_time if server_metric else None,
                    'end_to_end_time': (client_metrics.get('duration', 0) / 1000) if client_metrics else None
                }
            }
        )
        
        # Extract specific timings if available
        if client_metrics.get('type') == 'image-upload':
            # Calculate network time (total client time - server processing time)
            if server_metric and server_metric.upload_time:
                network_time = (client_metrics.get('duration', 0) / 1000) - server_metric.upload_time
                correlated_metric.metadata['network_time'] = network_time
        
        db.session.add(correlated_metric)
        db.session.commit()
        
        # Emit real-time update if significant
        if client_metrics.get('duration', 0) > 5000:  # More than 5 seconds
            notify_slow_operation(
                endpoint=client_metrics.get('type', 'unknown'),
                duration=client_metrics.get('duration', 0),
                operation_type='client'
            )
        
        return jsonify({
            'message': 'Client metrics received',
            'correlation_id': correlated_metric.id
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error processing client metrics: {str(e)}")
        return jsonify({'error': 'Failed to process client metrics'}), 500


@api.route('/analytics/performance/summary', methods=['GET'])
@jwt_required()
def get_performance_summary():
    """Get a comprehensive performance summary combining client and server metrics"""
    try:
        # Get time range from query params
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Query both server and client metrics
        all_metrics = PerformanceMetric.query.filter(
            PerformanceMetric.timestamp >= since
        ).all()
        
        # Separate client and server metrics
        server_metrics = [m for m in all_metrics if m.method != 'CLIENT']
        client_metrics = [m for m in all_metrics if m.method == 'CLIENT']
        
        # Calculate statistics
        summary = {
            'time_range': f'{hours} hours',
            'server': {
                'total_requests': len(server_metrics),
                'avg_response_time': sum(m.total_time for m in server_metrics) / len(server_metrics) if server_metrics else 0,
                'error_rate': len([m for m in server_metrics if m.status_code != 200]) / len(server_metrics) if server_metrics else 0,
                'by_endpoint': {}
            },
            'client': {
                'total_operations': len(client_metrics),
                'avg_duration': sum(m.total_time for m in client_metrics) / len(client_metrics) if client_metrics else 0,
                'by_type': {}
            },
            'combined': {
                'total_interactions': len(all_metrics),
                'slow_operations': len([m for m in all_metrics if m.total_time > 5]),
                'peak_hour': None
            }
        }
        
        # Group server metrics by endpoint
        from collections import defaultdict
        endpoint_groups = defaultdict(list)
        for metric in server_metrics:
            endpoint_groups[metric.endpoint].append(metric)
        
        for endpoint, metrics in endpoint_groups.items():
            summary['server']['by_endpoint'][endpoint] = {
                'count': len(metrics),
                'avg_time': sum(m.total_time for m in metrics) / len(metrics),
                'error_count': len([m for m in metrics if m.status_code != 200])
            }
        
        # Group client metrics by type
        type_groups = defaultdict(list)
        for metric in client_metrics:
            op_type = metric.metadata.get('client_metrics', {}).get('type', 'unknown')
            type_groups[op_type].append(metric)
        
        for op_type, metrics in type_groups.items():
            summary['client']['by_type'][op_type] = {
                'count': len(metrics),
                'avg_duration': sum(m.total_time for m in metrics) / len(metrics),
                'success_rate': len([m for m in metrics if m.status_code == 200]) / len(metrics) if metrics else 0
            }
        
        # Find peak hour
        hour_groups = defaultdict(int)
        for metric in all_metrics:
            hour = metric.timestamp.strftime('%Y-%m-%d %H:00')
            hour_groups[hour] += 1
        
        if hour_groups:
            peak_hour = max(hour_groups.items(), key=lambda x: x[1])
            summary['combined']['peak_hour'] = {
                'hour': peak_hour[0],
                'request_count': peak_hour[1]
            }
        
        return jsonify(summary), 200
        
    except Exception as e:
        current_app.logger.error(f"Error generating performance summary: {str(e)}")
        return jsonify({'error': 'Failed to generate performance summary'}), 500


# WebSocket event for requesting specific performance data
@socketio.on('request_performance_analysis')
def handle_performance_analysis_request(data):
    """Analyze performance for specific operations or time periods"""
    try:
        analysis_type = data.get('type', 'general')
        params = data.get('params', {})
        
        if analysis_type == 'upload_performance':
            # Analyze upload performance
            visit_id = params.get('visitId')
            metrics = PerformanceMetric.query.filter(
                PerformanceMetric.visit_id == visit_id,
                PerformanceMetric.endpoint.like('%/images%')
            ).all()
            
            analysis = {
                'visit_id': visit_id,
                'upload_count': len(metrics),
                'avg_upload_time': sum(m.upload_time for m in metrics if m.upload_time) / len([m for m in metrics if m.upload_time]) if metrics else 0,
                'total_files': sum(m.num_images for m in metrics if m.num_images) or 0,
                'total_size': sum(m.file_size for m in metrics if m.file_size) or 0
            }
            
        elif analysis_type == 'diagnosis_performance':
            # Analyze diagnosis performance
            visit_id = params.get('visitId')
            metrics = PerformanceMetric.query.filter(
                PerformanceMetric.visit_id == visit_id,
                PerformanceMetric.endpoint.like('%/initiate-diagnosis%')
            ).all()
            
            analysis = {
                'visit_id': visit_id,
                'diagnosis_count': len(metrics),
                'avg_processing_time': sum(m.processing_time for m in metrics if m.processing_time) / len([m for m in metrics if m.processing_time]) if metrics else 0,
                'success_rate': len([m for m in metrics if m.status_code == 200]) / len(metrics) if metrics else 0
            }
            
        else:
            # General analysis
            analysis = {
                'message': 'General performance analysis',
                'total_metrics': PerformanceMetric.query.count()
            }
        
        emit('performance_analysis_result', {
            'type': analysis_type,
            'analysis': analysis,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        emit('performance_analysis_error', {
            'error': str(e)
        })   

import cv2
import numpy as np
import os
import json
import logging
from flask import current_app
from datetime import datetime

logger = logging.getLogger(__name__)

def draw_bounding_boxes(image_path, detection_data):
    """
    Draw bounding boxes on an image based on detection data from the ML API.
    
    Args:
        image_path (str): Path to the original image
        detection_data (dict): Detection data from the ML API
        
    Returns:
        str: Path to the annotated image
    """
    try:
        # Ensure image path is absolute
        if not os.path.isabs(image_path):
            image_path = os.path.abspath(image_path)
            
        # Log current working directory and image path for debugging
        logger.info(f"Current working directory: {os.getcwd()}")
        logger.info(f"Attempting to process image: {image_path}")
        
        # Validate that image exists
        if not os.path.exists(image_path):
            logger.error(f"Image not found: {image_path}")
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.path.dirname(image_path), 'annotated')
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate output filename
        base_filename = os.path.basename(image_path)
        filename, ext = os.path.splitext(base_filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        output_path = os.path.join(output_dir, f"{filename}_annotated_{timestamp}{ext}")
        
        # Read the image
        logger.info(f"Reading image from: {image_path}")
        img = cv2.imread(image_path)
        if img is None:
            logger.error(f"Failed to read image: {image_path}")
            raise ValueError(f"Failed to read image: {image_path}")
        
        # Get image dimensions
        height, width, _ = img.shape
        logger.info(f"Image dimensions: {width}x{height}")
        
        # Define colors for different types
        colors = {
            'PF': (0, 0, 255),    # Red for P. falciparum (BGR format)
            'PV': (0, 255, 255),  # Yellow for P. vivax
            'PM': (255, 0, 0),    # Blue for P. malariae
            'PO': (0, 255, 0),    # Green for P. ovale
            'WBC': (255, 0, 255), # Purple for white blood cells
            'default': (255, 255, 255)  # White for unknown
        }
        
        # Log detection data structure
        logger.info(f"Detection data: {detection_data}")
        logger.info(f"Number of parasites in detection data: {len(detection_data.get('parasites_detected', []))}")
        logger.info(f"Number of WBCs in detection data: {detection_data.get('white_blood_cells_detected', 0)}")
        
        # Add info banner at the top
        info_height = 40
        canvas = np.zeros((height + info_height, width, 3), dtype=np.uint8)
        canvas[info_height:, :] = img  # Add the original image below the info banner
        canvas[:info_height, :] = (240, 240, 240)  # Light gray banner
        
        # Add detection summary to banner
        parasite_count = detection_data.get('parasite_count', 0)
        wbc_count = detection_data.get('white_blood_cells_detected', 0)
        
        # Check for different API response formats
        if 'parasites_detected' in detection_data:
            logger.info("Using 'parasites_detected' format")
            parasites = detection_data.get('parasites_detected', [])
        else:

            logger.info("Using alternate format")
            # Try alternate format
            parasites = []
            for key in detection_data:
                if isinstance(detection_data[key], dict) and 'bbox' in detection_data[key]:
                    parasites.append(detection_data[key])
        
        # Add text to banner
        cv2.putText(
            canvas, 
            f"Parasites: {parasite_count}   WBCs: {wbc_count}", 
            (10, 25), 
            cv2.FONT_HERSHEY_SIMPLEX, 
            0.7, 
            (0, 0, 0), 
            2
        )
        
        # Process parasites detected
        if parasites:
            logger.info(f"Processing {len(parasites)} parasites")
            # In your visualization_utils.py, inside the parasites loop:
            logger.info(f"Parasite: {parasite}, has valid bbox: {bbox is not None and len(bbox) == 4}")
            for parasite in parasites:
                # Safely extract bbox
                bbox = None
                if isinstance(parasite, dict):
                    bbox = parasite.get('bbox')
                
                if not bbox or len(bbox) != 4:
                    logger.warning(f"Invalid bbox in parasite: {parasite}")
                    continue
                
                # Extract coordinates
                x1, y1, x2, y2 = map(int, bbox)
                
                # Adjust Y coordinates for the info banner
                y1 += info_height
                y2 += info_height
                
                # Determine type and get color
                p_type = parasite.get('type', 'default')
                confidence = parasite.get('confidence', 0.0)
                color = colors.get(p_type, colors['default'])
                
                # Draw bounding box
                cv2.rectangle(canvas, (x1, y1), (x2, y2), color, 2)
                
                # Create label with type and confidence
                label = f"{p_type}: {confidence:.2f}"
                
                # Draw background for text
                (text_width, text_height), _ = cv2.getTextSize(
                    label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1
                )
                
                # Draw text background
                cv2.rectangle(
                    canvas,
                    (x1, y1 - text_height - 5),
                    (x1 + text_width + 5, y1),
                    color,
                    -1  # Filled rectangle
                )
                
                # Draw text label
                cv2.putText(
                    canvas,
                    label,
                    (x1, y1 - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    (255, 255, 255),  # White text
                    1
                )
        
        # Process WBCs if they have bounding boxes
        # Some API responses might include WBC bounding boxes
        if 'wbc_bboxes' in detection_data:
            wbc_bboxes = detection_data.get('wbc_bboxes', [])
            logger.info(f"Processing {len(wbc_bboxes)} WBCs with bboxes")
            
            for bbox in wbc_bboxes:
                if not bbox or len(bbox) != 4:
                    continue
                
                # Extract coordinates
                x1, y1, x2, y2 = map(int, bbox)
                
                # Adjust Y coordinates for the info banner
                y1 += info_height
                y2 += info_height
                
                # Draw rectangle for WBC
                color = colors['WBC']
                cv2.rectangle(canvas, (x1, y1), (x2, y2), color, 2)
                
                # Add WBC label
                cv2.putText(
                    canvas,
                    "WBC",
                    (x1, y1 - 5),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    color,
                    1
                )
        
        # Save the annotated image
        logger.info(f"Saving annotated image to: {output_path}")
        cv2.imwrite(output_path, canvas)
        
        return output_path
        
    except Exception as e:
        logger.error(f"Error in draw_bounding_boxes: {str(e)}")
        # Re-raise the exception to be handled by the caller
        raise

@api.route('/images/<int:image_id>/with-detections', methods=['GET'])
# @jwt_required()
def get_image_with_detections(image_id):
    """
    Generates and returns an image with bounding boxes for detected parasites
    """
    try:
        # Get the image
        image = Image.query.get_or_404(image_id)
        
        # Check if we need to generate or regenerate the image
        force_regenerate = request.args.get('force', 'false').lower() == 'true'
        
        # First check if we already have an annotated version
        if not force_regenerate:
            # Look for existing annotated image
            base_path = os.path.dirname(image.file_path)
            annotated_dir = os.path.join(base_path, 'annotated')
            base_filename = os.path.basename(image.file_path)
            filename, ext = os.path.splitext(base_filename)
            
            # Look for any annotated version of this image
            if os.path.exists(annotated_dir):
                existing_files = [f for f in os.listdir(annotated_dir) if f.startswith(f"{filename}_annotated_")]
                if existing_files:
                    # Use the most recent one
                    existing_files.sort(reverse=True)
                    annotated_path = os.path.join(annotated_dir, existing_files[0])
                    return send_file(annotated_path)
        
        # No existing annotated image found, or force regenerate is True
        
        # Retrieve the detection data from metadata
        metadata = Metadata.query.filter_by(
            entity_id=image_id,
            entity_type='image',
            key='detection_data'
        ).first()
        
        if not metadata:
            return jsonify({"error": "No detection data found for this image"}), 404
        
        # Parse the detection data
        detection_data = json.loads(metadata.value)
        
        # Import the visualization utility
        from .visualization_utils import draw_bounding_boxes
        
        # Generate the annotated image
        annotated_path = draw_bounding_boxes(image.file_path, detection_data)
        
        # Return the annotated image
        return send_file(annotated_path)
        
    except FileNotFoundError as e:
        current_app.logger.error(f"File not found: {str(e)}")
        return jsonify({"error": "Image file not found"}), 404
        
    except Exception as e:
        current_app.logger.error(f"Error generating image with detections: {str(e)}")
        return jsonify({"error": f"Failed to generate annotated image: {str(e)}"}), 500
    
@api.route('/visits/<int:visit_id>/detection-summary', methods=['GET'])
@jwt_required()
def get_visit_detection_summary(visit_id):
    """
    Returns summary of detections for all images in a visit
    """
    try:
        # Get all images for this visit
        images = Image.query.filter_by(visit_id=visit_id).all()
        
        if not images:
            return jsonify({"error": "No images found for this visit"}), 404
        
        # Get the diagnosis result for this visit
        diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
        
        # Prepare the summary
        summary = {
            "visit_id": visit_id,
            "diagnosis_status": diagnosis.status if diagnosis else "pending",
            "parasite_name": diagnosis.parasite_name if diagnosis else None,
            "confidence": diagnosis.average_confidence if diagnosis else None,
            "severity": diagnosis.severity_level if diagnosis else None,
            "parasite_density": diagnosis.parasite_density if diagnosis else None,
            "total_parasites": diagnosis.count if diagnosis else 0,
            "total_wbcs": diagnosis.total_wbcs if diagnosis else 0,
            "images": []
        }
        
        # Get detection data for each image
        for image in images:
            image_data = {
                "image_id": image.image_id,
                "file_path": image.file_path,
                "smear_type": image.smear_type,
                "test_type": image.test_type,
                "processing_status": image.processing_status
            }
            
            # Get image diagnosis
            image_diagnosis = DiagnosisResult.query.filter_by(
                visit_id=visit_id, 
                image_id=image.image_id
            ).first()
            
            if image_diagnosis:
                image_data["parasite_count"] = image_diagnosis.count
                image_data["wbc_count"] = image_diagnosis.wbc_count
            
            # Get detection metadata if it exists
            metadata = Metadata.query.filter_by(
                entity_id=image.image_id,
                entity_type='image',
                key='detection_data'
            ).first()
            
            if metadata:
                detection_data = json.loads(metadata.value)
                
                # Add basic detection info (without full bounding box data to reduce payload size)
                image_data["detections"] = {
                    "parasite_count": detection_data.get("parasite_count", 0),
                    "wbc_count": detection_data.get("white_blood_cells_detected", 0),
                    "parasites": [
                        {
                            "type": p.get("type"),
                            "confidence": p.get("confidence")
                        } for p in detection_data.get("parasites_detected", [])
                    ]
                }
            
            # Add annotated image URL
            image_data["annotated_image_url"] = url_for(
                'api.get_image_with_detections',
                image_id=image.image_id,
                _external=True
            )
            
            summary["images"].append(image_data)
        
        return jsonify(summary)
        
    except Exception as e:
        current_app.logger.error(f"Error getting detection summary: {str(e)}")
        return jsonify({"error": f"Failed to get detection summary: {str(e)}"}), 500

@api.route('/images', methods=['GET'])
@jwt_required()
def get_images():
    images = Image.query.all()
    result = images_schema.dump(images)  # Use dump instead of jsonify
    return jsonify(result)  # Return the result using Flask's jsonify

@api.route('/images/<int:image_id>', methods=['GET'])
@jwt_required()
def get_image(image_id):
    image = Image.query.get_or_404(image_id)
    result = image_schema.dump(image)  # Use dump instead of jsonify
    return jsonify(result)  # Return the result using Flask's jsonify

@api.route('/images/<int:image_id>', methods=['PUT'])
@jwt_required()
def update_image(image_id):
    data = request.get_json()
    image = Image.query.get_or_404(image_id)
    image = image_schema.load(data, instance=image, partial=True)
    db.session.commit()
    return jsonify({'message': 'Image updated successfully!'})

@api.route('/images/<int:image_id>', methods=['DELETE'])
@jwt_required()
def delete_image(image_id):
    image = Image.query.get_or_404(image_id)
    db.session.delete(image)
    db.session.commit()
    return jsonify({'message': 'Image deleted successfully!'})


@api.route('/dashboard/stats', methods=['GET'])
@jwt_required()
@cache_query
@monitor_query_performance
def get_dashboard_stats():
    yesterday = datetime.now() - timedelta(days=1)

    query = f"""
    WITH 
    total_patients AS (
        SELECT COUNT(*) AS count FROM patients
    ),
    pending_results AS (
        SELECT COUNT(*) AS count 
        FROM images i
        LEFT JOIN diagnosis_results dr ON i.image_id = dr.image_id
        WHERE dr.result_id IS NULL
    ),
    diagnosis_distribution AS (
        SELECT status, COUNT(*) AS count
        FROM diagnosis_results
        WHERE severity_level IS NOT NULL
        GROUP BY status
    ),
    completed_diagnoses AS (
        SELECT COUNT(*) AS count 
        FROM diagnosis_results 
        WHERE severity_level IS NOT NULL
    ),
    new_diagnoses AS (
        SELECT COUNT(*) AS count 
        FROM diagnosis_results 
        WHERE created_at >= '{yesterday.isoformat()}'
        AND severity_level IS NOT NULL
    )
    SELECT 
        (SELECT count FROM total_patients) AS total_patients,
        (SELECT count FROM pending_results) AS pending_results,
        (SELECT count FROM completed_diagnoses) AS completed_diagnoses,
        (SELECT count FROM new_diagnoses) AS new_diagnoses,
        (SELECT json_object_agg(status, count) FROM diagnosis_distribution) AS diagnosis_distribution
    """

    optimized_query = optimize_query(query)
    result = db.session.execute(text(optimized_query)).fetchone()

    # Log the result structure
    logging.info(f'Result: {result}')

    if not result or any(value is None for value in result):
        logging.error(f"Some values are None in the result: {result}")
        return jsonify({"error": "No data found"}), 404

    # Convert RowProxy to a dictionary
    stats = {
        'total_patients': result[0],
        'pending_results': result[1],
        'completed_diagnoses': result[2],
        'new_diagnoses': result[3],
        'diagnosis_distribution': result[4],
    }

    # Log the processed stats
    logging.info(f"Processed Stats: {stats}")

    # Convert diagnosis_distribution from JSON to Python dict and add pending_results to 'inconclusive'
    diagnosis_distribution = stats['diagnosis_distribution'] or {}
    if isinstance(diagnosis_distribution, str):
        import json
        diagnosis_distribution = json.loads(diagnosis_distribution)  # Convert from JSON string to dict if necessary
    diagnosis_distribution['inconclusive'] = diagnosis_distribution.get('inconclusive', 0) + stats['pending_results']
    stats['diagnosis_distribution'] = diagnosis_distribution

    return jsonify(stats)

@api.route('/dashboard/chart-data', methods=['GET'])
@jwt_required()
def get_chart_data():
    # Pie chart data for aggregated results (where severity level is present)
    pie_data = db.session.query(
        DiagnosisResult.status,
        func.count(DiagnosisResult.status)
    ).filter(DiagnosisResult.severity_level != None)\
    .group_by(DiagnosisResult.status).all()

    # Create the pie chart data (ignoring 'inconclusive' or NULL)
    pie_chart_data = [{'name': status, 'value': count} for status, count in pie_data if status and status != 'inconclusive']

    # Line chart data for diagnoses in the past 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    line_data = db.session.query(
        func.date(DiagnosisResult.result_date).label('date'),
        func.count(DiagnosisResult.result_id).label('count')
    ).filter(DiagnosisResult.severity_level != None)\
    .filter(DiagnosisResult.result_date >= thirty_days_ago)\
    .group_by(func.date(DiagnosisResult.result_date))\
    .order_by(func.date(DiagnosisResult.result_date)).all()

    # Prepare the line chart data
    line_chart_data = [{'name': date.strftime('%Y-%m-%d'), 'newDiagnoses': count} for date, count in line_data]

    return jsonify({
        'pieChartData': pie_chart_data,
        'lineChartData': line_chart_data
    })

@api.route('/patients/search', methods=['GET'])
@jwt_required()
@monitor_query_performance
def search_patients():
    query = request.args.get('query', '')
    status = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    search_query = f"""
    SELECT p.* FROM patients p
    LEFT JOIN visits v ON p.patient_id = v.patient_id
    LEFT JOIN diagnosis_results d ON v.visit_id = d.visit_id AND d.image_id IS NULL
    WHERE p.search_vector @@ plainto_tsquery('english', :query)
    """

    if status:
        search_query += " AND d.status = :status"
    if date_from:
        search_query += " AND p.created_at >= :date_from"
    if date_to:
        search_query += " AND p.created_at <= :date_to"

    search_query += " ORDER BY p.created_at DESC"

    optimized_query = optimize_query(search_query)
    result = db.session.execute(text(optimized_query), {
        'query': query,
        'status': status,
        'date_from': date_from,
        'date_to': date_to
    })

    patients = result.fetchall()
    return jsonify(patients_schema.dump(patients)), 200
@api.route('/patients/advanced-search', methods=['GET'])
@jwt_required()
def advanced_search_patients():
    name = request.args.get('name')
    age_min = request.args.get('age_min', type=int)
    age_max = request.args.get('age_max', type=int)
    gender = request.args.get('gender')
    diagnosis_status = request.args.get('diagnosis_status')
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')

    query = Patient.query

    if name:
        query = query.filter(Patient.name.ilike(f'%{name}%'))
    if age_min:
        query = query.filter(Patient.age >= age_min)
    if age_max:
        query = query.filter(Patient.age <= age_max)
    if gender:
        query = query.filter(Patient.gender == gender)
    if diagnosis_status:
        query = query.join(DiagnosisResult).filter(DiagnosisResult.status == diagnosis_status)

    if sort_order == 'desc':
        query = query.order_by(getattr(Patient, sort_by).desc())
    else:
        query = query.order_by(getattr(Patient, sort_by).asc())

    patients = query.all()
    return jsonify(patients_schema.dump(patients))
from sqlalchemy import func


@api.route('/visits/<int:visit_id>', methods=['GET'])
@jwt_required()
def get_visit_details(visit_id):
    # print(f"Backend: Fetching details for visit_id: {visit_id}")
    visit = Visit.query.get_or_404(visit_id)
    patient = Patient.query.get(visit.patient_id)
    
    visit_data = {
        'visit_id': visit.visit_id,
        'patient_id': patient.patient_id,
        'patient_name': patient.name,
        'gender': patient.gender,
        'age': patient.age,
        'visit_date': visit.visit_date.isoformat(),
        'status': visit.status,
        'reason': visit.reason,
        'symptoms': visit.symptoms,
        'notes': visit.notes,
        'images': [{'image_id': img.image_id, 'file_path': img.file_path} for img in visit.images]
    }
    
    # print(f"Backend: Returning visit data: {visit_data}")
    return jsonify(visit_data)

@api.route('/analytics', methods=['GET'])
@jwt_required()
def get_analytics_data():
    # Get total counts
    total_patients = Patient.query.count()
    total_visits = Visit.query.count()
    total_diagnoses = DiagnosisResult.query.filter(DiagnosisResult.image_id == None).count()

    # Get counts for the last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_patients = Patient.query.filter(Patient.created_at >= thirty_days_ago).count()
    new_visits = Visit.query.filter(Visit.created_at >= thirty_days_ago).count()
    new_diagnoses = DiagnosisResult.query.filter(DiagnosisResult.created_at >= thirty_days_ago, DiagnosisResult.image_id == None).count()

    # Get diagnosis distribution
    diagnosis_distribution = db.session.query(
        DiagnosisResult.parasite_name,
        func.count(DiagnosisResult.result_id)
    ).filter(DiagnosisResult.image_id == None).group_by(DiagnosisResult.parasite_name).all()

    # Get severity distribution
    severity_distribution = db.session.query(
        DiagnosisResult.severity_level,
        func.count(DiagnosisResult.result_id)
    ).filter(DiagnosisResult.image_id == None).group_by(DiagnosisResult.severity_level).all()

    return jsonify({
        'total_patients': total_patients,
        'total_visits': total_visits,
        'total_diagnoses': total_diagnoses,
        'new_patients_last_30_days': new_patients,
        'new_visits_last_30_days': new_visits,
        'new_diagnoses_last_30_days': new_diagnoses,
        'diagnosis_distribution': dict(diagnosis_distribution),
        'severity_distribution': dict(severity_distribution)
    })

@api.route('/diagnoses/pending', methods=['GET'])
@jwt_required()
def get_pending_diagnoses():
    pending_diagnoses = db.session.query(Visit).join(Image).filter(
        Visit.status != 'completed',
        Image.processing_status.in_(['queued', 'processing'])
    ).all()

    result = []
    for visit in pending_diagnoses:
        patient = Patient.query.get(visit.patient_id)
        result.append({
            'visit_id': visit.visit_id,
            'patient_id': patient.patient_id,
            'patient_name': patient.name,
            'visit_date': visit.visit_date.isoformat(),
            'status': visit.status,
            'image_count': Image.query.filter_by(visit_id=visit.visit_id).count()
        })

    return jsonify(result)

@api.route('/visits/<int:visit_id>/diagnosis', methods=['POST'])
@jwt_required()
def submit_diagnosis(visit_id):
    # Implement logic to submit a diagnosis for a visit
    pass

from flask_socketio import emit

@api.route('/visits/<int:visit_id>/diagnosis-results', methods=['GET'])
@jwt_required()
def get_diagnosis_results(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    overall_diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
    image_diagnoses = DiagnosisResult.query.filter(DiagnosisResult.visit_id == visit_id, DiagnosisResult.image_id != None).all()

    if not overall_diagnosis:
        return jsonify({"error": "No diagnosis results found for this visit"}), 404

    result = {
        "overall_diagnosis": diagnosis_result_schema.dump(overall_diagnosis),
        "image_diagnoses": diagnosis_results_schema.dump(image_diagnoses)
    }
    

    return jsonify(result), 200

@api.route('/patients/with-visits', methods=['GET'])
@jwt_required()
def get_patients_with_visits():
    try:
        # Fetch patients and their latest visit details
        patients_with_visits = db.session.query(Patient).join(Visit).all()

        result = []
        
        for patient in patients_with_visits:
            visits = sorted(patient.visits, key=lambda visit: visit.visit_date, reverse=True)
            latest_visit = visits[0] if visits else None
            past_visits = visits[1:] if len(visits) > 1 else []

            patient_data = {
                'patient_id': patient.patient_id,
                'name': patient.name,
                'latest_visit': {
                    'visit_id': latest_visit.visit_id,
                    'date': latest_visit.visit_date.isoformat() if latest_visit else None,
                    'reason': latest_visit.reason,
                    'status': latest_visit.status
                } if latest_visit else None,
                'visit_history': [{
                    'visit_id': visit.visit_id,
                    'date': visit.visit_date.isoformat(),
                    'status': visit.status
                } for visit in past_visits]
            }

            result.append(patient_data)

        return jsonify(result)

    except Exception as e:
        print(f"Error fetching patients with visits: {str(e)}")
        return jsonify({"message": "Error fetching patients with visits"}), 500

from flask import send_file
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus import PageBreak, Flowable, Frame, NextPageTemplate, PageTemplate
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime, timedelta
import os


class HorizontalLine(Flowable):
    """Custom flowable for a horizontal line with custom color and thickness"""
    def __init__(self, width, thickness=1, color=colors.black):
        Flowable.__init__(self)  
        self.width = width
        self.thickness = thickness
        self.color = color

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)


def header_footer(canvas, doc):
    # Save canvas state
    canvas.saveState()
    
    # Header
    header_color = colors.HexColor('#4361ee')
    
    # Draw a colored banner at the top
    canvas.setFillColor(header_color)
    canvas.rect(0, doc.height + doc.topMargin - 0.5*inch, doc.width + doc.leftMargin + doc.rightMargin, 1*inch, fill=1, stroke=0)
    
    # Add hospital name
    canvas.setFont("Helvetica-Bold", 16)
    canvas.setFillColor(colors.white)
    canvas.drawString(doc.leftMargin + 0.1*inch, doc.height + doc.topMargin + 0.4*inch, "MEDICAL DIAGNOSIS CENTER")
    
    # Add header subtitle
    canvas.setFont("Helvetica", 10)
    canvas.drawString(doc.leftMargin + 0.1*inch, doc.height + doc.topMargin + 0.15*inch, "Patient Diagnosis Report")
    
    # Add date at the top right
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(doc.width + doc.leftMargin - 0.1*inch, doc.height + doc.topMargin + 0.15*inch, 
                          f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    # Footer
    canvas.setFillColor(colors.HexColor('#e9ecef'))
    canvas.rect(0, doc.bottomMargin - 0.75*inch, doc.width + doc.leftMargin + doc.rightMargin, 0.75*inch, fill=1, stroke=0)
    
    canvas.setFillColor(colors.HexColor('#495057'))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, doc.bottomMargin - 0.4*inch, 
                     "This report is generated by the Automated Diagnostic System and should be reviewed by a healthcare professional.")
    
    # Add page number - FIXED: using canvas.getPageNumber()
    canvas.setFont("Helvetica", 9)
    page_num = f"Page {canvas.getPageNumber()}" 
    canvas.drawRightString(doc.width + doc.leftMargin - 0.1*inch, doc.bottomMargin - 0.4*inch, page_num)
    
    # Add a line above the footer
    canvas.setStrokeColor(colors.HexColor('#ced4da'))
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, doc.bottomMargin - 0.05*inch, 
                doc.width + doc.leftMargin - 0.1*inch, doc.bottomMargin - 0.05*inch)
    
    # Restore canvas state
    canvas.restoreState()


def get_severity_color(severity_level):
    if severity_level.lower() == 'severe':
        return colors.HexColor('#e63946')  # Red
    elif severity_level.lower() == 'moderate':
        return colors.HexColor('#f4a261')  # Orange
    elif severity_level.lower() == 'mild':
        return colors.HexColor('#40916c')  # Green
    else:
        return colors.HexColor('#6c757d')  # Gray


@api.route('/visits/<int:visit_id>/download-report', methods=['GET'])
@jwt_required()
def download_visit_report(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    patient = Patient.query.get(visit.patient_id)
    diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
    image_diagnoses = DiagnosisResult.query.filter(DiagnosisResult.visit_id==visit_id, 
                                                 DiagnosisResult.image_id.isnot(None)).all()

    # Create a buffer and document
    buffer = BytesIO()
    
    # Set up document with proper margins
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        leftMargin=1*inch,
        rightMargin=1*inch,
        topMargin=1.25*inch,
        bottomMargin=1*inch
    )
    
    # Register header and footer
    template = PageTemplate(id='normal', frames=[Frame(
        doc.leftMargin, doc.bottomMargin, 
        doc.width, doc.height, 
        id='normal'
    )], onPage=header_footer)
    
    doc.addPageTemplates([template])
    
    # Styles setup
    styles = getSampleStyleSheet()
    
    # Add custom styles
    styles.add(ParagraphStyle(
        name='SectionTitle',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#364fc7'),
        spaceAfter=6
    ))
    
    styles.add(ParagraphStyle(
        name='SubTitle',
        parent=styles['Heading3'],
        fontSize=10,
        textColor=colors.HexColor('#495057'),
        spaceAfter=3
    ))
    
    styles.add(ParagraphStyle(
        name='InfoValue',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=3
    ))
    
    styles.add(ParagraphStyle(
        name='InfoLabel',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#6c757d'),
        spaceAfter=1
    ))
    
    # Empty list to hold flowables
    elements = []
    
    # Add title (will be replaced by header function)
    elements.append(Spacer(1, 0.5*inch))
    
    # Add confidential stamp
    elements.append(Paragraph("CONFIDENTIAL MEDICAL RECORD", 
                              ParagraphStyle('Confidential', fontSize=10, textColor=colors.red, alignment=TA_CENTER)))
    elements.append(Spacer(1, 0.3*inch))
    
    # Patient information section
    patient_info_title = Paragraph("Patient Information", styles['SectionTitle'])
    elements.append(patient_info_title)
    
    # Create a horizontal line
    elements.append(HorizontalLine(doc.width, 1, colors.HexColor('#ced4da')))
    elements.append(Spacer(1, 0.1*inch))
    
    # Patient info as a simple table - FIXED VERSION
    patient_data = [
        [
            Paragraph("Name:", styles['InfoLabel']), 
            Paragraph(f"{patient.name}", styles['InfoValue']),
            Paragraph("Patient ID:", styles['InfoLabel']), 
            Paragraph(f"{patient.patient_id}", styles['InfoValue'])
        ],
        [
            Paragraph("Age:", styles['InfoLabel']), 
            Paragraph(f"{patient.age} years", styles['InfoValue']),
            Paragraph("Gender:", styles['InfoLabel']), 
            Paragraph(f"{patient.gender.capitalize()}", styles['InfoValue'])
        ]
    ]
    
    patient_table = Table(patient_data, colWidths=[1.3*inch, doc.width/2-1.3*inch, 1.3*inch, doc.width/2-1.3*inch])
    patient_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    
    elements.append(patient_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Visit information section - FIXED VERSION
    elements.append(Paragraph("Visit Details", styles['SectionTitle']))
    elements.append(HorizontalLine(doc.width, 1, colors.HexColor('#ced4da')))
    elements.append(Spacer(1, 0.1*inch))
    
    visit_data = [
        [
            Paragraph("Visit Date:", styles['InfoLabel']), 
            Paragraph(f"{visit.visit_date.strftime('%Y-%m-%d')}", styles['InfoValue']),
            Paragraph("Visit ID:", styles['InfoLabel']), 
            Paragraph(f"{visit.visit_id}", styles['InfoValue'])
        ]
    ]
    
    visit_table = Table(visit_data, colWidths=[1.3*inch, doc.width/2-1.3*inch, 1.3*inch, doc.width/2-1.3*inch])
    visit_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    
    elements.append(visit_table)
    elements.append(Spacer(1, 0.1*inch))
    
    # Visit reason, symptoms, and notes
    elements.append(Paragraph("Reason for Visit:", styles['SubTitle']))
    elements.append(Paragraph(visit.reason or "Not provided", styles['Normal']))
    elements.append(Spacer(1, 0.1*inch))
    
    elements.append(Paragraph("Symptoms:", styles['SubTitle']))
    elements.append(Paragraph(visit.symptoms or "None reported", styles['Normal']))
    elements.append(Spacer(1, 0.1*inch))
    
    elements.append(Paragraph("Clinical Notes:", styles['SubTitle']))
    elements.append(Paragraph(visit.notes or "No notes provided", styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Diagnosis section
    if diagnosis:
        elements.append(Paragraph("Diagnosis Results", styles['SectionTitle']))
        elements.append(HorizontalLine(doc.width, 1, colors.HexColor('#ced4da')))
        elements.append(Spacer(1, 0.1*inch))
        
        # Get severity info
        severity_color = get_severity_color(diagnosis.severity_level)
        severity_text = diagnosis.severity_level.upper()
        
        # Diagnosis summary - FIXED VERSION
        diagnosis_summary_data = [
            [
                Paragraph("Parasite", styles['SubTitle']), 
                Paragraph("Status", styles['SubTitle']), 
                Paragraph("Confidence", styles['SubTitle']), 
                Paragraph("Severity", styles['SubTitle'])
            ],
            [
                Paragraph(diagnosis.parasite_name, styles['Normal']), 
                Paragraph(diagnosis.status, styles['Normal']), 
                Paragraph(f"{diagnosis.average_confidence:.2f}%", styles['Normal']), 
                Paragraph(severity_text, styles['Normal'])  # Simple text without custom styling
            ]
        ]
        
        # Create table with proper styling
        diagnosis_summary = Table(diagnosis_summary_data, colWidths=[doc.width/4, doc.width/4, doc.width/4, doc.width/4])
        
        # Build the table style
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#495057')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]
        
        # Add severity cell styling
        table_style.append(('BACKGROUND', (3, 1), (3, 1), severity_color))
        table_style.append(('TEXTCOLOR', (3, 1), (3, 1), colors.white))
        
        diagnosis_summary.setStyle(TableStyle(table_style))
        
        elements.append(diagnosis_summary)
        elements.append(Spacer(1, 0.1*inch))
        
        # Detailed diagnosis data
        elements.append(Paragraph("Detailed Analysis", styles['SubTitle']))
        
        # Create header style
        header_style = ParagraphStyle('TableHeader', parent=styles['Normal'], fontName='Helvetica-Bold')
        
        diagnostic_data = [
            [
                Paragraph("Parameter", header_style), 
                Paragraph("Value", header_style)
            ],
            [
                Paragraph("Parasite Count", styles['Normal']), 
                Paragraph(str(diagnosis.count), styles['Normal'])
            ],
            [
                Paragraph("Total WBCs", styles['Normal']), 
                Paragraph(str(diagnosis.total_wbcs), styles['Normal'])
            ],
            [
                Paragraph("Parasite Density", styles['Normal']), 
                Paragraph(f"{diagnosis.parasite_density:.2f} parasites/μL", styles['Normal'])
            ]
        ]
        
        diagnostic_table = Table(diagnostic_data, colWidths=[doc.width/2, doc.width/2])
        diagnostic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e9ecef')),
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#495057')),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ]))
        
        elements.append(diagnostic_table)
        
        # Image diagnoses if available
        if image_diagnoses:
            elements.append(Spacer(1, 0.3*inch))
            elements.append(Paragraph("Individual Image Results", styles['SubTitle']))
            
            # Prepare header row with paragraph objects
            image_data = [
                [
                    Paragraph("Image ID", header_style),
                    Paragraph("Parasite Count", header_style),
                    Paragraph("WBC Count", header_style)
                ]
            ]
            
            # Add data rows with paragraph objects
            for img_diagnosis in image_diagnoses:
                image_data.append([
                    Paragraph(str(img_diagnosis.image_id), styles['Normal']),
                    Paragraph(str(img_diagnosis.count), styles['Normal']),
                    Paragraph(str(img_diagnosis.wbc_count), styles['Normal'])
                ])
            
            img_table = Table(image_data, colWidths=[doc.width/3, doc.width/3, doc.width/3])
            img_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e9ecef')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#495057')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8f9fa'), colors.HexColor('#ffffff')]),
            ]))
            
            elements.append(img_table)
    else:
        elements.append(Paragraph("Diagnosis Results", styles['SectionTitle']))
        elements.append(HorizontalLine(doc.width, 1, colors.HexColor('#ced4da')))
        elements.append(Spacer(1, 0.1*inch))
        elements.append(Paragraph("No diagnosis results available for this visit.", styles['Normal']))
    
    # Disclaimer section
    elements.append(Spacer(1, 0.5*inch))
    elements.append(HorizontalLine(doc.width, 1, colors.HexColor('#ced4da')))
    elements.append(Spacer(1, 0.1*inch))
    
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#6c757d'),
        alignment=TA_LEFT
    )
    
    disclaimer_text = """
    DISCLAIMER: This report is generated by an automated diagnostic system and should be interpreted by a qualified healthcare professional.
    The results provided here are based on computational analysis and may require clinical correlation.
    Please consult with a healthcare provider before making any medical decisions based on this report.
    """
    
    elements.append(Paragraph(disclaimer_text, disclaimer_style))
    
    # Signature section
    elements.append(Spacer(1, 0.5*inch))
    
    signature_style = ParagraphStyle('SignatureLabel', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#6c757d'))
    
    signature_data = [
        [
            Paragraph("", styles['Normal']),
            Paragraph("", styles['Normal'])
        ],
        [
            Paragraph("Physician Signature", signature_style),
            Paragraph("Laboratory Director", signature_style)
        ],
        [
            Paragraph("Date: _______________", signature_style),
            Paragraph("Date: _______________", signature_style)
        ]
    ]
    
    signature_table = Table(signature_data, colWidths=[doc.width/2, doc.width/2])
    signature_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    
    elements.append(signature_table)
    
    # Build the document
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer, 
        as_attachment=True, 
        download_name=f'patient_{patient.patient_id}visit{visit_id}_report.pdf', 
        mimetype='application/pdf'
    )

@api.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    try:
        identity = get_jwt_identity()
        user_id = identity.get('user_id')

        if not user_id:
            current_app.logger.error(f"Invalid JWT token: user_id not found. Identity: {identity}")
            return jsonify({"error": "Invalid JWT token: user id not found"}), 400

        notifications = Notification.query.filter_by(user_id=user_id).all()
        return jsonify([notification_schema.dump(notification) for notification in notifications])
    except Exception as e:
        current_app.logger.error(f"Error in get_notifications: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@api.route('/notifications/<int:notification_id>/mark-read', methods=['POST'])
@jwt_required()
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    notification.read = True
    db.session.commit()
    return jsonify({'message': 'Notification marked as read'})

# Chat Routes

@api.route('/chats', methods=['GET'])
@jwt_required()
def get_chats():
    user_id = get_jwt_identity()['user_id']
    chats = Chat.query.filter_by(user_id=user_id).order_by(Chat.last_message_time.desc()).all()
    dumped_chats = chats_schema.dump(chats)
    print("Dumped chats:", dumped_chats)  # Add this line
    return jsonify(dumped_chats)
@api.route('/chats', methods=['POST'])
@jwt_required()
def create_chat():
    user_id = get_jwt_identity()['user_id']
    data = request.json
    participant_id = data.get('participant_id')
    
    if not participant_id:
        return jsonify({'error': 'Participant ID is required'}), 400

    existing_chat = Chat.query.filter(
        ((Chat.user_id == user_id) & (Chat.participant_id == participant_id)) |
        ((Chat.user_id == participant_id) & (Chat.participant_id == user_id))
    ).first()

    if existing_chat:
        return jsonify({'message': 'Chat already exists', 'chat': chat_schema.dump(existing_chat)}), 200

    new_chat = Chat(user_id=user_id, participant_id=participant_id)
    db.session.add(new_chat)
    db.session.commit()

    return jsonify({'message': 'Chat created successfully', 'chat': chat_schema.dump(new_chat)}), 201

@api.route('/chats/<int:chat_id>/messages', methods=['GET'])
@jwt_required()
def get_chat_messages(chat_id):
    messages = Message.query.filter_by(chat_id=chat_id).order_by(Message.timestamp.asc()).all()
    return jsonify(messages_schema.dump(messages))

@api.route('/chats/<int:chat_id>/messages', methods=['POST'])
@jwt_required()
def send_message(chat_id):
    user_id = get_jwt_identity()['id']
    content = request.json.get('content')
    if not content:
        return jsonify({'error': 'Message content is required'}), 400
    
    chat = Chat.query.get_or_404(chat_id)
    new_message = Message(chat_id=chat_id, sender_id=user_id, content=content)
    db.session.add(new_message)
    
    chat.last_message = content
    chat.last_message_time = datetime.utcnow()
    
    db.session.commit()
    
    message_data = message_schema.dump(new_message)
    socketio.emit('new_message', message_data, room=chat_id)
    
    return jsonify(message_data), 201


@api.route('/diagnosis-trends', methods=['GET'])
@jwt_required()
def get_diagnosis_trends():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = db.session.query(
        func.date(DiagnosisResult.result_date).label('date'),
        DiagnosisResult.parasite_name,
        func.count(DiagnosisResult.id).label('count')
    ).filter(DiagnosisResult.image_id == None)  # Only overall diagnoses
    
    if start_date:
        query = query.filter(DiagnosisResult.result_date >= start_date)
    if end_date:
        query = query.filter(DiagnosisResult.result_date <= end_date)
    
    results = query.group_by(func.date(DiagnosisResult.result_date), DiagnosisResult.parasite_name).all()
    
    trends = {}
    for date, parasite, count in results:
        if date not in trends:
            trends[date] = {}
        trends[date][parasite] = count
    
    return jsonify(trends)

@api.route('/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    total_patients = Patient.query.count()
    total_visits = Visit.query.count()
    total_diagnoses = DiagnosisResult.query.filter(DiagnosisResult.image_id == None).count()
    
    parasite_distribution = db.session.query(
        DiagnosisResult.parasite_name,
        func.count(DiagnosisResult.id).label('count')
    ).filter(DiagnosisResult.image_id == None).group_by(DiagnosisResult.parasite_name).all()
    
    severity_distribution = db.session.query(
        DiagnosisResult.severity_level,
        func.count(DiagnosisResult.id).label('count')
    ).filter(DiagnosisResult.image_id == None).group_by(DiagnosisResult.severity_level).all()
    
    return jsonify({
        'total_patients': total_patients,
        'total_visits': total_visits,
        'total_diagnoses': total_diagnoses,
        'parasite_distribution': dict(parasite_distribution),
        'severity_distribution': dict(severity_distribution)
    })

def create_notification(user_id, message):
    new_notification = Notification(user_id=user_id, message=message)
    db.session.add(new_notification)
    db.session.commit()
    socketio.emit('new_notification', notification_schema.dump(new_notification), room=user_id)


# Example of a function that queries both current and archived data

def get_patient_history(patient_id, include_archived=False):
    # Query current visits
    current_visits = Visit.query.filter_by(patient_id=patient_id).all()
    
    if include_archived:
        # Query archived visits
        archived_visits = current_app.data_archiver.retrieve_archived_data(
            start_date=datetime.min,  # Use appropriate start date
            end_date=datetime.now(),
            table_name='visits'
        )
        archived_visits = [visit for visit in archived_visits if visit.patient_id == patient_id]
        
        # Combine current and archived visits
        all_visits = current_visits + archived_visits
        return sorted(all_visits, key=lambda v: v.visit_date, reverse=True)
    
    return current_visits