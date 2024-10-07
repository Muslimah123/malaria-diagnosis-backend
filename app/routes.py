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

# @api.route('/patients/<string:patient_id>', methods=['PUT'])
# @jwt_required()
# def update_patient(patient_id):
#     print(f"Received update request for patient {patient_id}")

#     data = request.get_json()

#     # Remove 'patient_id' from the data if it exists
#     if 'patient_id' in data:
#         del data['patient_id']  # We don't need to update this, as it's part of the URL

#     # Fetch the patient from the database
#     patient = Patient.query.filter_by(patient_id=patient_id).first()

#     # If the patient doesn't exist, return a 404
#     if not patient:
#         return jsonify({'message': 'Patient not found'}), 404

#     # Load the data into the patient instance
#     try:
#         patient = patient_schema.load(data, instance=patient, session=db.session, partial=True)
#         db.session.commit()
#         update_all_patient_search_vectors()
        
#         return jsonify({'message': 'Patient updated successfully!'}), 200
#     except ValidationError as e:
#         return jsonify({'errors': e.messages}), 400
#     except Exception as e:
#         db.session.rollback()  # Rollback in case of errors
#         return jsonify({'error': str(e)}), 500
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

@api.route('/visits/<int:visit_id>/images', methods=['POST'])
@jwt_required()
def upload_visit_images(visit_id):
    visit = Visit.query.get_or_404(visit_id)

    if 'images' not in request.files:
        return jsonify({"error": "No images provided"}), 400

    images = request.files.getlist('images')
    existing_images_count = Image.query.filter_by(visit_id=visit_id).count()

    if len(images) + existing_images_count > 5:
        return jsonify({"error": f"Maximum 5 images allowed per visit. This visit already has {existing_images_count} images."}), 400

    smear_types = request.form.getlist('smear_type')
    test_types = request.form.getlist('test_type')

    if len(smear_types) != len(images) or len(test_types) != len(images):
        return jsonify({"error": "Mismatch in number of smear types or test types"}), 400

    uploaded_images = []
    # image_paths = []  # To store paths for batch processing

    try:
        for idx, image in enumerate(images):
            if not allowed_file(image.filename):
                logging.warning(f"Rejected file: {image.filename}")
                continue  # Skip to the next file
            
            logging.info(f"Processing image: {image.filename}, {image.content_type}, {image.content_length}")
            
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
                # db.session.flush()  # Ensures the image is assigned an ID
                uploaded_images.append(new_image)
                # image_paths.append(file_path)  # Collect file paths for batch processing
                logging.info(f"Successfully processed and saved image: {image.filename}")
            else:
                logging.warning(f"Failed to save image: {image.filename}")

        if uploaded_images:
            db.session.commit()

            new_total_image_count = existing_images_count + len(uploaded_images)

            # Trigger diagnosis if total images reach or exceed 5
            # if new_total_image_count >= 5:
            #     process_images_batch.delay(visit_id)

            return jsonify({
                "message": f"{len(uploaded_images)} images uploaded successfully.",
                "total_images": new_total_image_count
            }), 201
        else:
            return jsonify({"error": "No valid images were uploaded. Allowed formats are PNG, JPG, JPEG, and GIF."}), 400

    except Exception as e:
        current_app.logger.error(f"Error uploading images: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Error uploading images: {str(e)}"}), 500

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

@api.route('/visits/<int:visit_id>/initiate-diagnosis', methods=['POST'])
@jwt_required()
def initiate_diagnosis(visit_id):
    try:
        visit = Visit.query.get_or_404(visit_id)
        
        # Ensure there are at least 5 images uploaded
        images = Image.query.filter_by(visit_id=visit_id).all()
        if len(images) < 5:
            return jsonify({"error": "At least 5 images are required to start the diagnosis"}), 400
        
        # Check if diagnosis has already been performed
        existing_diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()
        if existing_diagnosis:
            return jsonify({"message": "Diagnosis has already been performed for this visit", 
                            "diagnosis": diagnosis_result_schema.dump(existing_diagnosis)}), 200
        
        # Get image paths
        image_paths = [image.file_path for image in images]
        
        # Prepare the request data for process_images_backend
        data = {'image_paths': image_paths}
        
        # Create a test request context
        with current_app.test_request_context('/process_images', method='POST', json=data):
            # Call process_images_backend within the test request context
            response = process_images_backend()
            
        # Check if the response is a tuple (indicating an error response)
        if isinstance(response, tuple):
            return response
        
        # Parse the JSON response
        result = response.json
        
        # Create an overall DiagnosisResult for the visit
        overall_diagnosis = DiagnosisResult(
            visit_id=visit_id,
            image_id=None,  # This indicates it's an overall result
            parasite_name=result['dominant_parasite'],
            average_confidence=result['dominant_confidence'],
            count=result['total_parasites'],
            severity_level=result['severity'],
            status='positive' if result['total_parasites'] > 0 else 'negative',
            parasite_density=result['parasite_density'],
            total_wbcs=result['total_wbcs']
        )
        db.session.add(overall_diagnosis)
        
        # Create individual DiagnosisResults for each image
        for image, image_result in zip(images, result['image_results']):
            individual_diagnosis = DiagnosisResult(
                visit_id=visit_id,
                image_id=image.image_id,
                count=image_result['parasite_count'],
                wbc_count=image_result['wbc_count']
            )
            db.session.add(individual_diagnosis)
        
        # Update visit status
        visit.status = 'completed'
        for image in images:
            image.processing_status = 'completed'
        
        db.session.commit()
        
        # Create notification for doctors
        admin_users = User.query.filter_by(role='admin').all()
        for admin in admin_users:
            create_notification(admin.user_id, f"Diagnosis results ready for visit ID: {visit_id}")
        # Fetch all diagnosis results for this visit
        all_diagnoses = DiagnosisResult.query.filter_by(visit_id=visit_id).all()
        
        # Prepare the response
        response_data = {
            "message": "Diagnosis process completed successfully",
            "overall_diagnosis": diagnosis_result_schema.dump(overall_diagnosis),
            "image_diagnoses": [diagnosis_result_schema.dump(d) for d in all_diagnoses if d.image_id is not None],
            "summary": {
                "dominant_parasite": result['dominant_parasite'],
                "average_confidence": result['dominant_confidence'],
                "total_parasites": result['total_parasites'],
                "parasite_density": result['parasite_density'],
                "severity": result['severity'],
                "total_wbcs": result['total_wbcs']
            }
        }
        
        return jsonify(response_data), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error initiating diagnosis: {str(e)}")
        return jsonify({"error": f"Error initiating diagnosis: {str(e)}"}), 500

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

    # # Convert result to dictionary by accessing the values directly
    # if result:
    #     stats = {
    #         'total_patients': result[0],
    #         'pending_results': result[1],
    #         'completed_diagnoses': result[2],
    #         'new_diagnoses': result[3],
    #         'diagnosis_distribution': result[4],
    #     }
    # else:
    #     return jsonify({"error": "No data found"}), 404
     # Check if result is None or if certain values are None
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
# @api.route('/patients/search', methods=['GET'])
# @jwt_required()
# def search_patients():
#        query = request.args.get('query', '')
#        status = request.args.get('status', '')
#        date_from = request.args.get('date_from', '')
#        date_to = request.args.get('date_to', '')
       
#        patients = Patient.query
       
#        if query:
#            patients = patients.filter(or_(
#                Patient.name.ilike(f'%{query}%'),
#                Patient.patient_id.ilike(f'%{query}%'),
#                Patient.email.ilike(f'%{query}%')
#            ))
       
#        if status:
#            patients = patients.join(Image).join(DiagnosisResult).filter(DiagnosisResult.status == status)
       
#        if date_from:
#            patients = patients.filter(Patient.created_at >= datetime.strptime(date_from, '%Y-%m-%d'))
       
#        if date_to:
#            patients = patients.filter(Patient.created_at <= datetime.strptime(date_to, '%Y-%m-%d'))
       
#        result = patients_schema.dump(patients.all())
#        return jsonify(result), 200
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


@api.route('/process_images', methods=['POST'])
def process_images_backend():
    print("Processing request received in backend")
    data = request.json
    print("Data received:", data)

    if not data or 'image_paths' not in data:
        return jsonify({'error': 'No image paths provided in the request'}), 400

    image_paths = data['image_paths']
    
    # Check if the paths exist
    for path in image_paths:
        if not os.path.exists(path):
            return jsonify({'error': f'Image not found: {path}'}), 400

    # Process the images using the logic from Updated_Helpers.py
    results = process_images(MODEL_PATH, image_paths)

    return jsonify(results)

# from flask import send_file
# from io import BytesIO
# from reportlab.lib.pagesizes import letter
# from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
# from reportlab.lib.styles import getSampleStyleSheet
# from reportlab.lib import colors
# from sqlalchemy import func
# import json


@api.route('/visits/<int:visit_id>/download-report', methods=['GET'])
@jwt_required()
def download_visit_report(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    patient = Patient.query.get(visit.patient_id)
    diagnosis = DiagnosisResult.query.filter_by(visit_id=visit_id, image_id=None).first()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Add title
    elements.append(Paragraph(f"Visit Report - {visit.visit_date.strftime('%Y-%m-%d')}", styles['Title']))
    elements.append(Spacer(1, 12))

    # Add patient information
    elements.append(Paragraph(f"Patient: {patient.name}", styles['Heading2']))
    elements.append(Paragraph(f"Patient ID: {patient.patient_id}", styles['Normal']))
    elements.append(Paragraph(f"Age: {patient.age}", styles['Normal']))
    elements.append(Paragraph(f"Gender: {patient.gender}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Add visit information
    elements.append(Paragraph("Visit Details", styles['Heading2']))
    elements.append(Paragraph(f"Reason: {visit.reason}", styles['Normal']))
    elements.append(Paragraph(f"Symptoms: {visit.symptoms}", styles['Normal']))
    elements.append(Paragraph(f"Notes: {visit.notes}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Add diagnosis information
    if diagnosis:
        elements.append(Paragraph("Diagnosis Results", styles['Heading2']))
        data = [
            ["Parasite", diagnosis.parasite_name],
            ["Status", diagnosis.status],
            ["Confidence", f"{diagnosis.average_confidence:.2f}%"],
            ["Count", str(diagnosis.count)],
            ["Severity", diagnosis.severity_level],
            ["Parasite Density", f"{diagnosis.parasite_density:.2f}"],
            ["Total WBCs", str(diagnosis.total_wbcs)]
        ]
        t = Table(data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.grey),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 1), (-1, -1), colors.beige),
        ]))
        elements.append(t)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f'visit_report_{visit_id}.pdf', mimetype='application/pdf')

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