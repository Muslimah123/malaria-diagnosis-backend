from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, JWTManager,get_jwt_identity
from app.models import db, User, Patient, Image, DiagnosisResult, Metadata
from datetime import timedelta
from app.schemas import UserSchema, PatientSchema, ImageSchema, DiagnosisResultSchema, MetadataSchema
from app.utils import save_image
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from marshmallow import EXCLUDE,ValidationError
from sqlalchemy import select
import requests


import os

api = Blueprint('api', __name__)
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_folder')

# JWT setup
def init_jwt(app):
    app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY') 
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    jwt = JWTManager(app)
    return jwt
ph=PasswordHasher()
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

@api.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = ph.hash(data['password'])
    new_user = user_schema.load({
        'username': data['username'],
        'email': data['email'],
        'password': hashed_password,
        'role': data['role']
    },session=db.session)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'})

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    try:
        if not user or not ph.verify(user.password, data['password']):
            return jsonify({'message': 'Invalid credentials!'}), 401
    except VerifyMismatchError:
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Create access token
    access_token = create_access_token(identity={'email': user.email, 'role': user.role})
    return jsonify(access_token=access_token)

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
def create_patient():
    data = request.get_json()
    max_retries = 5  # maximum number of retries to generate a unique ID
    attempt = 0

    while attempt < max_retries:
        try:
            new_patient = patient_schema.load(data, session=db.session, unknown=EXCLUDE)
            new_patient.patient_id = Patient.generate_patient_id()  # generate ID here
            db.session.add(new_patient)
            db.session.commit()
            return jsonify({'message': 'Patient created successfully!', 'patient': patient_schema.dump(new_patient)})
        except IntegrityError as e:
            db.session.rollback()
            if 'unique constraint "patients_pkey"' in str(e.orig):
                attempt += 1  # increment attempt counter
                continue  # try again to generate a new ID
            else:
                return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
        except ValidationError as err:
            return jsonify(err.messages), 400
        except Exception as e:
            db.session.rollback()
            print(f'Error: {str(e)}')  # Print the actual error message for debugging
            return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    return jsonify({'message': 'Failed to create a unique patient ID after several attempts.'}), 500

@api.route('/patients', methods=['GET'])
@jwt_required()
def get_patients():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('limit', 10, type=int)

    # Create a select statement
    stmt = select(Patient)

    # Use the paginate method on the select statement
    patients_page = db.paginate(stmt, page=page, per_page=per_page)

    return jsonify({
        'patients': patients_schema.dump(patients_page.items),
        'totalPages': patients_page.pages,
        'page': patients_page.page,
        'per_page': patients_page.per_page,
        'total': patients_page.total
    })

   

@api.route('/patients/<string:patient_id>', methods=['GET'])
@jwt_required()
def get_patient(patient_id):
    patient = Patient.query.filter_by(patient_id=patient_id).first()
    if patient is None:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get associated images
    images = Image.query.filter_by(patient_id=patient_id).all()
    
    # Get diagnosis results for these images
    image_ids = [image.image_id for image in images]
    diagnosis_results = DiagnosisResult.query.filter(DiagnosisResult.image_id.in_(image_ids)).all()
    
    patient_data = patient_schema.dump(patient)
    patient_data['images'] = images_schema.dump(images)
    patient_data['diagnosis_results'] = diagnosis_results_schema.dump(diagnosis_results)
    
    return jsonify(patient_data)

@api.route('/patients/<string:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    data = request.get_json()
    patient = Patient.query.filter_by(patient_id=patient_id).first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    patient = patient_schema.load(data, instance=patient, session=db.session,partial=True)
    db.session.commit()
    return jsonify({'message': 'Patient updated successfully!'})

@api.route('/patients/<string:patient_id>', methods=['DELETE'])
@jwt_required()
def delete_patient(patient_id):
    patient = Patient.query.filter_by(patient_id=patient_id).first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    db.session.delete(patient)
    db.session.commit()
    return jsonify({'message': 'Patient deleted successfully!'})

@api.route('/images', methods=['POST'])
@jwt_required()
def upload_images():
    patient_id = request.form.get('patient_id')
    images = request.files.getlist('images')
    smear_types = request.form.getlist('smear_type')
    test_types = request.form.getlist('test_type')

    if not patient_id or not images or not smear_types or not test_types:
        return jsonify({"error": "Missing data"}), 400

    for idx, image in enumerate(images):
        file_path = save_image(image, UPLOAD_FOLDER)

        new_image = Image(
            patient_id=patient_id,
            file_path=file_path,
            smear_type=smear_types[idx],
            test_type=test_types[idx],
            status='queued'
        )
        db.session.add(new_image)

    db.session.commit()

    return jsonify({"message": "Images uploaded successfully"}), 201

@api.route('/process_image/<int:image_id>', methods=['POST'])
@jwt_required()
def process_image(image_id):
    image = Image.query.get(image_id)
    if not image:
        return jsonify({'error': 'Image not found'}), 404

    # Update image status to preprocessing
    image.status = 'preprocessing'
    db.session.commit()

    # Send the image for processing
    file_path = image.file_path
    response = send_image_for_processing(file_path)

    if response.status_code != 200:
        return jsonify({'error': 'Processing failed'}), response.status_code

    data = response.json()
    save_diagnosis_results(image_id, data)

    return jsonify({'message': 'Image processed successfully'}), 200

def send_image_for_processing(file_path):
    url = "Alain's endpoint"
    files = {'file': open(file_path, 'rb')}
    response = requests.post(url, files=files)
    return response

def save_diagnosis_results(image_id, data):
    for parasite in data['detected_parasites']:
        diagnosis_result = DiagnosisResult(
            image_id=image_id,
            parasite_name=parasite['parasite_name'],
            average_confidence=parasite['average_confidence'],
            count=parasite['count'],
            severity_level=parasite['severity_level'],
            status='positive' if parasite['count'] > 0 else 'negative'
        )
        db.session.add(diagnosis_result)

    # Update image status to processed
    image = Image.query.get(image_id)
    image.status = 'processed'
    db.session.commit()


@api.route('/diagnosis_results/<int:image_id>', methods=['GET'])
@jwt_required()
def get_diagnosis_results(image_id):
    results = DiagnosisResult.query.filter_by(image_id=image_id).all()
    results_schema = DiagnosisResultSchema(many=True)
    return jsonify(results_schema.dump(results)), 200

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
@api.route('/diagnosis-results', methods=['POST'])
@jwt_required()
def create_diagnosis_result():
    data = request.get_json()
    new_result = diagnosis_result_schema.load(data)
    db.session.add(new_result)
    db.session.commit()
    return jsonify({'message': 'Diagnosis result created successfully!'})

# @api.route('/diagnosis-results', methods=['GET'])
# @jwt_required()
# def get_diagnosis_results():
#     results = DiagnosisResult.query.all()
#     return diagnosis_results_schema.jsonify(results)

# @api.route('/diagnosis-results/<int:result_id>', methods=['GET'])
# @jwt_required()
# def get_diagnosis_result(result_id):
#     result = DiagnosisResult.query.get_or_404(result_id)
#     return diagnosis_result_schema.jsonify(result)

@api.route('/diagnosis-results/<int:result_id>', methods=['PUT'])
@jwt_required()
def update_diagnosis_result(result_id):
    data = request.get_json()
    result = DiagnosisResult.query.get_or_404(result_id)
    result = diagnosis_result_schema.load(data, instance=result, partial=True)
    db.session.commit()
    return jsonify({'message': 'Diagnosis result updated successfully!'})

@api.route('/diagnosis-results/<int:result_id>', methods=['DELETE'])
@jwt_required()
def delete_diagnosis_result(result_id):
    result = DiagnosisResult.query.get_or_404(result_id)
    db.session.delete(result)
    db.session.commit()
    return jsonify({'message': 'Diagnosis result deleted successfully!'})

@api.route('/metadata', methods=['POST'])
@jwt_required()
def create_metadata():
    data = request.get_json()
    new_metadata = metadata_schema.load(data)
    db.session.add(new_metadata)
    db.session.commit()
    return jsonify({'message': 'Metadata created successfully!'})

@api.route('/metadata', methods=['GET'])
@jwt_required()
def get_metadata():
    metadata = Metadata.query.all()
    return metadata_items_schema.jsonify(metadata)

@api.route('/metadata/<int:metadata_id>', methods=['GET'])
@jwt_required()
def get_metadata_item(meta_id):
    metadata = Metadata.query.get_or_404(meta_id)
    return metadata_schema.jsonify(metadata)

@api.route('/metadata/<int:metadata_id>', methods=['PUT'])
@jwt_required()
def update_metadata(meta_id):
    data = request.get_json()
    metadata = Metadata.query.get_or_404(meta_id)
    metadata = metadata_schema.load(data, instance=metadata, partial=True)
    db.session.commit()
    return jsonify({'message': 'Metadata updated successfully!'})

@api.route('/metadata/<int:metadata_id>', methods=['DELETE'])
@jwt_required()
def delete_metadata(meta_id):
    metadata = Metadata.query.get_or_404(meta_id)
    db.session.delete(metadata)
    db.session.commit()
    return jsonify({'message': 'Metadata deleted successfully!'})


