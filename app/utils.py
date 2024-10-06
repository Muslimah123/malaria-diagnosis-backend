
import os
import requests
from werkzeug.utils import secure_filename
from flask import current_app
from .database import db
from .models import Image, DiagnosisResult, Visit
import logging
from .socket_events import send_processing_update
from functools import wraps


logger = logging.getLogger(__name__)

def save_image(file, upload_folder):
    if not file:
        return None
    
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)
    
    return filepath


# def process_image_batch_logic(visit_id):
#     logger.info(f"Processing image batch for visit {visit_id}")
    
#     visit = Visit.query.get(visit_id)
#     if not visit:
#         logger.error(f"Visit with id {visit_id} not found")
#         send_processing_update(None, None, 'failed')
#         return

#     try:
#         # Get image paths
#         image_paths = [image.file_path for image in visit.images]
        
#         # Prepare the request data
#         data = {'image_paths': image_paths}
        
#         # Create a test request context and call the process_images_backend function
#         with current_app.test_request_context('/process_images', method='POST', json=data):
#             response = process_images_backend()
        
#         # Check if the response is a tuple (indicating an error response)
#         if isinstance(response, tuple):
#             raise Exception(f"Error processing images: {response[0]}")
        
#         # Parse the JSON response
#         result = response.json
        
#         logger.info(f"Received response: {result}")

#         # Create an overall DiagnosisResult for the visit
#         overall_diagnosis = DiagnosisResult(
#             visit_id=visit_id,
#             image_id=None,  # This indicates it's an overall result
#             parasite_name=result['dominant_parasite'],
#             average_confidence=result['dominant_confidence'],
#             count=result['total_parasites'],
#             severity_level=result['severity'],
#             status='positive' if result['total_parasites'] > 0 else 'negative',
#             parasite_density=result['parasite_density'],
#             total_wbcs=result['total_wbcs']
#         )
#         db.session.add(overall_diagnosis)
        
#         # Create individual DiagnosisResults for each image
#         for image, image_result in zip(visit.images, result['image_results']):
#             individual_diagnosis = DiagnosisResult(
#                 visit_id=visit_id,
#                 image_id=image.image_id,
#                 count=image_result['parasite_count'],
#                 wbc_count=image_result['wbc_count']
#             )
#             db.session.add(individual_diagnosis)
        
#         # Update visit status
#         visit.status = 'completed'
#         for image in visit.images:
#             image.processing_status = 'completed'

#         # Commit all the results and updates
#         db.session.commit()

#         # Notify the client via socket that the processing for the visit is complete
#         send_processing_update(visit.patient_id, None, 'visit_completed')

#         logger.info(f"All images for visit {visit_id} processed successfully.")

#     except Exception as e:
#         logger.error(f"Error during batch processing for visit {visit_id}: {str(e)}")
#         visit.status = 'failed'
#         for image in visit.images:
#             image.processing_status = 'failed'
#         db.session.commit()
#         send_processing_update(visit.patient_id, None, 'failed')
#         raise  # Re-raise to handle retries in case of Celery task

# logging.basicConfig(level=logging.INFO)
# Query Optimizer Utilities

def optimize_query(query):
    """
    Optimize the given SQL query using the QueryOptimizer.
    """
    return current_app.query_optimizer.optimize_query(query)

def analyze_query_performance(query):
    """
    Analyze the performance of the given SQL query.
    """
    return current_app.advanced_query_optimizer.analyze_query_performance(query)

def suggest_query_optimizations(query):
    """
    Suggest optimizations for the given SQL query.
    """
    analysis = analyze_query_performance(query)
    return current_app.advanced_query_optimizer.suggest_optimizations(analysis)

def cache_query(func):
    """
    Decorator to cache the results of a query function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        return current_app.query_optimizer.cache_query(func)(*args, **kwargs)
    return wrapper

def monitor_query_performance(func):
    """
    Decorator to monitor the performance of a query function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        return current_app.query_optimizer.monitor_query_performance(func)(*args, **kwargs)
    return wrapper

def create_materialized_view(name, query):
    """
    Create a materialized view with the given name and query.
    """
    current_app.query_optimizer.create_materialized_view(name, query)

def refresh_materialized_view(name):
    """
    Refresh the materialized view with the given name.
    """
    current_app.query_optimizer.refresh_materialized_view(name)

def analyze_table(table_name):
    """
    Analyze the given table to update its statistics.
    """
    current_app.query_optimizer.analyze_table(table_name)

logging.basicConfig(level=logging.INFO)
