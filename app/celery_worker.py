

# import logging
# from .models import Visit, Image, db
# from .socket_events import send_processing_update
# from .celery_config import celery
# from .utils import process_image_batch_logic

# logger = logging.getLogger(__name__)

# @celery.task(bind=True, max_retries=3)
# def process_images_batch(self, visit_id):
#     logger.info(f"Processing images for visit {visit_id}")
#     try:
#         visit = Visit.query.get(visit_id)
#         if not visit:
#             logger.error(f"Visit with id {visit_id} not found")
#             raise Exception(f"Visit with id {visit_id} not found")

#         Image.query.filter_by(visit_id=visit_id).update({'processing_status': 'processing'})
#         db.session.commit()

#         send_processing_update(visit.patient_id, None, 'processing')

#         logger.info(f"Calling process_image_batch_logic for visit {visit_id}")

#         process_image_batch_logic(visit_id)

#         logger.info(f"Finished processing images for visit {visit_id}")

#         send_processing_update(visit.patient_id, None, 'visit_completed')

#     except Exception as exc:
#         logger.error(f"Error processing images for visit {visit_id}: {str(exc)}")
#         if self.request.retries < self.max_retries:
#             Image.query.filter_by(visit_id=visit_id).update({'processing_status': 'queued'})
#             db.session.commit()
#             send_processing_update(visit.patient_id, None, 'queued')
#             logger.info(f'Processing images for visit {visit_id} failed, retrying in 60 seconds')
#             raise self.retry(exc=exc, countdown=60)
#         else:
#             Image.query.filter_by(visit_id=visit_id).update({'processing_status': 'failed'})
#             visit = Visit.query.get(visit_id)
#             if visit:
#                 visit.status = 'failed'
#             db.session.commit()
#             send_processing_update(visit.patient_id, None, 'failed')
#             raise exc

