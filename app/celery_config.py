from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['result_backend'],
        broker=app.config['broker_url']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery

# Create a dummy app for Celery configuration
from flask import Flask
dummy_app = Flask(__name__)
dummy_app.config.update(
    broker_url=os.getenv('CELERY_BROKER_URL'),
    result_backend=os.getenv('CELERY_RESULT_BACKEND'),
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    imports=['app.celery_worker'],  
    worker_concurrency=int(os.getenv('CELERY_WORKER_CONCURRENCY', '4')),
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # EXTERNAL_ML_API_URL=os.getenv('EXTERNAL_ML_API_URL', 'http://localhost:5001/process_images')

)

celery = make_celery(dummy_app)
