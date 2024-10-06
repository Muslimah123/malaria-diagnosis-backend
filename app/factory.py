from flask import Flask
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from .extensions import mail, oauth, init_mail, init_oauth
from .socket_events import init_socketio
from .database import db
import os
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import logging
from .query_optimizer import QueryOptimizer, AdvancedQueryOptimizer
from .database_management import initialize_database, optimize_database
from .data_archiver import DataArchiver
from apscheduler.schedulers.background import BackgroundScheduler
# from app.database_management import optimize_db_command
from .commands import optimize_db_command  # Ensure this import is here





load_dotenv()

migrate = Migrate()
ma = Marshmallow()

def create_app():
    app = Flask(__name__)
    env = os.environ.get('APP_ENVIRONMENT', 'development')
    app.config.from_object(f'config.{env.capitalize()}Config')
    # Configure mail
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

     # Celery configuration
    app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL')
    app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND')
   
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload_folder')
    
    # api.config['EXTERNAL_ML_API_URL']=os.getenv('EXTERNAL_ML_API_URL',"https://127.0.0.1:5001/process_images")

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    ma.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

     # Initialize JWT
    jwt = JWTManager(app)
    socketio = init_socketio(app)


    init_mail(app)
    init_oauth(app)

        # Initialize QueryOptimizer
    query_optimizer = QueryOptimizer(db)
    advanced_query_optimizer = AdvancedQueryOptimizer(db)
    app.query_optimizer = query_optimizer
    app.advanced_query_optimizer = advanced_query_optimizer

    # Initialize DataArchiver
    data_archiver = DataArchiver(db)
    app.data_archiver = data_archiver

    with app.app_context():

        data_archiver.create_archive_tables()

    # Set up scheduled archiving
    scheduler = BackgroundScheduler()

    # Wrap the scheduled jobs in the app context
    with app.app_context():
    # Run the archiving job on the 1st of every month at 2 AM
        scheduler.add_job(data_archiver.archive_old_data, 'cron', day='1', hour='2')

    # Run the cleanup job on the 15th of every month at 3 AM
        scheduler.add_job(
            lambda: cleanup_archived_image_files(datetime.now() - timedelta(days=365)),
            'cron', 
            day='15', 
            hour='3'
        )

# Start the scheduler
    scheduler.start()



     # Initialize database
    with app.app_context():
        db.create_all()
        # initialize_database()
        optimize_database()
    
    app.cli.add_command(optimize_db_command)



    return app,socketio

# def register_blueprints(app):
#     from .routes import api as routes_api
#     app.register_blueprint(routes_api, url_prefix='/api')

