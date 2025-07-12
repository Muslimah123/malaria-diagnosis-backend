

# Updated factory.py with performance monitoring integration

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
from .commands import optimize_db_command
from .performance_monitor import init_performance_monitoring, PerformanceMetric
from datetime import datetime, timedelta

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
    
    # Initialize Performance Monitoring
    app = init_performance_monitoring(app)
    
    # Setup performance logging
    setup_performance_logging(app)

    with app.app_context():
        data_archiver.create_archive_tables()
        
        # Create performance metrics table
        db.create_all()

    # Set up scheduled tasks
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
        
        # Add performance monitoring tasks
        # Refresh performance stats every hour
        scheduler.add_job(
            lambda: refresh_performance_stats(app),
            'interval',
            hours=1,
            id='refresh_perf_stats'
        )
        
        # Clean old performance metrics daily
        scheduler.add_job(
            lambda: clean_old_performance_metrics(app),
            'cron',
            hour=2,
            id='clean_perf_metrics'
        )
        
        # Emit real-time performance updates every minute
        scheduler.add_job(
            lambda: emit_performance_updates(app, socketio),
            'interval',
            minutes=1,
            id='emit_perf_updates'
        )

    # Start the scheduler
    scheduler.start()

    # Initialize database
    with app.app_context():
        db.create_all()
        optimize_database()
    
    app.cli.add_command(optimize_db_command)

    return app, socketio


def setup_performance_logging(app):
    """Configure logging for performance monitoring"""
    
    # Create performance logger
    perf_logger = logging.getLogger('performance')
    perf_logger.setLevel(logging.INFO)
    
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create file handler for performance logs
    from logging.handlers import RotatingFileHandler
    perf_handler = RotatingFileHandler(
        os.path.join(log_dir, 'performance.log'),
        maxBytes=10485760,  # 10MB
        backupCount=10
    )
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    perf_handler.setFormatter(formatter)
    
    # Add handler to logger
    perf_logger.addHandler(perf_handler)
    
    # Also log to console in development
    if app.config.get('DEBUG'):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        perf_logger.addHandler(console_handler)


def refresh_performance_stats(app):
    """Refresh performance statistics materialized view"""
    with app.app_context():
        try:
            # PostgreSQL specific - refresh materialized view if it exists
            db.session.execute("SELECT refresh_performance_stats()")
            db.session.commit()
        except Exception as e:
            app.logger.warning(f"Could not refresh performance stats: {e}")


def clean_old_performance_metrics(app):
    """Clean performance metrics older than 30 days"""
    with app.app_context():
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            PerformanceMetric.query.filter(
                PerformanceMetric.timestamp < cutoff_date
            ).delete()
            db.session.commit()
            app.logger.info(f"Cleaned performance metrics older than {cutoff_date}")
        except Exception as e:
            app.logger.error(f"Error cleaning old performance metrics: {e}")
            db.session.rollback()


def emit_performance_updates(app, socketio):
    """Emit real-time performance updates via WebSocket"""
    with app.app_context():
        try:
            from datetime import datetime, timedelta
            
            # Get metrics from last minute
            one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
            recent_metrics = PerformanceMetric.query.filter(
                PerformanceMetric.timestamp >= one_minute_ago
            ).all()
            
            if recent_metrics:
                # Calculate statistics
                upload_times = [m.upload_time for m in recent_metrics if m.upload_time]
                processing_times = [m.processing_time for m in recent_metrics if m.processing_time]
                
                stats = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_requests': len(recent_metrics),
                    'avg_response_time': sum(m.total_time for m in recent_metrics) / len(recent_metrics),
                    'upload_metrics': {
                        'count': len(upload_times),
                        'avg': sum(upload_times) / len(upload_times) if upload_times else 0,
                        'min': min(upload_times) if upload_times else 0,
                        'max': max(upload_times) if upload_times else 0
                    },
                    'processing_metrics': {
                        'count': len(processing_times),
                        'avg': sum(processing_times) / len(processing_times) if processing_times else 0,
                        'min': min(processing_times) if processing_times else 0,
                        'max': max(processing_times) if processing_times else 0
                    },
                    'error_rate': len([m for m in recent_metrics if m.status_code != 200]) / len(recent_metrics),
                    'active_endpoints': list(set(m.endpoint for m in recent_metrics))
                }
                
                # Emit to all connected clients in the performance monitoring room
                socketio.emit('performance_update', stats, room='performance_monitoring')
                
        except Exception as e:
            app.logger.error(f"Error emitting performance updates: {e}")


def cleanup_archived_image_files(cutoff_date):
    """Placeholder for cleaning up archived image files"""
    # Implementation depends on your file storage strategy
    pass

# Add these commands to your factory.py after creating the app
# from .performance_monitor import (
#     performance_report_command,
#     setup_performance_monitoring_command,
#     simulate_performance_load_command
# )

# def register_performance_commands(app):
#     """Register performance monitoring commands"""
#     app.cli.add_command(setup_performance_monitoring_command)
#     app.cli.add_command(performance_report_command)
#     app.cli.add_command(simulate_performance_load_command)