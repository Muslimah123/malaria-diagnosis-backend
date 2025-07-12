# app/performance_monitor.py

import time
import logging
from functools import wraps
from datetime import datetime
from flask import g, request
from app.models import db
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base

# Configure logging
logger = logging.getLogger(__name__)

# Performance Metrics Model
class PerformanceMetric(db.Model):
    __tablename__ = 'performance_metrics'
    
    id = Column(Integer, primary_key=True)
    endpoint = Column(String(255))
    method = Column(String(10))
    request_id = Column(String(36))
    user_id = Column(Integer)
    visit_id = Column(Integer)
    
    # Timing metrics (in seconds)
    upload_time = Column(Float)
    processing_time = Column(Float)
    total_time = Column(Float)
    db_query_time = Column(Float)
    
    # Additional metrics
    file_size = Column(Integer)  # in bytes
    num_images = Column(Integer)
    status_code = Column(Integer)
    error_message = Column(String(500))
    
    # Metadata
    meta_data = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'endpoint': self.endpoint,
            'method': self.method,
            'request_id': self.request_id,
            'user_id': self.user_id,
            'visit_id': self.visit_id,
            'upload_time': self.upload_time,
            'processing_time': self.processing_time,
            'total_time': self.total_time,
            'db_query_time': self.db_query_time,
            'file_size': self.file_size,
            'num_images': self.num_images,
            'status_code': self.status_code,
            'error_message': self.error_message,
            'meta_data': self.meta_data,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }


def track_performance(metric_type='general'):
    """Decorator to track performance metrics for endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate unique request ID
            import uuid
            request_id = str(uuid.uuid4())
            g.request_id = request_id
            g.start_time = time.time()
            g.db_query_time = 0
            
            # Track request start
            if metric_type == 'upload':
                g.upload_start = time.time()
            elif metric_type == 'processing':
                g.processing_start = time.time()
            
            try:
                # Execute the actual function
                result = f(*args, **kwargs)
                
                # Calculate timing
                end_time = time.time()
                total_time = end_time - g.start_time
                
                # Create performance metric
                metric = PerformanceMetric(
                    endpoint=request.endpoint,
                    method=request.method,
                    request_id=request_id,
                    total_time=total_time,
                    db_query_time=g.get('db_query_time', 0),
                    status_code=200
                )
                
                # Add specific timing based on metric type
                if metric_type == 'upload' and hasattr(g, 'upload_end'):
                    metric.upload_time = g.upload_end - g.upload_start
                elif metric_type == 'processing' and hasattr(g, 'processing_end'):
                    metric.processing_time = g.processing_end - g.processing_start
                
                # Extract additional context
                if hasattr(g, 'current_user'):
                    metric.user_id = g.current_user.get('user_id')
                
                # Save metric
                db.session.add(metric)
                db.session.commit()
                
                # Log performance
                logger.info(f"Performance: {request.endpoint} - {total_time:.3f}s")
                
                return result
                
            except Exception as e:
                # Track error metrics
                end_time = time.time()
                total_time = end_time - g.start_time
                
                metric = PerformanceMetric(
                    endpoint=request.endpoint,
                    method=request.method,
                    request_id=request_id,
                    total_time=total_time,
                    status_code=500,
                    error_message=str(e)[:500]
                )
                
                db.session.add(metric)
                db.session.commit()
                
                logger.error(f"Error in {request.endpoint}: {str(e)}")
                raise
                
        return decorated_function
    return decorator


def track_db_query(f):
    """Decorator to track database query time"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start = time.time()
        result = f(*args, **kwargs)
        end = time.time()
        
        if hasattr(g, 'db_query_time'):
            g.db_query_time += (end - start)
        else:
            g.db_query_time = (end - start)
            
        return result
    return decorated_function


class PerformanceTracker:
    """Context manager for tracking specific operations"""
    def __init__(self, operation_name):
        self.operation_name = operation_name
        self.start_time = None
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        logger.info(f"{self.operation_name} took {duration:.3f}s")
        
        # Store in g for access in decorators
        if not hasattr(g, 'operation_times'):
            g.operation_times = {}
        g.operation_times[self.operation_name] = duration


# Utility functions for performance analysis
def get_performance_stats(endpoint=None, start_date=None, end_date=None):
    """Get performance statistics for analysis"""
    query = db.session.query(PerformanceMetric)
    
    if endpoint:
        query = query.filter(PerformanceMetric.endpoint == endpoint)
    if start_date:
        query = query.filter(PerformanceMetric.timestamp >= start_date)
    if end_date:
        query = query.filter(PerformanceMetric.timestamp <= end_date)
    
    metrics = query.all()
    
    if not metrics:
        return None
    
    # Calculate statistics
    total_times = [m.total_time for m in metrics if m.total_time]
    upload_times = [m.upload_time for m in metrics if m.upload_time]
    processing_times = [m.processing_time for m in metrics if m.processing_time]
    
    stats = {
        'count': len(metrics),
        'total_time': {
            'avg': sum(total_times) / len(total_times) if total_times else 0,
            'min': min(total_times) if total_times else 0,
            'max': max(total_times) if total_times else 0,
        },
        'upload_time': {
            'avg': sum(upload_times) / len(upload_times) if upload_times else 0,
            'min': min(upload_times) if upload_times else 0,
            'max': max(upload_times) if upload_times else 0,
        },
        'processing_time': {
            'avg': sum(processing_times) / len(processing_times) if processing_times else 0,
            'min': min(processing_times) if processing_times else 0,
            'max': max(processing_times) if processing_times else 0,
        },
        'error_rate': len([m for m in metrics if m.status_code != 200]) / len(metrics),
        'success_rate': len([m for m in metrics if m.status_code == 200]) / len(metrics),
    }
    
    return stats


# Middleware for automatic performance tracking
def init_performance_monitoring(app):
    """Initialize performance monitoring for the Flask app"""
    
    @app.before_request
    def before_request():
        g.start_time = time.time()
        g.request_start = datetime.utcnow()
    
    @app.after_request
    def after_request(response):
        if hasattr(g, 'start_time'):
            total_time = time.time() - g.start_time
            response.headers['X-Response-Time'] = str(total_time)
            
            # Log slow requests
            if total_time > 5.0:  # 5 seconds threshold
                logger.warning(f"Slow request: {request.endpoint} took {total_time:.3f}s")
        
        return response
    
    return app