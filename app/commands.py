import click
from flask.cli import with_appcontext
from app.performance_monitor import PerformanceMetric
from app.database import db
from datetime import datetime, timedelta
import json

@click.command('optimize-db')
@with_appcontext
def optimize_db_command():
    from flask import current_app
    from .database_management import optimize_database
    from .data_archiver import DataArchiver
    
    click.echo('Optimizing database...')
    optimize_database()
    
    click.echo('Creating archive tables...')
    data_archiver = DataArchiver(current_app.extensions['sqlalchemy'].db)
    data_archiver.create_archive_tables()
    
    click.echo('Database optimization completed.')

@click.command('setup-performance-monitoring')
@with_appcontext
def setup_performance_monitoring_command():
    """Initialize performance monitoring tables and views"""
    from flask import current_app
    
    click.echo('Setting up performance monitoring...')
    
    try:
        # Create performance metrics table if it doesn't exist
        db.create_all()
        
        # Create materialized view and functions using raw SQL
        # This is in case migrations haven't been run yet
        with db.engine.connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id SERIAL PRIMARY KEY,
                    endpoint VARCHAR(255),
                    method VARCHAR(10),
                    request_id VARCHAR(36),
                    user_id INTEGER,
                    visit_id INTEGER,
                    upload_time FLOAT,
                    processing_time FLOAT,
                    total_time FLOAT,
                    db_query_time FLOAT,
                    file_size INTEGER,
                    num_images INTEGER,
                    status_code INTEGER,
                    error_message VARCHAR(500),
                    metadata JSONB,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # Create indexes
            connection.execute("CREATE INDEX IF NOT EXISTS idx_perf_endpoint ON performance_metrics(endpoint);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_perf_timestamp ON performance_metrics(timestamp);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_perf_user_id ON performance_metrics(user_id);")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_perf_visit_id ON performance_metrics(visit_id);")
            
            click.echo('✓ Performance metrics table created')
            
            # Create performance summary view
            connection.execute("""
                CREATE OR REPLACE VIEW performance_summary AS
                SELECT 
                    endpoint,
                    DATE(timestamp) as date,
                    COUNT(*) as request_count,
                    AVG(total_time) as avg_total_time,
                    MIN(total_time) as min_total_time,
                    MAX(total_time) as max_total_time,
                    AVG(upload_time) as avg_upload_time,
                    AVG(processing_time) as avg_processing_time,
                    SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END) as error_count
                FROM performance_metrics
                GROUP BY endpoint, DATE(timestamp);
            """)
            
            click.echo('✓ Performance summary view created')
            
        click.echo('Performance monitoring setup completed successfully!')
        
    except Exception as e:
        click.echo(f'Error setting up performance monitoring: {str(e)}', err=True)
        raise


@click.command('performance-report')
@click.option('--hours', default=24, help='Number of hours to include in report')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json', 'csv']))
@with_appcontext
def performance_report_command(hours, output_format):
    """Generate a performance report"""
    from flask import current_app
    from sqlalchemy import func
    
    click.echo(f'Generating performance report for the last {hours} hours...\n')
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Overall statistics
    overall_stats = db.session.query(
        func.count(PerformanceMetric.id).label('total_requests'),
        func.avg(PerformanceMetric.total_time).label('avg_response_time'),
        func.min(PerformanceMetric.total_time).label('min_response_time'),
        func.max(PerformanceMetric.total_time).label('max_response_time'),
        func.sum(db.case([(PerformanceMetric.status_code != 200, 1)], else_=0)).label('error_count')
    ).filter(PerformanceMetric.timestamp >= since).first()
    
    # By endpoint statistics
    endpoint_stats = db.session.query(
        PerformanceMetric.endpoint,
        func.count(PerformanceMetric.id).label('count'),
        func.avg(PerformanceMetric.total_time).label('avg_time'),
        func.avg(PerformanceMetric.upload_time).label('avg_upload'),
        func.avg(PerformanceMetric.processing_time).label('avg_processing')
    ).filter(
        PerformanceMetric.timestamp >= since
    ).group_by(PerformanceMetric.endpoint).all()
    
    if output_format == 'json':
        report = {
            'period': f'Last {hours} hours',
            'generated_at': datetime.utcnow().isoformat(),
            'overall': {
                'total_requests': overall_stats.total_requests,
                'avg_response_time': float(overall_stats.avg_response_time) if overall_stats.avg_response_time else 0,
                'min_response_time': float(overall_stats.min_response_time) if overall_stats.min_response_time else 0,
                'max_response_time': float(overall_stats.max_response_time) if overall_stats.max_response_time else 0,
                'error_count': overall_stats.error_count,
                'error_rate': overall_stats.error_count / overall_stats.total_requests if overall_stats.total_requests > 0 else 0
            },
            'by_endpoint': [
                {
                    'endpoint': stat.endpoint,
                    'requests': stat.count,
                    'avg_response_time': float(stat.avg_time) if stat.avg_time else 0,
                    'avg_upload_time': float(stat.avg_upload) if stat.avg_upload else 0,
                    'avg_processing_time': float(stat.avg_processing) if stat.avg_processing else 0
                }
                for stat in endpoint_stats
            ]
        }
        click.echo(json.dumps(report, indent=2))
        
    elif output_format == 'csv':
        click.echo('endpoint,requests,avg_response_time,avg_upload_time,avg_processing_time')
        for stat in endpoint_stats:
            click.echo(f'{stat.endpoint},{stat.count},{stat.avg_time:.3f},{stat.avg_upload or 0:.3f},{stat.avg_processing or 0:.3f}')
            
    else:  # table format
        click.echo('=== OVERALL STATISTICS ===')
        click.echo(f'Total Requests: {overall_stats.total_requests}')
        click.echo(f'Average Response Time: {overall_stats.avg_response_time:.3f}s')
        click.echo(f'Min Response Time: {overall_stats.min_response_time:.3f}s')
        click.echo(f'Max Response Time: {overall_stats.max_response_time:.3f}s')
        click.echo(f'Errors: {overall_stats.error_count} ({overall_stats.error_count/overall_stats.total_requests*100:.1f}%)')
        
        click.echo('\n=== ENDPOINT BREAKDOWN ===')
        click.echo(f'{"Endpoint":<50} {"Requests":>10} {"Avg Time":>10} {"Upload":>10} {"Process":>10}')
        click.echo('-' * 90)
        
        for stat in sorted(endpoint_stats, key=lambda x: x.count, reverse=True):
            click.echo(
                f'{stat.endpoint:<50} {stat.count:>10} '
                f'{stat.avg_time:>10.3f}s '
                f'{(stat.avg_upload or 0):>10.3f}s '
                f'{(stat.avg_processing or 0):>10.3f}s'
            )


@click.command('simulate-performance-load')
@click.option('--requests', default=100, help='Number of requests to simulate')
@with_appcontext
def simulate_performance_load_command(requests):
    """Simulate performance data for testing"""
    import random
    
    click.echo(f'Simulating {requests} performance metrics...')
    
    endpoints = [
        '/api/visits/1/images',
        '/api/visits/1/initiate-diagnosis',
        '/api/patients',
        '/api/dashboard/stats',
        '/api/patients/search'
    ]
    
    for i in range(requests):
        endpoint = random.choice(endpoints)
        
        # Simulate realistic timings
        if 'images' in endpoint:
            upload_time = random.uniform(0.5, 3.0)
            total_time = upload_time + random.uniform(0.1, 0.5)
            processing_time = None
        elif 'diagnosis' in endpoint:
            processing_time = random.uniform(2.0, 10.0)
            total_time = processing_time + random.uniform(0.1, 0.5)
            upload_time = None
        else:
            total_time = random.uniform(0.05, 0.5)
            upload_time = None
            processing_time = None
        
        metric = PerformanceMetric(
            endpoint=endpoint,
            method='POST' if 'images' in endpoint or 'diagnosis' in endpoint else 'GET',
            request_id=f'test-{i}',
            user_id=random.randint(1, 10),
            visit_id=random.randint(1, 100) if 'visits' in endpoint else None,
            upload_time=upload_time,
            processing_time=processing_time,
            total_time=total_time,
            db_query_time=random.uniform(0.01, 0.1),
            status_code=200 if random.random() > 0.05 else 500,
            file_size=random.randint(100000, 5000000) if upload_time else None,
            num_images=random.randint(1, 5) if upload_time else None,
            timestamp=datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        )
        
        db.session.add(metric)
        
        if (i + 1) % 10 == 0:
            db.session.commit()
            click.echo(f'Created {i + 1} metrics...')
    
    db.session.commit()
    click.echo(f'✓ Successfully created {requests} performance metrics')

