"""Add performance metrics table

Revision ID: performance_metrics_001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'performance_metrics_001'
down_revision = None  # Update this with your latest migration revision
branch_labels = None
depends_on = None


def upgrade():
    # Create performance_metrics table
    op.create_table('performance_metrics',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('endpoint', sa.String(length=255), nullable=True),
        sa.Column('method', sa.String(length=10), nullable=True),
        sa.Column('request_id', sa.String(length=36), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('visit_id', sa.Integer(), nullable=True),
        sa.Column('upload_time', sa.Float(), nullable=True),
        sa.Column('processing_time', sa.Float(), nullable=True),
        sa.Column('total_time', sa.Float(), nullable=True),
        sa.Column('db_query_time', sa.Float(), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('num_images', sa.Integer(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.String(length=500), nullable=True),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('timestamp', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('idx_perf_endpoint', 'performance_metrics', ['endpoint'])
    op.create_index('idx_perf_timestamp', 'performance_metrics', ['timestamp'])
    op.create_index('idx_perf_user_id', 'performance_metrics', ['user_id'])
    op.create_index('idx_perf_visit_id', 'performance_metrics', ['visit_id'])
    op.create_index('idx_perf_request_id', 'performance_metrics', ['request_id'])
    
    # Create view for performance summary
    op.execute("""
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
            SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END) as error_count,
            AVG(file_size) as avg_file_size,
            SUM(num_images) as total_images_processed
        FROM performance_metrics
        GROUP BY endpoint, DATE(timestamp);
    """)
    
    # Create materialized view for dashboard
    op.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS performance_dashboard_stats AS
        SELECT 
            endpoint,
            DATE_TRUNC('hour', timestamp) as hour,
            COUNT(*) as requests_per_hour,
            AVG(total_time) as avg_response_time,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY total_time) as median_response_time,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY total_time) as p95_response_time,
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY total_time) as p99_response_time
        FROM performance_metrics
        WHERE timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY endpoint, DATE_TRUNC('hour', timestamp);
    """)
    
    # Create index on materialized view
    op.execute("""
        CREATE INDEX idx_perf_dashboard_stats_hour 
        ON performance_dashboard_stats(hour);
    """)
    
    # Create function to refresh materialized view
    op.execute("""
        CREATE OR REPLACE FUNCTION refresh_performance_stats()
        RETURNS void AS $$
        BEGIN
            REFRESH MATERIALIZED VIEW CONCURRENTLY performance_dashboard_stats;
        END;
        $$ LANGUAGE plpgsql;
    """)
    
    # Create function to get real-time performance stats
    op.execute("""
        CREATE OR REPLACE FUNCTION get_realtime_performance_stats(minutes_back INTEGER DEFAULT 5)
        RETURNS TABLE (
            endpoint VARCHAR,
            avg_response_time FLOAT,
            request_count INTEGER,
            error_count INTEGER,
            avg_upload_time FLOAT,
            avg_processing_time FLOAT
        ) AS $$
        BEGIN
            RETURN QUERY
            SELECT 
                pm.endpoint,
                AVG(pm.total_time)::FLOAT as avg_response_time,
                COUNT(*)::INTEGER as request_count,
                SUM(CASE WHEN pm.status_code != 200 THEN 1 ELSE 0 END)::INTEGER as error_count,
                AVG(pm.upload_time)::FLOAT as avg_upload_time,
                AVG(pm.processing_time)::FLOAT as avg_processing_time
            FROM performance_metrics pm
            WHERE pm.timestamp >= NOW() - (minutes_back || ' minutes')::INTERVAL
            GROUP BY pm.endpoint;
        END;
        $$ LANGUAGE plpgsql;
    """)


def downgrade():
    # Drop functions
    op.execute("DROP FUNCTION IF EXISTS get_realtime_performance_stats(INTEGER)")
    op.execute("DROP FUNCTION IF EXISTS refresh_performance_stats()")
    
    # Drop materialized view
    op.execute("DROP MATERIALIZED VIEW IF EXISTS performance_dashboard_stats")
    
    # Drop view
    op.execute("DROP VIEW IF EXISTS performance_summary")
    
    # Drop indexes
    op.drop_index('idx_perf_request_id', table_name='performance_metrics')
    op.drop_index('idx_perf_visit_id', table_name='performance_metrics')
    op.drop_index('idx_perf_user_id', table_name='performance_metrics')
    op.drop_index('idx_perf_timestamp', table_name='performance_metrics')
    op.drop_index('idx_perf_endpoint', table_name='performance_metrics')
    
    # Drop table
    op.drop_table('performance_metrics')