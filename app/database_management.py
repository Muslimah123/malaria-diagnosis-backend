# database_management.py

from .database import db
from sqlalchemy import text
from .utils import create_materialized_view, refresh_materialized_view

def create_patient_summary_view():
    create_materialized_view('patient_summary', """
        SELECT 
            p.patient_id,
            p.name,
            p.email,
            p.age,
            p.gender,
            p.address,
            p.created_at,
            v.visit_id AS latest_visit_id,
            v.visit_date AS latest_visit_date,
            d.status AS latest_diagnosis_status
        FROM 
            patients p
        LEFT JOIN LATERAL (
            SELECT visit_id, patient_id, visit_date
            FROM visits
            WHERE patient_id = p.patient_id
            ORDER BY visit_date DESC
            LIMIT 1
        ) v ON true
        LEFT JOIN LATERAL (
            SELECT visit_id, status
            FROM diagnosis_results
            WHERE visit_id = v.visit_id AND image_id IS NULL
            LIMIT 1
        ) d ON true
    """)

def refresh_patient_summary_view():
    refresh_materialized_view('patient_summary')

def create_all_materialized_views():
    create_patient_summary_view()
    # Add other materialized view creations here

def refresh_all_materialized_views():
    refresh_patient_summary_view()
    # Add other materialized view refreshes here

def initialize_database():
    create_all_materialized_views()

def optimize_database():
    # Directly connect to the engine and run VACUUM ANALYZE without a transaction
    with db.engine.connect() as connection:
        connection.execution_options(isolation_level="AUTOCOMMIT")  # Ensure autocommit mode is on
        connection.execute(text("VACUUM ANALYZE"))

# Add other database management functions as needed