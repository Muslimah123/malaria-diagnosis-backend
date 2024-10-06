# data_archiver.py

from datetime import datetime, timedelta
from sqlalchemy import text
from .models import Visit, DiagnosisResult, Image
from .database import db
import logging

class DataArchiver:
    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(__name__)

    def archive_old_data(self, months_old=12):
        try:
            cutoff_date = datetime.now() - timedelta(days=30*months_old)
            
            # Archive visits
            self._archive_visits(cutoff_date)
            
            # Archive diagnosis results
            self._archive_diagnosis_results(cutoff_date)
            
            # Archive images
            self._archive_images(cutoff_date)
            
            self.db.session.commit()
            self.logger.info(f"Successfully archived data older than {cutoff_date}")
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Error during archiving process: {str(e)}")

    def _archive_visits(self, cutoff_date):
        self.db.session.execute(text(f"""
            INSERT INTO archived_visits
            SELECT * FROM visits
            WHERE visit_date < :cutoff_date
        """), {'cutoff_date': cutoff_date})
        
        Visit.query.filter(Visit.visit_date < cutoff_date).delete()
        self.logger.info(f"Archived and deleted visits older than {cutoff_date}")

    def _archive_diagnosis_results(self, cutoff_date):
        self.db.session.execute(text(f"""
            INSERT INTO archived_diagnosis_results
            SELECT * FROM diagnosis_results
            WHERE result_date < :cutoff_date
        """), {'cutoff_date': cutoff_date})
        
        DiagnosisResult.query.filter(DiagnosisResult.result_date < cutoff_date).delete()
        self.logger.info(f"Archived and deleted diagnosis results older than {cutoff_date}")

    def _archive_images(self, cutoff_date):
        self.db.session.execute(text(f"""
            INSERT INTO archived_images
            SELECT * FROM images
            WHERE upload_date < :cutoff_date
        """), {'cutoff_date': cutoff_date})
        
        # Note: You might want to implement a file storage archiving mechanism here
        # to move the actual image files to a different storage location
        
        Image.query.filter(Image.upload_date < cutoff_date).delete()
        self.logger.info(f"Archived and deleted images older than {cutoff_date}")

    def retrieve_archived_data(self, start_date, end_date, table_name):
        try:
            query = text(f"""
                SELECT * FROM archived_{table_name}
                WHERE 
                    CASE 
                        WHEN :table_name = 'visits' THEN visit_date
                        WHEN :table_name = 'diagnosis_results' THEN result_date
                        WHEN :table_name = 'images' THEN upload_date
                    END
                    BETWEEN :start_date AND :end_date
            """)
            result = self.db.session.execute(query, {
                'table_name': table_name,
                'start_date': start_date,
                'end_date': end_date
            })
            return result.fetchall()
        except Exception as e:
            self.logger.error(f"Error retrieving archived data: {str(e)}")
            return []

    def create_archive_tables(self):
        try:
            self.db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS archived_visits (LIKE visits INCLUDING ALL);
                CREATE TABLE IF NOT EXISTS archived_diagnosis_results (LIKE diagnosis_results INCLUDING ALL);
                CREATE TABLE IF NOT EXISTS archived_images (LIKE images INCLUDING ALL);
            """))
            self.db.session.commit()
            self.logger.info("Archive tables created successfully")
        except Exception as e:
            self.db.session.rollback()
            self.logger.error(f"Error creating archive tables: {str(e)}")

data_archiver = DataArchiver(db)