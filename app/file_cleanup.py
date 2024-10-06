import os
from datetime import datetime
from flask import current_app

def cleanup_archived_image_files(cutoff_date):
    # Retrieve archived image data from the archive table via data_archiver
    archived_images = current_app.data_archiver.retrieve_archived_data(
        start_date=datetime.min,  # From the earliest possible date
        end_date=cutoff_date,     # Up to the cutoff date
        table_name='images'       # Assuming 'images' is the table for archived image data
    )

    # Iterate through archived images and delete files older than the cutoff date
    for image in archived_images:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], image.file_path)
        
        # Check if the file exists before attempting to delete it
        if os.path.exists(file_path):
            os.remove(file_path)
            current_app.logger.info(f"Deleted archived image file: {file_path}")
        else:
            current_app.logger.warning(f"File not found: {file_path}")
