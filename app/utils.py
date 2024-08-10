import os
from werkzeug.utils import secure_filename

def save_image(file, upload_folder):
    if not file:
        return None
    
    # Ensure the upload folder exists
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)
    
    return filepath
