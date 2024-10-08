# malaria-diagnosis-backend
# Database Migration Documentation


## Overview

This document outlines the recent optimizations and changes made to the MalariaAI backend application. These changes aim to improve performance, scalability, and maintainability of the system.

## Database Schema Changes

### New Indexes

We've added several new indexes to improve query performance:

1. User-related indexes:
   - `idx_user_email` on `users(email)`
   - `idx_user_google_id` on `users(google_id)`
   - `idx_user_role` on `users(role)`

2. Patient-related indexes:
   - `idx_patient_name` on `patients(name)`
   - `idx_patient_email` on `patients(email)`
   - `idx_patient_created_at` on `patients(created_at)`
   - `idx_patient_search_vector` on `patients(search_vector)`

3. Visit-related indexes:
   - `idx_visit_patient_id` on `visits(patient_id)`
   - `idx_visit_date` on `visits(visit_date)`

4. Image-related indexes:
   - `idx_image_visit_id` on `images(visit_id)`
   - `idx_image_processing_status` on `images(processing_status)`
   - `idx_image_upload_date` on `images(upload_date)`

5. Diagnosis-related indexes:
   - `idx_diagnosis_visit_id` on `diagnosis_results(visit_id)`
   - `idx_diagnosis_image_id` on `diagnosis_results(image_id)`
   - `idx_diagnosis_result_date` on `diagnosis_results(result_date)`
   - `idx_diagnosis_status` on `diagnosis_results(status)`

6.  Chat-related indexes:
   - `idx_chat_user_id` on `chats(user_id)`
   - `idx_chat_participant_id` on `chats(participant_id)`
   - `idx_chat_last_message_time` on `chats(last_message_time)`

7. Message-related indexes:
   - `idx_message_chat_id` on `messages(chat_id)`
   - `idx_message_sender_id` on `messages(sender_id)`
   - `idx_message_timestamp` on `messages(timestamp)`

8.  Notification-related indexes:
   - `idx_notification_user_id` on `notifications(user_id)`
   - `idx_notification_read` on `notifications(read)`

9. Backup code indexes:
   - `idx_backup_code_user_id` on `backup_codes(user_id)`

10.  Remembered device indexes:
   - `idx_remembered_device_user_id` on `remembered_devices(user_id)`
   - `idx_remembered_device_token` on `remembered_devices(token)`

11. Metadata-related indexes:
   -`idx_metadata_entity` on `metadata(entity_id, entity_type)`
   -`idx_metadata_key` on `metadata(key)`


### New Columns

- Added `search_vector` column to the `patients` table for full-text search capabilities.

### New Constraints

- Added `unique_patient_id` constraint on `patients(patient_id)`.

## New Functionalities

### Data Archiving

Implemented a `DataArchiver` class to manage long-term data storage:

- Automatic archiving of old visits, diagnosis results, and images.
- Creation of separate archive tables for each entity type.
- Scheduled archiving process to run periodically.

### Full-Text Search

Added full-text search capability for the `patients` table:

- Utilizes PostgreSQL's `tsvector` type for efficient text searching.
- Automatic updating of search vectors when patient data is modified.

### Query Optimization

Implemented a `QueryOptimizer` class to enhance query performance:

- Query analysis and optimization.
- Query caching for frequently accessed data.
- Performance monitoring for slow queries.

## Performance Improvements

1. Materialized Views:
   - Created materialized views for complex, frequently-accessed data.
   - Implemented scheduled refreshing of materialized views.

2. Connection Pooling:
   - Optimized database connection management to reduce overhead.

3. Batch Processing:
   - Implemented batch processing for image analysis tasks.

## New API Endpoints

1. `/api/v1/archived-data/<table_name>`:
   - Retrieves archived data for a specified table and date range.

2. `/api/optimize-query`:
   - Analyzes and optimizes a given SQL query.

## Maintenance Tasks

Added new Flask CLI commands for database maintenance:

1. `flask optimize-db`:
   - Runs database optimization tasks.
   - Creates archive tables.

2. `flask archive-old-data`:
   - Manually triggers the data archiving process.


## Running the Application

This backend application is designed to work in conjunction with a React frontend. Follow these steps to set up and run the backend:

### Prerequisites

- Python 3.8 or higher
- PostgreSQL 12 or higher
- pip (Python package manager)
- virtualenv (recommended for creating isolated Python environments)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/Muslimah123/malaria-diagnosis-backend.git
   cd malaria-diagnosis-backend
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root directory and add the following variables:
   ```
   DATABASE_URL=postgresql://username:password@localhost/malariaai
   JWT_SECRET_KEY=your_secret_key
   FLASK_APP=app
   FLASK_ENV=development
   ```

5. Initialize the database:
   ```
   flask db upgrade
   flask init-db
   ```

### Running the Application

1. Start the Flask development server:
   ```
   flask run
   ```

2. The backend will be available at `http://localhost:5000`.

### Connecting to the React Frontend

This backend is designed to work with a React frontend. Ensure that your frontend is configured to make API requests to the correct backend URL.

1. In your React application, set the API base URL:
   ```javascript
   // In your frontend config or .env file
   REACT_APP_API_URL=http://localhost:5000/api
   ```

2. Use this base URL when making API requests from your React components.

### Development Workflow

1. Make changes to the backend code as needed.
2. Run tests to ensure functionality:
   ```
   pytest
   ```
3. If you make changes to the database models, create and apply migrations:
   ```
   flask db migrate -m "Description of changes"
   flask db upgrade
   ```

4. Restart the Flask server to apply changes.

## Troubleshooting

- If you encounter database-related issues, ensure your PostgreSQL server is running and the DATABASE_URL is correct.
- For authentication issues, check that the JWT_SECRET_KEY is properly set and consistent between backend and frontend.


## Conclusion

These optimizations and new features significantly enhance the performance and scalability of the MalariaAI backend. Regular monitoring and further optimizations may be necessary as the system grows and usage patterns evolve.
