


from .factory import create_app
from .database import db
# from .celery_config import celery

app, socketio = create_app()

# Register blueprints
from .routes import api as routes_api
from .archived_data_routes import archived_data_bp  # Ensure you import the archived_data_bp


app.register_blueprint(routes_api, url_prefix='/api')
app.register_blueprint(archived_data_bp, url_prefix='/api/v1')


