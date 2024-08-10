from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import os


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
env = os.environ.get('APP_ENVIRONMENT', 'development')
app.config.from_object(f'config.{env.capitalize()}Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)  # Initialize Marshmallow 

#configure CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})


from . import models

# Register routes
from .routes import api as routes_api, init_jwt

# Initialize JWT
init_jwt(app)

# Register API blueprint
app.register_blueprint(routes_api, url_prefix='/api')