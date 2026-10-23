from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Ensure the upload folder exists
if not os.path.exists(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])):
    os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']))

from models import User, IngestedDataLog, ThreatAlert, ThreatIntelligence # Import models after db is initialized
from routes import * # Import routes

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
    app.run(debug=True)