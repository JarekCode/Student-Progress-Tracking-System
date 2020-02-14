from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flaskApi import secretsFile
from flask_mail import Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = secretsFile.getItem('appConfigSecretKey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///credentials.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
# Used for @login_required decorator for routes
login_manager.login_view = 'login'
# Create a nice message for @login_required
login_manager.login_message_category = 'info'

# Flask Mail set up
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# Can move to environment variables, in secretsFile.py for now
app.config['MAIL_USERNAME'] = secretsFile.getItem('mailUsername')
app.config['MAIL_PASSWORD'] = secretsFile.getItem('mailPassword')
mail = Mail(app)

from flaskApi import routes