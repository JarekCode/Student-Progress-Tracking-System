from datetime import datetime
from flaskApi import db, login_manager, app
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

# Need to put in for the extention to fina a user by id
# https://flask-login.readthedocs.io/en/latest/
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

# Class also inherits from UserMixin (To manage sessions)
# https://flask-login.readthedocs.io/en/latest/#flask_login.UserMixin
class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key = True)
  full_name = db.Column(db.String(30), unique = True, nullable = False)
  email = db.Column(db.String(130), unique = True, nullable = False)
  password = db.Column(db.String(60), nullable = False)
  image_file = db.Column(db.String(20), nullable = False, default = 'default.jpg')
  role = db.Column(db.String(20), nullable = False, default = 'student')
  date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)

  # Setting up a timed reset password token with app['SECRET_KEY'] and expiration time
  def get_reset_password_token(self, expire_sec = 1800):
    s = Serializer(app.config['SECRET_KEY'], expire_sec)
    # Returning the token with the payload of (User) 'id'
    return s.dumps({'user_id': self.id}).decode('utf-8')

  @staticmethod
  def verify_password_reset_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    # Token could be invalid/timed out, causing an exception
    try:
      user_id = s.loads(token)['user_id']
      return User.query.get(user_id)
    except:
      return None

  # Object's repr print for debuging
  def __repr__(self):
    return f"User('{self.full_name}', '{self.email}', {self.role}', '{self.date_created}')"