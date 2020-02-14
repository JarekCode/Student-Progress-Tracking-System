from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskApi.models import User

class RegisterForm(FlaskForm):
  # Form fields
  full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=30)])
  email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  register_form_submit = SubmitField('Sign Up')

  # Validate if an account with email passed in is already in the database
  def validate_email(self, email):
    # Get user from database by email. Will be None if email not taken
    user = User.query.filter_by(email = email.data.lower()).first()
    # If user is None, all good. Else, the user exists with the email so return error
    if(user):
      raise ValidationError('This email address is taken. Please log in or reset password.')


class LoginForm(FlaskForm):
  # Form fields
  email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  remember = BooleanField('Remember Me')
  login_form_submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
  # Form fields
  full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=30)])
  email = StringField('Email', validators=[DataRequired(), Email()])
  profile_picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
  update_account_form_submit = SubmitField('Update')

  # Validate if an account with email passed in is already in the database.
  def validate_email(self, email):
    # Only if the user changed their email, as it would be taken by themselves otherwise.
    if(email.data.lower() != current_user.email):
      # Get user from database by email. Will be None if email not taken
      user = User.query.filter_by(email = email.data.lower()).first()
      # If user is None, all good. Else, the user exists with the email so return error
      if(user):
        raise ValidationError('This email address is taken. Please log in or reset password.')


class RequestPasswordResetForm(FlaskForm):
  # Form fields
  email = StringField('Email', validators=[DataRequired(), Email()])
  request_reset_password_form_submit = SubmitField('Request Password Reset')

  # Validate if an account exists in the database with the email passed in.
  def validate_email(self, email):
    # Get user from database by email. Will be None if email does not exist
    user = User.query.filter_by(email = email.data.lower()).first()
    # If the user with the specified email is found, then all good. Else, the account with the
    # specified email does not exist in the database
    if(user is None):
      raise ValidationError('There is no account with this email. You must register first.')


class ResetPasswordForm(FlaskForm):
  # Form fields
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  reset_password_form_submit = SubmitField('Reset Password')


# For later development
class FeedbackForm(FlaskForm):
  # Form fields
  feedback = StringField('Feedback')
  feedbackSubmit = SubmitField('Submit')


class IndicatePauseForm(FlaskForm):
  # Form fields
  indicatePauseSubmit = SubmitField('Pause')