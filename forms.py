from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

class FeedbackForm(FlaskForm):
  feedback = StringField('Feedback')
  feedbackSubmit = SubmitField('Submit')

class IndicatePauseForm(FlaskForm):
  indicatePauseSubmit = SubmitField('Pause')