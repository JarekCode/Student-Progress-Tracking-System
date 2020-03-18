from flask import render_template, request, url_for, flash, redirect, session
from flaskApi import app, db, bcrypt, mail, secretsFile
from flaskApi.forms import RegisterForm, LoginForm, UpdateAccountForm, RequestPasswordResetForm, ResetPasswordForm, FeedbackForm, IndicatePauseForm, CreateGuideForm, DeleteGuideForm
from flaskApi.templates import *
from flaskApi.models import User
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from PIL import Image
from flask_mail import Message
import pymongo
import secrets
import os
import json

# Look going for in future dashboeards: https://getbootstrap.com/docs/4.4/examples/dashboard/

# MongoDB
mongoClient = pymongo.MongoClient()
mongodb_fyp_db = mongoClient.fyp_db
mongodb_fyp_mvp = mongoClient.fyp_mvp


#---------#
# General #
#---------#

# Home
@app.route('/')
def home():
  # Return
  return render_template('home.html', page_title = 'FYP_MVP Home')


# Register
@app.route('/register', methods = ['GET', 'POST'])
def register():
  # Check if user is already logged in
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))

  # Register Form
  form = RegisterForm()
  
  # POST: form submit
  if (form.validate_on_submit()):
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    # Store the new user to DB
    user = User(full_name = form.full_name.data, email = form.email.data.lower(), password = hashed_password)
    db.session.add(user)
    db.session.commit()
    # Flash Message: account created
    flash('Your account has been created!', 'success')
    # Return redirect
    return redirect(url_for('login'))
  # Return
  return render_template('register.html', page_title = 'Register', form = form)


# Login
@app.route('/login', methods = ['GET', 'POST'])
def login():
  # Check if user is already logged in
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))

  # Login Form
  form = LoginForm()

  # POST: form submit
  if (form.validate_on_submit()):
    # Make sure the user exists in the database. Will return None if not
    user = User.query.filter_by(email = form.email.data.lower()).first()
    # Check if the user exists from above query and compare if passwords match
    if(user and bcrypt.check_password_hash(user.password, form.password.data)):
      # Login using the flask_login extention
      login_user(user, remember = form.remember.data)
      # Using 'get' returns None if it does not exist
      next_page = request.args.get('next')
      # Return redirect to arg in url if it exists, not the default home page
      if(next_page):
        return redirect(next_page)
      # Return redirect default home page
      else:
        return redirect(url_for('home'))
    else:
      # # Flash Message: login unsuccessful
      flash(f'Login Unsuccessful. Please check your Email and Password.', 'danger')
  # Return
  return render_template('login.html', page_title = 'Login', form = form)


# Logout
@app.route('/logout')
def logout():
  # Logout the user
  logout_user()
  # Return redirect
  return redirect(url_for('home'))


# Saving the uploaded profile picture to DB
def save_profile_picture(form_picture):
  # 1. Change the name of the picture to random hex so it does not collide
  random_hex = secrets.token_hex(8)
  # 2. Create a file name with the extension uploaded by user
  # returns two things (file_name, file_extension) only need file_extension
  _, file_extension = os.path.splitext(form_picture.filename)
  # 3. Create the file name
  picture_filename = random_hex + file_extension
  # 4. Get the full path to where the picture will be saved
  picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_filename)
  # 5. Resize the image
  size = (250, 250)
  i = Image.open(form_picture)
  i.thumbnail(size)
  # 6. Save the resized picture to the file system
  i.save(picture_path)
  # Return picture file name
  return picture_filename


# Account
# @login_required - Has to be logged in to access this route
@app.route('/account', methods = ['GET', 'POST'])
@login_required
def account():
  # Update Account Form
  form = UpdateAccountForm()

  # POST: form submit
  if (form.validate_on_submit()):
    # New profile_picture not required, so check if it is there
    if (form.profile_picture.data):
      # Save the picture to the file system
      picture_filename = save_profile_picture(form.profile_picture.data)
      # Save the picture_filename to the user database
      current_user.image_file = picture_filename

    # Update full_name in DB
    current_user.full_name = form.full_name.data
    # Update email in DB
    current_user.email = form.email.data
    # Flash Message: account updated
    flash('Your account has been updated.', 'success')
    # Update the user database
    db.session.commit()

    # Return redirect
    return redirect(url_for('account'))
  # GET: Autofill the Update Account Form
  elif(request.method == 'GET'):
    form.full_name.data = current_user.full_name
    form.email.data = current_user.email
  # Get the picture name from database 'current_user.image_file' that is located in static/profile_pics/current_user.image_file
  image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
  # Return
  return render_template('account.html', page_title = 'Account', image_file = image_file, form = form)


# Send email with password reset token
def send_password_reset_email(user):
  token = user.get_reset_password_token()
  msg = Message('Password Reset Request', sender = secretsFile.getItem('mailUsername'), recipients = [user.email])
  msg.body = f'''To reset your password, visit the following link:

{url_for('reset_token', token = token, _external = True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
  # Send the email
  mail.send(msg)


# User requests to reset a password providing a new email address
@app.route('/reset_password', methods = ['GET', 'POST'])
def reset_request():
  # Check if user is already logged in,
  # User should be logged out before resetting password.
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))
  # Request Password Reset Form
  form = RequestPasswordResetForm()
  # POST: form submit
  if (form.validate_on_submit()):
    # Get the user from database using the email from the form
    user = User.query.filter_by(email=form.email.data).first()
    # Send this user an email with the token to reset the password
    send_password_reset_email(user)
    # Flash Message: email sent
    flash('An email has been sent with instructions on how to reset your password!', 'info')
    # Return redirect
    return redirect(url_for('login'))

  # Return
  return render_template('reset_request.html', page_title = 'Reset Password', form = form)


# Using a valid token, user sets a new password
@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_token(token):
  # Check if user is already logged in,
  # User should be logged out before resetting password.
  if(current_user.is_authenticated):
    # Return redirect
    return redirect(url_for('home'))
  # Verify the token from the email, None if token not valid/expired
  # User payload from the database is received if the token is valid
  user = User.verify_password_reset_token(token)
  if(user is None):
    flash('The token is invalid/expired.', 'warning')
    return redirect(url_for('reset_request'))
  # From here on, the token is valid, so create the password reset form
  form = ResetPasswordForm()
  # POST: form submit
  if (form.validate_on_submit()):
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    # Setting the new hashed password for the user
    user.password = hashed_password
    db.session.commit()
    # Flash Message: account created
    flash('Your password has been updated!', 'success')
    # Return redirect
    return redirect(url_for('login'))
  # Return
  return render_template('reset_token.html', page_title = 'Reset Password', form = form)

#------------#
# Instructor #
#------------#

# View a list of all guides
@app.route('/instructor/guides')
@login_required
def instructorGuides():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get all guides from the DB
  allGuides = mongodb_fyp_db.guides.find()
  # List passed in to template to display all guides in DB
  listOfGuides = []
  # Add relevant info for all guides to list
  for guide in allGuides:
    listOfGuides.append({'guide_code': guide['guide_code'], 'guide_name': guide['guide_name'], 'last_edited_time': guide['last_edited_time']})
  # Return
  return render_template('instructorGuides.html', page_title = 'Guides', listOfGuides = listOfGuides)


# Create a new guide
@app.route('/instructor/guide/create', methods = ['GET', 'POST'])
@login_required
def instructorGuideCreate():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Create Guide Form
  form = CreateGuideForm()
  # POST
  if(form.validate_on_submit()):
    # Extract the data from the form
    guideCode = form.guide_code.data
    guideName = form.guide_name.data
    # Store the initial empty guide to MongoDB
    info = {'guide_code': str(guideCode), 'guide_name': str(guideName), 'guide_content': [], 'last_edited_time': datetime.utcnow()}
    mongodb_fyp_db.guides.insert_one(info)
    # Flash Message: guide created
    flash('The guide has been created!', 'success')
    # Return
    return redirect(url_for('instructorGuides'))
  # GET
  # Return
  return render_template('instructorGuideCreate.html', page_title = 'Create Guide', form = form)


# Edit a guide
@app.route('/instructor/guide/edit/<guide_code>', methods = ['GET', 'POST'])
@login_required
def instructorGuideEdit(guide_code):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide based on the code
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_code": str(guide_code)} )
  
  print('guideFromDb:', guideFromDb)
  # If the guide is found, continue
  if(guideFromDb):
    # POST: save the edited info about the guide back to the database
    if(request.method == 'POST'):
      # Process string to json from QuillJS
      guideString = request.values.get('guide')
      guide = json.loads(guideString)
      # Update guide_content in mongoDB
      mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "guide_content": guide['ops'] } })
      # Update guide last_edited_time
      mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "last_edited_time": datetime.utcnow() } })
      # Flash Message: guide updated
      flash(f'The "{guideFromDb["guide_name"]}" guide has been updated!', 'success')
      # Return
      return redirect(url_for('instructorGuides'))

    # GET
    # Render the guide in QuillJS using javascript the the 'guideFromDb' variable passed into the template
    # NOTE: 'guideContent' must use json.dumps
    return render_template('instructorGuideEdit.html', guideContent = json.dumps(guideFromDb['guide_content']), guideName = guideFromDb['guide_name'], guideCode = guideFromDb['guide_code'], page_title = "{} - Edit".format(guideFromDb['guide_name']))

  # Else, return error that the guide was not found
  else:
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

# Delete a guide
@app.route('/instructor/guide/delete', methods = ['GET', 'POST'])
@login_required
def instructorGuideDelete():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  pass

  # Delete Guide Form
  form = DeleteGuideForm()
  # POST
  if(form.validate_on_submit()):
    # Retrieve the guide code from the form
    guideCode = form.guide_code.data
    # Delete the guide from mongoDB
    mongodb_fyp_db.guides.delete_one({ "guide_code": guideCode })
    # Flash Message: guide deleted
    flash('The guide has been deleted!', 'success')
    # Return
    return redirect(url_for('instructorGuides'))

  # GET
  # Flash Message: warning
  flash('Once the guide is deleted, all the guide data will be erased from the database!', 'danger')
  # Return
  return render_template('instructorGuideDelete.html', page_title = 'Delete Guide', form = form)


# For later development

#---------#
# Student #
#---------#

@app.route('/instructor')
@login_required
def instructor():
  # Get all items from studentStats
  allInfoItems = mongodb_fyp_mvp.studentStats.find()
  # Get all feedback from studentFeedback
  allFeedbackItems = mongodb_fyp_mvp.studentFeedback.find()
  # Return
  return render_template('instructor.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Instructor Dashboard")


@app.route('/guide/<guide_code>/<exercise_number>', methods=['GET','POST'])
@login_required
def guide(guide_code, exercise_number):
  try:
    # First Summary, when the end of guide is reached
    if(exercise_number == 'summary'):
      # Redirect to guideSummary()
      return redirect(url_for('guideSummary'))

    # Read guide from DB based on 'guide_code' and 'exercise_number' in URL
    guide = mongodb_fyp_mvp.guides.find_one( {"guide_code": guide_code} )

    # Extract only the exercise wanted from the array
    exercise = guide["guide_content"][int(exercise_number)]

    # Calculate Exercise Numbers
    c_exercise_number = int(exercise_number)
    # If 0, then can't go to negative
    if(int(exercise_number) == 0):
      n_exercise_number = int(exercise_number) + 1
      p_exercise_number = 0
    # If last exercise, go to summary at the end
    elif(int(exercise_number) == len(guide["guide_content"]) - 1):
      n_exercise_number = 'summary'
      p_exercise_number = int(exercise_number) - 1
    else:
      p_exercise_number = int(exercise_number) - 1
      n_exercise_number = int(exercise_number) + 1

    # Feedback form
    feedbackForm = FeedbackForm()
    # Pause form
    pauseForm = IndicatePauseForm()

    # On submit Feedback (POST)
    if feedbackForm.feedbackSubmit.data and feedbackForm.validate_on_submit():
      # Store feedback in MongoDB_fyp_mvp (POST)
      feedbackToStore = {'student_feedback_type': 'exercise_feedback', 'student_feedback': str(feedbackForm.feedback.data), 'guide_code': guide_code, 'exercise_number': exercise_number}
      mongodb_fyp_mvp.studentFeedback.insert_one(feedbackToStore)

      # Flash Message: feedback sent
      flash('Feedback Sent!', 'success')

      # Return (POST)
      return render_template('guide.html', exercise = exercise, current_exercise_number = c_exercise_number, previous_exercise_number = p_exercise_number, next_exercise_number = n_exercise_number, guide_code = guide_code, url_root = request.url_root, form = feedbackForm, pause_form = pauseForm)

    # On submit Pause (POST)
    if pauseForm.indicatePauseSubmit.data and pauseForm.validate_on_submit():
      # Store statiatics info to DB (POST)
      info = {'action': 'pause', 'guide_code': guide_code, 'exercise_number': exercise_number, 'time': datetime.utcnow()}
      mongodb_fyp_mvp.studentStats.insert_one(info)

      # Flash Message: paused
      flash('Paused.', 'warning')

      # Send all the info required in 'messages' to resume in the same exercise
      messages = json.dumps({'current_exercise_number': exercise_number, 'guide_code': guide_code, 'url_root': request.url_root})
      session['messages'] = messages

      # Return (POST)
      return redirect(url_for('guidePause', messages=messages))

    # Store statiatics info to DB
    info = {'action': 'exercise', 'guide_code': guide_code, 'exercise_number': exercise_number, 'time': datetime.utcnow()}
    mongodb_fyp_mvp.studentStats.insert_one(info)

    # Return
    return render_template('guide.html', exercise = exercise, current_exercise_number = c_exercise_number, previous_exercise_number = p_exercise_number, next_exercise_number = n_exercise_number, guide_code = guide_code, url_root = request.url_root, form = feedbackForm, pause_form = pauseForm)

  except Exception as e:
    return ("Page not found: {}".format(e))


@app.route('/guidePause')
@login_required
def guidePause():
  # Retrieve the info for the resume button that is passed as 'messages'
  messages = request.args['messages']
  messages = session['messages']

  # Return
  return render_template('guidePause.html', messages=json.loads(messages))


@app.route('/guideSummary', methods=['GET','POST'])
@login_required
def guideSummary():

  # NOTE they will be filtered for the person logged in

  # Get all items from studentStats
  allInfoItems = mongodb_fyp_mvp.studentStats.find()
  # Get all feedback from studentFeedback
  allFeedbackItems = mongodb_fyp_mvp.studentFeedback.find()

  # Feedback form
  feedbackForm = FeedbackForm()

  # On submit Feedback (POST)
  if feedbackForm.feedbackSubmit.data and feedbackForm.validate_on_submit():
    # Store feedback in MongoDB (POST)
    feedbackToStore = {'student_feedback_type': 'class_feedback', 'student_feedback': str(feedbackForm.feedback.data), 'guide_code': 'guide_code', 'exercise_number': 'class feedback'}
    mongodb_fyp_mvp.studentFeedback.insert_one(feedbackToStore)

    # Show flask message and return home (POST)
    flash('Class Feedback Sent!', 'success')
  
    return render_template('guideSummary.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Student Summary", form = feedbackForm)

  return render_template('guideSummary.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Student Summary", form = feedbackForm)