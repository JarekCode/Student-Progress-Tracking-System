#!/bin/env/python
from flask import render_template, request, url_for, flash, redirect, session
from flaskApi import app, db, bcrypt, mail, secretsFile
from flaskApi.forms import RegisterForm, LoginForm, UpdateAccountForm, RequestPasswordResetForm, ResetPasswordForm, FeedbackForm, IndicatePauseForm, CreateGuideForm, DeleteGuideForm, RenameGuideForm, CreateClassForm, EditClassForm, AddStudentToClassForm
from flaskApi.templates import *
from flaskApi.models import User
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, date, timedelta
from PIL import Image
from flask_mail import Message
from bson import ObjectId
import pymongo
import secrets
import os
import json
import pytz

# MongoDB
mongoClient = pymongo.MongoClient()
mongodb_fyp_db = mongoClient.fyp_db
mongodb_fyp_mvp = mongoClient.fyp_mvp

#--------#
# Errors #
#--------#

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('pageNotFound.html', page_title = 'Page Not Found'), 404

@app.errorhandler(500)
def internal_error(e):
    # note that we set the 500 status explicitly
    return render_template('internalError.html', page_title = 'Internal Error'), 500

#---------#
# General #
#---------#

# Home
@app.route('/')
def home():
  if(current_user.is_authenticated):
    if(current_user.role == 'student'):
      # Return student
      return redirect(url_for('studentHome'))
    elif(current_user.role == 'instructor'):
      # Return instructor
      return redirect(url_for('instructorHome'))
    elif(current_user.role == 'administrator'):
      # Return admin
      return redirect(url_for('adminHome'))
  else:
    # Return unauthenticated
    return render_template('unauthenticatedHome.html', page_title = 'FYP_MVP Home')


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

# Instructor home
@app.route('/instructor')
@login_required
def instructorHome():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  return render_template('instructorHome.html', page_title = 'Home')


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
    listOfGuides.append({'guide_name': guide['guide_name'], 'last_edited_time': guide['last_edited_time']})

  orderedGuides = sorted(listOfGuides, key=lambda k: k['guide_name'])

  # Return
  return render_template('instructorGuides.html', page_title = 'Guides', listOfGuides = orderedGuides)


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
    guideName = form.guide_name.data
    # Store the initial empty guide to MongoDB
    info = {'guide_name': str(guideName), 'number_of_exercises': 0, 'last_edited_time': datetime.utcnow(), 'guide_content': []}
    mongodb_fyp_db.guides.insert_one(info)
    # Flash Message: guide created
    flash('The guide has been created!', 'success')
    # Return
    return redirect(url_for('instructorGuides'))
  # GET
  # Return
  return render_template('instructorGuideCreate.html', page_title = 'Create Guide', form = form)


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
    # Retrieve the guide from the form
    guideName = form.guide_name.data
    # Delete the guide from mongoDB
    mongodb_fyp_db.guides.delete_one({ "guide_name": guideName })
    # Flash Message: guide deleted
    flash('The guide has been deleted!', 'success')
    # Return
    return redirect(url_for('instructorGuides'))

  # GET
  # Flash Message: warning
  flash('Once the guide is deleted, all the guide data will be erased from the database! Students will lose access to a guide if it is deleted!', 'danger')
  # Return
  return render_template('instructorGuideDelete.html', page_title = 'Delete Guide', form = form)


# View a list of all exercises in a given guide
@app.route('/instructor/guide/<guide_name>', methods = ['GET', 'POST'])
@login_required
def instructorGuide(guide_name):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  return render_template('instructorGuideExercises.html', guide = guideFromDb, page_title = 'Guide Exercises')


# Rename a guide
@app.route('/instructor/guide/<guide_name>/rename', methods = ['GET', 'POST'])
@login_required
def instructorGuideRename(guide_name):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  form = RenameGuideForm()
  # POST
  if(form.validate_on_submit()):
    # Retrieve the guide from the form
    guideName = form.guide_name.data
    # Delete the guide from mongoDB
    mongodb_fyp_db.guides.update_one({ "guide_name": guide_name }, { "$set": { "guide_name": guideName } })
    # Flash Message: guide deleted
    flash('The guide name has been updated!', 'success')
    # Return
    return redirect(url_for('instructorGuides'))
  # GET
  # Flash Message: warning
  flash('Once the guide name is changed, all existing classes using the old guide name will no longer be valid! Students will lose access to a guide if it is renamed!', 'danger')
  # Return
  return render_template('instructorGuideRename.html', page_title = 'Rename Guide', form = form)


# Rearrange the order of two exercises
@app.route('/instructor/guide/<guide_name>/rearrangeExercises/<ex_1>/<ex_2>')
@login_required
def instructorGuideRenarrangeExercises(guide_name, ex_1, ex_2):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Check if the exercise number is in the range of the actual guide stored in MongoDB
  try:
    if(int(ex_1) <= 0 or int(ex_1) > int(guideFromDb['number_of_exercises'])):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')
    if(int(ex_2) <= 0 or int(ex_2) > int(guideFromDb['number_of_exercises'])):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')
  except:
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Change the position of ex_1 with position of ex_2 in guide['guide_content']list
  # 1.1 Store the ex_1 item
  ex1_item = guideFromDb['guide_content'][int(ex_1) - 1]
  # 1.1 Store the ex_2 item
  ex2_item = guideFromDb['guide_content'][int(ex_2) - 1]
  try:
    # NOTE: Must be in this order, one index at a time. ie. the '"$position": (int(ex_1) - 1)' part
    # Index of Ex_1 | Unset/Replace/Delete(the unset one) (One at a time)
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$unset": { "guide_content." + str(int(ex_1) - 1): 1 }})
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$push": { "guide_content": { "$each": [ex2_item], "$position": (int(ex_1) - 1)} }})
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$pull": { "guide_content": None }})
    # Index of Ex_2 | Unset/Replace/Delete(the unset one) (One at a time)
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$unset": { "guide_content." + str(int(ex_2) - 1): 1 }})
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$push": { "guide_content": { "$each": [ex1_item], "$position": (int(ex_2) - 1)} }})
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$pull": { "guide_content": None }})
  except Exception as e:
    # Flash Message: error
    flash(f'Failed to delete exercise rearrange exercises! ({e})', 'danger')
    # Return
    return redirect(url_for('instructorGuide', guide_name = guide_name))
  # Flash Message: error
  flash(f'Rearrange Successful! Exercise " {ex_1} " is now at position " {ex_2} ".', 'success')
  # Return
  return redirect(url_for('instructorGuide', guide_name = guide_name))



# Create a new exercise for a given guide
@app.route('/instructor/guide/<guide_name>/createExercise')
@login_required
def instructorCreateExercise(guide_name):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Increment 'number_of_exercises' in MongoDB
  # Update number_of_exercises in mongoDB
  updated_number_of_exercises = guideFromDb['number_of_exercises'] + 1
  mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "number_of_exercises": updated_number_of_exercises } })

  # Add a new empty list to 'guide_content' in MongoDB
  mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$push": { "guide_content": [] } })

  # Update 'last_edited_time' in MongoDB
  mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "last_edited_time": datetime.utcnow() } })

  # Return
  return redirect(url_for('instructorGuide', guide_name = guide_name))


# Delete exercise from a given guide
@app.route('/instructor/guide/<guide_name>/deleteExercise/<exercise_number>')
@login_required
def instructorDeleteExercise(guide_name, exercise_number):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  
  # Check if the exercise number is in the range of the actual guide stored in MongoDB
  try:
    if(int(exercise_number) <= 0 or int(exercise_number) > int(guideFromDb['number_of_exercises'])):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')
  except:
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  try:
    # Delete the exercise / needs two steps to delete by index
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$unset": { "guide_content." + str(int(exercise_number) - 1): 1 }})
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$pull": { "guide_content": None }})

    # Decrease the number of exercises by 1
    updated_number_of_exercises = guideFromDb['number_of_exercises'] - 1
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "number_of_exercises": updated_number_of_exercises } })

    # Update 'last_edited_time' in MongoDB
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "last_edited_time": datetime.utcnow() } })

    # Flash Message: guide updated
    flash(f'Deleted exercise {exercise_number}. The order of exercises has been updated!', 'success')
    # Return
    return redirect(url_for('instructorGuide', guide_name = guide_name))
  except Exception as e:
    # Flash Message: error
    flash(f'Failed to delete exercise "{exercise_number}"! ({e})', 'danger')
    # Return
    return redirect(url_for('instructorGuide', guide_name = guide_name))


# Edit a given exercise in a given guide
@app.route('/instructor/guide/<guide_name>/exercise/<exercise_number>', methods = ['GET', 'POST'])
@login_required
def instructorEditExercise(guide_name, exercise_number):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide based on the name
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )

  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Check if the exercise number is in the range of the actual guide stored in MongoDB
  try:
    if(int(exercise_number) <= 0 or int(exercise_number) > int(guideFromDb['number_of_exercises'])):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')
  except:
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # POST: save the edited info about the guide back to the database
  if(request.method == 'POST'):
    # Process string to json from QuillJS
    guideExerciseString = request.values.get('guide')
    guide = json.loads(guideExerciseString)
    # Update guide_content in MongoDB
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "guide_content." + str((int(exercise_number) - 1)): guide['ops'] } })
    # Update guide last_edited_time
    mongodb_fyp_db.guides.update_one({ "guide_name": guideFromDb['guide_name'] }, { "$set": { "last_edited_time": datetime.utcnow() } })
    # Flash Message: guide updated
    flash(f'The "{guideFromDb["guide_name"]}" guide has been updated!', 'success')
    # Return
    return redirect(url_for('instructorGuide', guide_name = guide_name))

  # Render the guide in QuillJS using javascript the the 'guideFromDb' variable passed into the template
  # NOTE: 'guideContent' must use json.dumps
  return render_template('instructorGuideExerciseEdit.html', guideContent = json.dumps(guideFromDb['guide_content'][(int(exercise_number) - 1)]), guideName = guideFromDb['guide_name'], exercise_number = exercise_number, page_title = "{} - Edit".format(guideFromDb['guide_name']))


# Classes Menu
@app.route('/instructor/classes')
@login_required
def instructorClasses():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Get all classes from the DB
  allClasses = mongodb_fyp_db.classes.find()
  # List passed in to template to display all classes in DB
  listOfClasses = []
  # Add relevant info for all classes to list
  for theClass in allClasses:
    listOfClasses.append({'class_id': theClass['_id'], 'start_date': theClass['start_date'], 'finish_date': theClass['finish_date'], 'start_date_local': theClass['start_date_local'], 'finish_date_local': theClass['finish_date_local'], 'timezone': theClass['timezone'], 'instructor_email': theClass['instructor_email'], 'guide_name': theClass['guide_name'], 'student_emails': theClass['student_emails']})

  # Re-order the list by start_date
  orderedClasses = sorted(listOfClasses, key=lambda k: k['start_date'])
  # Split the old classed into a second list
  pastClasses = []
  normalClasses = []
  currentTime = datetime.utcnow()
  for c in orderedClasses:
    if(c['finish_date'] < currentTime):
      pastClasses.append(c)
    else:
      normalClasses.append(c)

  # Return
  return render_template('instructorClasses.html', page_title = 'Classes', listOfClasses = normalClasses, listOfPastClasses = pastClasses)


# https://stackoverflow.com/questions/1357711/pytz-utc-conversion
def toUTC(d, tz):
  return tz.normalize(tz.localize(d)).astimezone(pytz.utc)


# Create a new class
@app.route('/instructor/class/create', methods = ['GET', 'POST'])
@login_required
def instructorClassCreate():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get all the instructors into a list
  instructorData = []
  instructors = User.query.filter_by(role = 'instructor')
  for i in instructors:
    instructorData.append((i.email, i.full_name))
  
  # Get all the guides into a list
  guideData = []
  # MongoDB
  mongoClient = pymongo.MongoClient()
  mongodb_fyp_db = mongoClient.fyp_db
  # Get the guide with the passed in name from the database
  guides = mongodb_fyp_db.guides.find()
  mongoClient.close()
  for i in guides:
    guideData.append((i['guide_name'], i['guide_name']))

  # Create Class Form
  form = CreateClassForm()
  form.instructor_email.choices = instructorData
  form.guide_name.choices = guideData
  # Getting the available timezones from secretsFile.py
  form.timezone.choices = secretsFile.getItem('classTimezones')
  
  # POST
  if(form.validate_on_submit()):
    # Extract the data from the form
    classStartDate = form.start_date.data
    classTimezone = form.timezone.data
    instructorEmail = form.instructor_email.data
    guideName = form.guide_name.data

    # Start Date
    classStartDateDT = datetime.combine(classStartDate, datetime.min.time())
    # Finish Date
    classFinishDateDT = classStartDateDT.replace(hour = 23)
    classFinishDateDT = classFinishDateDT.replace(minute = 59)

    # Use the timezone to convert back to UTC (time on server)
    tz = pytz.timezone(classTimezone)
    classStartDateDT_UTC = toUTC(classStartDateDT, tz)
    classFinishDateDT_UTC = toUTC(classFinishDateDT, tz)

    # Store the initial class to MongoDB
    info = {'start_date': classStartDateDT_UTC, 'finish_date': classFinishDateDT_UTC, 'start_date_local': classStartDateDT, 'finish_date_local': classFinishDateDT, 'timezone': classTimezone, 'instructor_email': str(instructorEmail), 'guide_name': str(guideName), 'student_emails': []}
    mongodb_fyp_db.classes.insert_one(info)
    # Flash Message: class created
    flash('The class has been created!', 'success')
    # Return
    return redirect(url_for('instructorClasses'))
  # GET
  # Return
  return render_template('instructorClassCreate.html', page_title = 'Create Class', form = form)


# View a class
@app.route('/instructor/class/<class_id>', methods = ['GET', 'POST'])
@login_required
def instructorClass(class_id):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  # Return the class
  return render_template('instructorClassInfo.html', theClass = theClass, page_title = 'Class Info')


# Add student to class
@app.route('/instructor/class/<class_id>/addStudent', methods = ['GET', 'POST'])
@login_required
def instructorClassAddStudent(class_id):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  # Add the student to class
  form = AddStudentToClassForm()
  # POST
  if(form.validate_on_submit()):
    # Extract the data from the form
    studentEmail = form.student_email.data.lower()
    # If student email already in the list, just send a flash message saying so and don't add again
    if(studentEmail in theClass['student_emails']):
      # Flash Message: student added
      flash(f'{studentEmail} is already in this class!', 'info')
      # Return
      return redirect(url_for('instructorClass', class_id = class_id))
    # Else, Add the student to the list of students in MongoDB
    else:
      mongodb_fyp_db.classes.update_one({ "_id": ObjectId(class_id) }, { "$push": { "student_emails": studentEmail } })
      # Flash Message: student added
      flash(f'{studentEmail} added to class!', 'success')
      # Return
      return redirect(url_for('instructorClass', class_id = class_id))
  # GET
  return render_template('instructorAddStudentToClass.html', form = form, page_title = 'Add Student')

# Remove student from class
@app.route('/instructor/class/<class_id>/removeStudent/<student_email>', methods = ['GET', 'POST'])
@login_required
def instructorClassRemoveStudent(class_id, student_email):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  try:
    # Remove the student from class
    mongodb_fyp_db.classes.update_one({ "_id": ObjectId(class_id) }, { "$pull": { "student_emails": student_email } })
    # Flash Message: student added
    flash(f'{student_email} removed form class!', 'success')
    # Return
    return redirect(url_for('instructorClass', class_id = class_id))
  except:
    # Flash Message: error
    flash(f'Failed to remove {student_email} form class!', 'danger')
    # Return
    return redirect(url_for('instructorClass', class_id = class_id))


# Delete class
@app.route('/instructor/class/<class_id>/deleteClass', methods = ['GET', 'POST'])
@login_required
def instructorDeleteClass(class_id):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  try:
    # Remove the class
    mongodb_fyp_db.classes.delete_one({ "_id": ObjectId(class_id) })
    # Flash Message: class deleted
    flash(f'[{theClass["guide_name"]}] Class deleted!', 'info')
    # Return
    return redirect(url_for('instructorClasses'))
  except:
    # Flash Message: error
    flash(f'Failed to remove the {class_id} class!', 'danger')
    # Return
    return redirect(url_for('instructorClasses'))


# Edit class
@app.route('/instructor/class/<class_id>/editClass', methods = ['GET', 'POST'])
@login_required
def instructorEditClass(class_id):
    # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # MongoDB
  mongoClient = pymongo.MongoClient()
  mongodb_fyp_db = mongoClient.fyp_db
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Get all the instructors into a list
  instructorData = []
  instructors = User.query.filter_by(role = 'instructor')
  for i in instructors:
    instructorData.append((i.email, i.full_name))
  
  # Get all the guides into a list
  guideData = []
  # Get the guide with the passed in name from the database
  guides = mongodb_fyp_db.guides.find()
  mongoClient.close()
  for i in guides:
    guideData.append((i['guide_name'], i['guide_name']))

  # Create Class Form
  form = EditClassForm()
  form.instructor_email.choices = instructorData
  form.guide_name.choices = guideData
  # Getting the available timezones from secretsFile.py
  form.timezone.choices = secretsFile.getItem('classTimezones')
  
  # POST
  if(form.validate_on_submit()):
    # Extract the data from the form
    classStartDate = form.start_date.data
    classTimezone = form.timezone.data
    instructorEmail = form.instructor_email.data
    guideName = form.guide_name.data

    # Start Date
    classStartDateDT = datetime.combine(classStartDate, datetime.min.time())
    # Finish Date
    classFinishDateDT = classStartDateDT.replace(hour = 23)
    classFinishDateDT = classFinishDateDT.replace(minute = 59)

    # Use the timezone to convert back to UTC (time on server)
    tz = pytz.timezone(classTimezone)
    classStartDateDT_UTC = toUTC(classStartDateDT, tz)
    classFinishDateDT_UTC = toUTC(classFinishDateDT, tz)

    # Store the initial class to MongoDB
    info = {'start_date': classStartDateDT_UTC, 'finish_date': classFinishDateDT_UTC, 'start_date_local': classStartDateDT, 'finish_date_local': classFinishDateDT, 'timezone': classTimezone, 'instructor_email': str(instructorEmail), 'guide_name': str(guideName)}
    mongodb_fyp_db.classes.update_one({ "_id": ObjectId(class_id) }, { "$set": info })
    # Flash Message: class created
    flash('The class has been updated!', 'success')
    # Return
    return redirect(url_for('instructorClasses'))
  # GET
  # Return
  return render_template('instructorClassEdit.html', page_title = 'Edit Class', form = form)


# Instructor class dashboard
@app.route('/instructor/class/<class_id>/dashboard')
@login_required
def instructorClassDashboard(class_id):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  
  # Get all statistics for the class
  classStats = mongodb_fyp_db.statistics.find({"class_id": ObjectId(class_id)})

  # Statistics data
  classGuide = mongodb_fyp_db.guides.find_one({'guide_name': theClass['guide_name']})
  numberOfExercisesInClass = len(classGuide['guide_content'])
  # get latest data for each student
  latestExerciseProgressStats = {}
  for i in classStats:
    if(i['student_email'] not in latestExerciseProgressStats.keys()):
      latestExerciseProgressStats[i['student_email']] = i
    else:
      if(i['statistic_date'] > latestExerciseProgressStats[i['student_email']]['statistic_date']):
        latestExerciseProgressStats[i['student_email']] = i
  
  # Chart data
  try:
    exercisesList = []
    studentNames = []
    studentExerciseData = []

    for i in range(numberOfExercisesInClass):
      exercisesList.append(i)

    for i in latestExerciseProgressStats:
      studentNames.append(str(latestExerciseProgressStats[i]['student_name']))
      studentExerciseData.append(int(latestExerciseProgressStats[i]['exercise_number']))
  except Exception as e:
    # Flash Message: error
    flash(f'Failed to process graph data! "{e}"', 'danger')

  # Get current time
  updateTime = datetime.utcnow()

  # Return
  return render_template('instructorClassDashboard.html', exercisesList = exercisesList, studentNames = studentNames, studentExerciseData = studentExerciseData, latestStats = latestExerciseProgressStats, numberOfExercisesInClass = numberOfExercisesInClass, updateTime= updateTime, class_id = class_id, page_title = 'Dashboard')

# Instructor class dashboard for individual student
@app.route('/instructor/class/<class_id>/dashboard/student/<student_email>')
@login_required
def instructorClassDashboardStudentActivity(class_id, student_email):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  # Check if the student is in the class
  if(student_email not in theClass['student_emails']):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Get student statistics
  student_exercise_progress_mongo_object = mongodb_fyp_db.statistics.find({"class_id": ObjectId(class_id), "student_email": student_email, "statistic_type": "exercise_progress"})
  student_exercise_progress_list = []
  for i in student_exercise_progress_mongo_object:
    student_exercise_progress_list.append(i)

  # Calculate time spent on each exercise
  # Key: exercise_number | Value: Time spent on exercise
  time_dict = {}
  time_dict_seconds = {}
  for i in range(len(student_exercise_progress_list)):
    try:
      # If not in dict, initialise with 0:0:0 time
      if(student_exercise_progress_list[i]['exercise_number'] not in time_dict.keys()):
        time_dict[student_exercise_progress_list[i]['exercise_number']] = timedelta(hours=0, minutes=0, seconds=0)
        time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = 0
      if(student_exercise_progress_list[i+1]['exercise_number'] not in time_dict.keys()):
        time_dict[student_exercise_progress_list[i]['exercise_number']] = timedelta(hours=0, minutes=0, seconds=0)
        time_dict_seconds[student_exercise_progress_list[i+1]['exercise_number']] = 0

      # If exercise i < exercise i+1 (Time updates for exercise i)
      if(student_exercise_progress_list[i]['exercise_number'] < student_exercise_progress_list[i+1]['exercise_number']):
        td = student_exercise_progress_list[i+1]['statistic_date'] - student_exercise_progress_list[i]['statistic_date']
        td_seconds = td.total_seconds()
        time_dict[student_exercise_progress_list[i]['exercise_number']] = time_dict[student_exercise_progress_list[i]['exercise_number']] + td
        time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] + td_seconds
      # Else If exercise i > exercise i+1 (Time updates for exercise i+1)
      # Else exercise i == exercise i+1 (Time updates for exercise i or i+1 (same))
      else:
        td = student_exercise_progress_list[i+1]['statistic_date'] - student_exercise_progress_list[i]['statistic_date']
        td_seconds = td.total_seconds()
        time_dict[student_exercise_progress_list[i]['exercise_number']] = time_dict[student_exercise_progress_list[i]['exercise_number']] + td
        time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] + td_seconds
    except Exception as e:
      # Index out of bounds = End of student_exercise_progress_list
      print('ERROR:', e)

  chart_labels = []
  chart_data = []
  
  for i in time_dict_seconds:
    chart_labels.append(i)
    chart_data.append(time_dict_seconds[i])

  # Return
  return render_template('instructorClassDashboardStudentActivity.html', student_exercise_progress_list = student_exercise_progress_list, time_dict = time_dict, chart_labels = chart_labels, chart_data = chart_data, student_email = student_email, page_title = 'Dashboard - {}'.format(str(student_email)))

#---------#
# Student #
#---------#

# Student home
@app.route('/student')
@login_required
def studentHome():
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  return render_template('studentHome.html', page_title = 'Home')


# View student guides from the past
@app.route('/student/guides')
@login_required
def studentGuides():
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Check all classes to see if a user is or has been enrolled in, in the past
  allClasssesFromDB = mongodb_fyp_db.classes.find()
  listOfEnrolledGuides = []
  currentTime = datetime.utcnow()
  for c in allClasssesFromDB:
    if(current_user.email in c['student_emails']):
      if(currentTime > c['start_date']):
        listOfEnrolledGuides.append(c['guide_name'])
  
  orderedClasses = sorted(listOfEnrolledGuides, key=lambda k: k)

  # Return
  return render_template('studentGuides.html', listOfEnrolledGuides = orderedClasses, page_title = 'Guides')


# View student guide (if enrolled in any class)
@app.route('/student/guide/<guide_name>/exercise/<exercise_number>')
@login_required
def studentGuide(guide_name, exercise_number):
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Check all classes to see if a user is or has been enrolled in, in the past
  allClasssesFromDB = mongodb_fyp_db.classes.find()
  listOfEnrolledGuides = []
  for c in allClasssesFromDB:
    if(current_user.email in c['student_emails']):
      listOfEnrolledGuides.append(c['guide_name'])
  
  # Check if the guide the student wants to view, is actually eligible from above check
  if(guide_name not in listOfEnrolledGuides):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide from db
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )
  number_of_exercises = str(guideFromDb['number_of_exercises'])
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  
  # Validate exercise number
  if(int(exercise_number) <= 0 or (int(exercise_number) > int(guideFromDb['number_of_exercises']))):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # If 0, then can't go to negative
  if(int(exercise_number) == 0):
    n_exercise_number = int(exercise_number) + 1
    p_exercise_number = 0
  # If last exercise, go to summary at the end
  elif(int(exercise_number) == len(guideFromDb["guide_content"])):
    n_exercise_number = 'end'
    p_exercise_number = int(exercise_number) - 1
  else:
    p_exercise_number = int(exercise_number) - 1
    n_exercise_number = int(exercise_number) + 1

  # Now get the guide and return it to the template
  return render_template('studentGuideExerciseNoStats.html', guideName = guide_name, guideContent = json.dumps(guideFromDb['guide_content'][(int(exercise_number) - 1)]), p_exercise_number = p_exercise_number, n_exercise_number = n_exercise_number, exerciseNumber = exercise_number, number_of_exercises = number_of_exercises, guidepage_title = str(guideFromDb['guide_name']))


# View guide exercise
@app.route('/student/class/<class_id>/guide/<guide_name>/exercise/<exercise_number>', methods=['GET','POST'])
@login_required
def studentGuideExercise(class_id, guide_name, exercise_number):
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Check if the class exists in MongoDB
  theClass = mongodb_fyp_db.classes.find_one( {"_id": ObjectId(class_id)} )
  if(theClass is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')
  
  if(current_user.email not in theClass['student_emails']):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide based on the name
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_name": str(guide_name)} )

  # Check if 'guide_name' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Check if the exercise number is in the range of the actual guide stored in MongoDB
  try:
    if(int(exercise_number) <= 0 or (int(exercise_number) > int(guideFromDb['number_of_exercises']))):
      return render_template('pageNotFound.html', page_title = 'Page Not Found')
  except:
    # if it is summary, pass as it is valid
    if((exercise_number == 'summary') or (exercise_number == 'end')):
      pass
    else:
      return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Calculate Exercise Numbers / Only do if 'exercise_number' not 'summary' or 'end'
  if((exercise_number == 'summary') or (exercise_number == 'end')):
    pass
  else:
    # If 0, then can't go to negative
    if(int(exercise_number) == 0):
      n_exercise_number = int(exercise_number) + 1
      p_exercise_number = 0
    # If last exercise, go to summary at the end
    elif(int(exercise_number) == len(guideFromDb["guide_content"])):
      n_exercise_number = 'end'
      p_exercise_number = int(exercise_number) - 1
    else:
      p_exercise_number = int(exercise_number) - 1
      n_exercise_number = int(exercise_number) + 1
  
  if(exercise_number == 'summary'):
    # ----------- COPY PASTE -----------
    # Get student statistics
    student_exercise_progress_mongo_object = mongodb_fyp_db.statistics.find({"class_id": ObjectId(class_id), "student_email": current_user.email, "statistic_type": "exercise_progress"})
    student_exercise_progress_list = []
    for i in student_exercise_progress_mongo_object:
      student_exercise_progress_list.append(i)

    # Calculate time spent on each exercise
    # Key: exercise_number | Value: Time spent on exercise
    time_dict = {}
    time_dict_seconds = {}
    for i in range(len(student_exercise_progress_list)):
      try:
        # If not in dict, initialise with 0:0:0 time
        if(student_exercise_progress_list[i]['exercise_number'] not in time_dict.keys()):
          time_dict[student_exercise_progress_list[i]['exercise_number']] = timedelta(hours=0, minutes=0, seconds=0)
          time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = 0
        if(student_exercise_progress_list[i+1]['exercise_number'] not in time_dict.keys()):
          time_dict[student_exercise_progress_list[i]['exercise_number']] = timedelta(hours=0, minutes=0, seconds=0)
          time_dict_seconds[student_exercise_progress_list[i+1]['exercise_number']] = 0

        # If exercise i < exercise i+1 (Time updates for exercise i)
        if(student_exercise_progress_list[i]['exercise_number'] < student_exercise_progress_list[i+1]['exercise_number']):
          td = student_exercise_progress_list[i+1]['statistic_date'] - student_exercise_progress_list[i]['statistic_date']
          td_seconds = td.total_seconds()
          time_dict[student_exercise_progress_list[i]['exercise_number']] = time_dict[student_exercise_progress_list[i]['exercise_number']] + td
          time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] + td_seconds
        # Else If exercise i > exercise i+1 (Time updates for exercise i+1)
        # Else exercise i == exercise i+1 (Time updates for exercise i or i+1 (same))
        else:
          td = student_exercise_progress_list[i+1]['statistic_date'] - student_exercise_progress_list[i]['statistic_date']
          td_seconds = td.total_seconds()
          time_dict[student_exercise_progress_list[i]['exercise_number']] = time_dict[student_exercise_progress_list[i]['exercise_number']] + td
          time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] = time_dict_seconds[student_exercise_progress_list[i]['exercise_number']] + td_seconds
      except Exception as e:
        # Index out of bounds = End of student_exercise_progress_list
        print('ERROR:', e)
    chart_labels = []
    chart_data = []
    
    for i in time_dict_seconds:
      chart_labels.append(i)
      chart_data.append(time_dict_seconds[i])
    # ----------- COPY PASTE -----------
    return render_template('studentGuideSummary.html', time_dict = time_dict, chart_labels = chart_labels, chart_data = chart_data, page_title = "{} Summary".format(guideFromDb['guide_name']))

  # If the class is in progress, Gather statistics and store them to MongoDB
  current_date = datetime.utcnow()
  if((theClass['start_date'] < current_date) and (theClass['finish_date'] > current_date)):
    # Check if it is the end and the student is presented with their summary / different return
    if(exercise_number == 'end'):
      # Update statisitcs again with the last exercise again so the instructor sees the final exercise timings
      # NOTE: If a student refreshes the summary, the last question time will update
      info = {'class_id': ObjectId(class_id), 'guide_name': guide_name, 'exercise_number': str(guideFromDb['number_of_exercises']), 'student_email': current_user.email, 'student_name': current_user.full_name, 'statistic_type': 'exercise_progress', 'statistic_date': current_date}
      mongodb_fyp_db.statistics.insert_one(info)
      # Redirect to summary
      # This is done so when the student refreshes summary, it won't accumulate to time spent on final question
      return redirect(url_for('studentGuideExercise', class_id = class_id, guide_name = guide_name, exercise_number = 'summary'))
    else:
      info = {'class_id': ObjectId(class_id), 'guide_name': guide_name, 'exercise_number': exercise_number, 'student_email': current_user.email, 'student_name': current_user.full_name, 'statistic_type': 'exercise_progress', 'statistic_date': current_date}
      mongodb_fyp_db.statistics.insert_one(info)
      # Return the guide and exercise to the student
      return render_template('studentGuideExercise.html', p_exercise_number = p_exercise_number, n_exercise_number = n_exercise_number, guideContent = json.dumps(guideFromDb['guide_content'][(int(exercise_number) - 1)]), guideName = guideFromDb['guide_name'], exerciseNumber = exercise_number, class_id = class_id, page_title = "{}".format(guideFromDb['guide_name']))
  # Else, the class has not yet started
  else:
    if(theClass['start_date'] > current_date):
      return render_template('studentClassOutOfDate.html', outOfDateType = 'early', page_title = "{}".format(guideFromDb['guide_name']))
    elif(theClass['finish_date'] < current_date):
      return render_template('studentClassOutOfDate.html', outOfDateType = 'past', page_title = "{}".format(guideFromDb['guide_name']))
    else:
      return render_template('studentClassOutOfDate.html', outOfDateType = 'generic', page_title = "{}".format(guideFromDb['guide_name']))


# View guide exercise
@app.route('/student/classes')
@login_required
def studentClasses():
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Check if the logged in student has any classes they are enrolled in
  allClasssesFromDB = mongodb_fyp_db.classes.find()
  listOfEnrolledClasses = []
  for c in allClasssesFromDB:
    if(current_user.email in c['student_emails']):
      listOfEnrolledClasses.append(c)
  
  # Sort the classes into upcoming/ongoing and past classes
  orderedClasses = sorted(listOfEnrolledClasses, key=lambda k: k['start_date'])

  normalClasses = []
  pastClasses = []

  currentTime = datetime.utcnow()
  for c in orderedClasses:
    if(c['finish_date'] < currentTime):
      pastClasses.append(c)
    else:
      normalClasses.append(c)

  # Return
  return render_template('studentClasses.html', page_title = 'Classes', listOfClasses = normalClasses, listOfPastClasses = pastClasses)

#---------------#
# Administrator #
#---------------#

# Administrator home
@app.route('/administrator')
@login_required
def adminHome():
  # Check if the person logged in is an administrator
  if(current_user.role != 'administrator'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  return render_template('adminHome.html', page_title = 'Home')


# Manage application variables
@app.route('/administrator/application')
@login_required
def adminManageApplication():
  # Check if the person logged in is an administrator
  if(current_user.role != 'administrator'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  
  # Get all timezones
  timezones = secretsFile.getItem('classTimezones')

  # Return
  return render_template('adminManageApplication.html', timezones = timezones, page_title = 'Manage Application')


# Manage people and accounts
@app.route('/administrator/people')
@login_required
def adminManagePeople():
  # Check if the person logged in is an administrator
  if(current_user.role != 'administrator'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get all people in the application (1. admins, 2. instructors, 3. students)
  allAdmins = User.query.filter_by(role='administrator').all()
  allInstructors = User.query.filter_by(role='instructor').all()
  allStudents = User.query.filter_by(role='student').all()

  # Replace the hashed passwords with 'N/A', just in case
  for i in allAdmins:
    i.password = i.password.replace(i.password, 'N/A')
  for i in allInstructors:
    i.password = i.password.replace(i.password, 'N/A')
  for i in allStudents:
    i.password = i.password.replace(i.password, 'N/A')

  # Return
  return render_template('adminManagePeople.html', allAdmins = allAdmins, allInstructors = allInstructors, allStudents = allStudents, page_title = 'Manage People')


# Change role of an account
@app.route('/administrator/people/<email_address>/changeRole/<new_role>')
@login_required
def adminManagePeopleChangeRole(email_address, new_role):
  # Check if the person logged in is an administrator
  if(current_user.role != 'administrator'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the user email exists in db
  user = User.query.filter_by(email=email_address).first()
  if(user is None):
    flash(f'"{email_address}" does not exist in the database', 'danger')
    return redirect(url_for('adminManagePeople'))
  # Check if the role is ['administrator' or 'instructor' or 'student']
  validRoles = ['administrator', 'instructor', 'student']
  if(new_role not in validRoles):
    flash(f'"{new_role}" is not valid. Valid Roles: "administrator", "instructor", "student".', 'danger')
    return redirect(url_for('adminManagePeople'))

  # Update user role
  user.role = new_role
  db.session.add(user)
  db.session.commit()
  # Return redirect
  flash(f'"{email_address}" role updated to "{new_role}"', 'success')
  return redirect(url_for('adminManagePeople'))


# Delete user from the application
@app.route('/administrator/people/<email_address>/deleteUser')
@login_required
def adminManagePeopleDeleteUser(email_address):
  # Check if the person logged in is an administrator
  if(current_user.role != 'administrator'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  # Check if the user email exists in db
  user = User.query.filter_by(email=email_address).first()
  if(user is None):
    flash(f'"{email_address}" does not exist in the database.', 'danger')
    return redirect(url_for('adminManagePeople'))
  
  # Delete user
  userToDelete = User.query.filter_by(email=email_address).first()
  db.session.delete(userToDelete)
  db.session.commit()
  # Return redirect
  flash(f'"{email_address}" user has been deleted.', 'success')
  return redirect(url_for('adminManagePeople'))
