from flask import render_template, request, url_for, flash, redirect, session
from flaskApi import app, db, bcrypt, mail, secretsFile
from flaskApi.forms import RegisterForm, LoginForm, UpdateAccountForm, RequestPasswordResetForm, ResetPasswordForm, FeedbackForm, IndicatePauseForm, CreateGuideForm, DeleteGuideForm, CreateClassForm, AddStudentToClassForm
from flaskApi.templates import *
from flaskApi.models import User
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, date
from PIL import Image
from flask_mail import Message
from bson import ObjectId
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
    info = {'guide_code': str(guideCode), 'guide_name': str(guideName), 'number_of_exercises': 0, 'last_edited_time': datetime.utcnow(), 'guide_content': []}
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


# View a list of all exercises in a given guide
@app.route('/instructor/guide/<guide_code>', methods = ['GET', 'POST'])
@login_required
def instructorGuide(guide_code):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_code": str(guide_code)} )
  # Check if 'guide_code' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  return render_template('instructorGuideExercises.html', guide = guideFromDb, page_title = 'Guide Exercises')


# Create a new exercise for a given guide
@app.route('/instructor/guide/<guide_code>/createExercise')
@login_required
def instructorCreateExercise(guide_code):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide from MongoDB
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_code": str(guide_code)} )
  # Check if 'guide_code' is correct and a guide is found
  if(guideFromDb is None):
    return render_template('pageNotFound.html', page_title = 'Page Not Found')

  # Increment 'number_of_exercises' in MongoDB
  # Update number_of_exercises in mongoDB
  updated_number_of_exercises = guideFromDb['number_of_exercises'] + 1
  mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "number_of_exercises": updated_number_of_exercises } })

  # Add a new empty list to 'guide_content' in MongoDB
  mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$push": { "guide_content": [] } })

  # Update 'last_edited_time' in MongoDB
  mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "last_edited_time": datetime.utcnow() } })

  # Return
  return redirect(url_for('instructorGuide', guide_code = guide_code))

# Edit a given exercise in a given guide
@app.route('/instructor/guide/<guide_code>/exercise/<exercise_number>', methods = ['GET', 'POST'])
@login_required
def instructorEditExercise(guide_code, exercise_number):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Get the guide based on the code
  guideFromDb = mongodb_fyp_db.guides.find_one( {"guide_code": str(guide_code)} )

  # Check if 'guide_code' is correct and a guide is found
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
    mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "guide_content." + str((int(exercise_number) - 1)): guide['ops'] } })
    # Update guide last_edited_time
    mongodb_fyp_db.guides.update_one({ "guide_code": guideFromDb['guide_code'] }, { "$set": { "last_edited_time": datetime.utcnow() } })
    # Flash Message: guide updated
    flash(f'The "{guideFromDb["guide_name"]}" guide has been updated!', 'success')
    # Return
    return redirect(url_for('instructorGuide', guide_code = guide_code))

  # Render the guide in QuillJS using javascript the the 'guideFromDb' variable passed into the template
  # NOTE: 'guideContent' must use json.dumps
  return render_template('instructorGuideExerciseEdit.html', guideContent = json.dumps(guideFromDb['guide_content'][(int(exercise_number) - 1)]), guideName = guideFromDb['guide_name'], guideCode = guideFromDb['guide_code'], exerciseNumber = exercise_number, page_title = "{} - Edit".format(guideFromDb['guide_name']))


#---------#
#  TO-DO  #
#---------#
# Delete exercise from a given guide
@app.route('/instructor/<guide_code>/deleteExercise')
@login_required
def instructorDeleteExercise(guide_code):
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')
  return render_template('accessDenied.html', page_title = 'Access Denied')


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
    listOfClasses.append({'class_id': theClass['_id'], 'start_date': theClass['start_date'], 'finish_date': theClass['finish_date'], 'instructor_email': theClass['instructor_email'], 'guide_code': theClass['guide_code'], 'student_emails': theClass['student_emails']})

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

# Create a new class
@app.route('/instructor/class/create', methods = ['GET', 'POST'])
@login_required
def instructorClassCreate():
  # Check if the person logged in is an instructor
  if(current_user.role != 'instructor'):
    return render_template('accessDenied.html', page_title = 'Access Denied')

  # Create Class Form
  form = CreateClassForm()
  
  # POST
  if(form.validate_on_submit()):
    # Extract the data from the form
    classStartDate = form.start_date.data
    classStartDateDT = datetime.combine(classStartDate, datetime.min.time())
    classFinishDate = form.finish_date.data
    classFinishDateDT = datetime.combine(classFinishDate, datetime.min.time())
    instructorEmail = form.instructor_email.data
    guideCode = form.guide_code.data

    # Store the initial class to MongoDB
    info = {'start_date': classStartDateDT, 'finish_date': classFinishDateDT, 'instructor_email': str(instructorEmail), 'guide_code': str(guideCode), 'student_emails': []}
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
    flash(f'[{theClass["guide_code"]}] Class deleted!', 'info')
    # Return
    return redirect(url_for('instructorClasses'))
  except:
    # Flash Message: error
    flash(f'Failed to remove the {class_id} class!', 'danger')
    # Return
    return redirect(url_for('instructorClasses'))



#---------#
# Student #
#---------#

@app.route('/student/guide/<guide_code>/exercise/<exercise_number>', methods=['GET','POST'])
@login_required
def studentGuide(guide_code, exercise_number):
  # Check if the person logged in is an student
  if(current_user.role != 'student'):
    return render_template('accessDenied.html', page_title = 'Access Denied')




# For later development


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