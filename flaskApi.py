from flask import Flask, render_template, request, url_for, flash, redirect, session
from templates import *
from forms import FeedbackForm, IndicatePauseForm
import pymongo, datetime, json
import secretsFile

app = Flask(__name__)

app.config['SECRET_KEY'] = secretsFile.getItem("appConfigSecretKey")

# https://getbootstrap.com/docs/4.4/examples/dashboard/

# MongoDB
mongoClient = pymongo.MongoClient()
mongodb = mongoClient.fyp_mvp
#mongoClient.close()

@app.route('/')
def home():
  # Return
  return render_template('home.html', page_title = 'FYP_MVP Home')

@app.route('/instructor')
def instructor():
  # Get all items from studentStats
  allInfoItems = mongodb.studentStats.find()
  # Get all feedback from studentFeedback
  allFeedbackItems = mongodb.studentFeedback.find()
  # Return
  return render_template('instructor.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Instructor Dashboard")

@app.route('/guide/<guide_code>/<exercise_number>', methods=['GET','POST'])
def guide(guide_code, exercise_number):
  try:
    # First Summary, when the end of guide is reached
    if(exercise_number == 'summary'):
      # Redirect to guideSummary()
      return redirect(url_for('guideSummary'))

    # Read guide from DB based on 'guide_code' and 'exercise_number' in URL
    guide = mongodb.guides.find_one( {"guide_code": guide_code} )

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
      # Store feedback in MongoDB (POST)
      feedbackToStore = {'student_feedback_type': 'exercise_feedback', 'student_feedback': str(feedbackForm.feedback.data), 'guide_code': guide_code, 'exercise_number': exercise_number}
      mongodb.studentFeedback.insert_one(feedbackToStore)

      # Show flask message and return home (POST)
      flash('Feedback Sent!', 'success')

      # Return (POST)
      return render_template('guide.html', exercise = exercise, current_exercise_number = c_exercise_number, previous_exercise_number = p_exercise_number, next_exercise_number = n_exercise_number, guide_code = guide_code, url_root = request.url_root, form = feedbackForm, pause_form = pauseForm)

    # On submit Pause (POST)
    if pauseForm.indicatePauseSubmit.data and pauseForm.validate_on_submit():
      # Store statiatics info to DB (POST)
      info = {'action': 'pause', 'guide_code': guide_code, 'exercise_number': exercise_number, 'time': datetime.datetime.utcnow()}
      mongodb.studentStats.insert_one(info)

      # Show flask message and return to pause page (POST)
      flash('Paused.', 'warning')

      # Send all the info required in 'messages' to resume in the same exercise
      messages = json.dumps({'current_exercise_number': exercise_number, 'guide_code': guide_code, 'url_root': request.url_root})
      session['messages'] = messages

      # Return (POST)
      return redirect(url_for('guidePause', messages=messages))

    # Store statiatics info to DB
    info = {'action': 'exercise', 'guide_code': guide_code, 'exercise_number': exercise_number, 'time': datetime.datetime.utcnow()}
    mongodb.studentStats.insert_one(info)

    # Return
    return render_template('guide.html', exercise = exercise, current_exercise_number = c_exercise_number, previous_exercise_number = p_exercise_number, next_exercise_number = n_exercise_number, guide_code = guide_code, url_root = request.url_root, form = feedbackForm, pause_form = pauseForm)

  except Exception as e:
    return ("Page not found: {}".format(e))

@app.route('/guidePause')
def guidePause():
  # Retrieve the info for the resume button that is passed as 'messages'
  messages = request.args['messages']
  messages = session['messages']

  # Return
  return render_template('guidePause.html', messages=json.loads(messages))

@app.route('/guideSummary', methods=['GET','POST'])
def guideSummary():

  # NOTE they will be filtered for the person logged in

  # Get all items from studentStats
  allInfoItems = mongodb.studentStats.find()
  # Get all feedback from studentFeedback
  allFeedbackItems = mongodb.studentFeedback.find()

  # Feedback form
  feedbackForm = FeedbackForm()

  # On submit Feedback (POST)
  if feedbackForm.feedbackSubmit.data and feedbackForm.validate_on_submit():
    # Store feedback in MongoDB (POST)
    feedbackToStore = {'student_feedback_type': 'class_feedback', 'student_feedback': str(feedbackForm.feedback.data), 'guide_code': 'guide_code', 'exercise_number': 'class feedback'}
    mongodb.studentFeedback.insert_one(feedbackToStore)

    # Show flask message and return home (POST)
    flash('Class Feedback Sent!', 'success')
  
    return render_template('guideSummary.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Student Summary", form = feedbackForm)

  return render_template('guideSummary.html', student_stats = allInfoItems, student_feedback = allFeedbackItems, page_title = "Student Summary", form = feedbackForm)

# app.run
if __name__ == '__main__':
  app.run(debug=True)

'''

'guide_code' MUST BE UNIQUE!

{
  guide_name: "First Test Guide",
  guide_code: "FTG",
  guide_content: [
    {
      exercise_name: "Introduction",
      exercise_content: [
        "Welcome to my guide!"
      ]
    },
    {
      exercise_name: "Exercise 1 - Hello World",
      exercise_content: [
        "Click Here.",
        "Click There.",
        "You're Done!"
      ]
    },
    {
      exercise_name: "Exercise 2 - Goodbye World",
      exercise_content: [
        "Click Here.",
        "Click There.",
        "You're Done!"
      ]
    },
    {
      exercise_name: "Exercise 3 - Ok World",
      exercise_content: [
        "Click Here.",
        "Click There.",
        "You're Done!"
      ]
    },
    {
      exercise_name: "Exercise 4 - Not Ok World",
      exercise_content: [
        "Click Here.",
        "Click There.",
        "You're Done!"
      ]
    },
    {
      exercise_name: "Exercise 5 - The Endgame",
      exercise_content: [
        "Click Here.",
        "Click There.",
        "You're Done!"
      ]
    }
  ]
}
'''
