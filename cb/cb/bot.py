from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime
import json
import logging
import os
from google.auth import exceptions
from google.cloud import dialogflow_v2 as dialogflow
from google.oauth2 import service_account

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///college_enquiry.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize URLSafeTimedSerializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

# Load responses from JSON file
try:
    with open('responses.json', 'r') as f:
        bot_responses = json.load(f)
except FileNotFoundError:
    logging.error("responses.json file not found. Please ensure the file exists in the project directory.")
    bot_responses = {'default': 'Sorry, I don\'t understand that.'}

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Dialogflow Credentials and Client Setup
def get_dialogflow_client():
    credentials = service_account.Credentials.from_service_account_file(
        'service-account.json'
    )
    client = dialogflow.SessionsClient(credentials=credentials)
    return client

def detect_intent_texts(project_id, session_id, text, language_code='en'):
    session_client = get_dialogflow_client()
    session = session_client.session_path(project_id, session_id)
    text_input = dialogflow.TextInput(text=text, language_code=language_code)
    query_input = dialogflow.QueryInput(text=text_input)

    try:
        response = session_client.detect_intent(request={'session': session, 'query_input': query_input})
        return response.query_result.fulfillment_text
    except exceptions.GoogleAPICallError as e:
        logging.error(f"Dialogflow API call failed: {e}")
        return bot_responses['default']

def call_dialogflow(message):
    project_id = 'helpful-cat-430917-k8'  # Replace with your project ID
    session_id = '1234567890'  # Replace with a unique session ID for each user
    try:
        response = detect_intent_texts(project_id, session_id, message)
        logging.debug(f"Dialogflow response: {response}")
        return response
    except exceptions.GoogleAPICallError as e:
        logging.error(f"Dialogflow API call failed: {e}")
        return bot_responses['default']

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            flash(f'A password reset link has been sent to your email: {reset_url}', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found', 'danger')
    return render_template('forgot.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The reset link is expired.', 'danger')
        return redirect(url_for('forgot'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/get-response', methods=['POST'])
def get_response():
    data = request.get_json()
    user_message = data.get('user_message')
    logging.debug(f"Received user message: {user_message}")

    if not user_message:
        logging.error("No user message received.")
        return jsonify({'bot_message': "Sorry, I didn't understand that."})

    try:
        # Get bot response from Dialogflow
        bot_message = call_dialogflow(user_message)
        logging.debug(f"Responding with bot message: {bot_message}")
        return jsonify({'bot_message': bot_message})
    except Exception as e:
        logging.error(f"Error in generating response: {e}")
        return jsonify({'bot_message': "Sorry, something went wrong."}), 500


if __name__ == '__main__':
    app.run(debug=True)
