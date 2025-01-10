from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from flask_cors import CORS
import random
import sqlite3
import logging
import os
import requests

# Set up logging
class HTTPLogger(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        # Send log entry to the logging server
        try:
            requests.post("http://your-logging-server.com/log", json={"log": log_entry})  # Replace with your logging server URL
        except Exception as e:
            print(f"Failed to send log to server: {e}")

# Initialize the Flask application
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure Flask-Mail using environment variables
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Use environment variable
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Use environment variable
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')  # Use environment variable

mail = Mail(app)

# In-memory storage for OTP and PIN
otp_storage = {}
pin_storage = {}

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
http_handler = HTTPLogger()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
http_handler.setFormatter(formatter)
logger.addHandler(http_handler)

def create_connection():
    conn = sqlite3.connect('users.db')  # Ensure your database file is in the same directory
    return conn

@app.route('/')  # Route for the root URL
def home():
    logger.info("Home endpoint accessed.")
    return "Welcome to the Login API! Use /api/login to log in and /api/requestOtp to request an OTP."

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    logger.debug(f"Login attempt for email: {email}")

    # Validate the email and password against the database
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
        otp_storage[email] = otp  # Store OTP in memory
        send_otp(email, otp)  # Send OTP to the user's email
        logger.info(f"OTP sent to {email}.")
        
        # Generate a new PIN
        pin = generate_random_pin()
        pin_storage[email] = pin  # Store the PIN in memory
        logger.info(f"Generated PIN {pin} for {email}")

        # Optionally, send the PIN to the ESP32
        send_pin_to_esp32(email, pin)

        return jsonify(success=True, message='OTP sent to your email', email=email, pin=pin)
    else:
        logger.warning(f"Invalid login attempt for email: {email}")
        return jsonify(success=False, message='Invalid email or password'), 401

@app.route('/api/requestOtp', methods=['POST'])
def request_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        logger.error("Email is required for OTP request.")
        return jsonify(success=False, message='Email is required'), 400

    # Generate a 6-digit OTP
    otp = random.randint(100000, 999999)
    otp_storage[email] = otp  # Store OTP in memory
    send_otp(email, otp)  # Send OTP to the user's email
    logger.info(f"OTP sent to {email}.")
    
    # Generate a new PIN
    pin = generate_random_pin()
    pin_storage[email] = pin  # Store the PIN in memory
    logger.info(f"Generated PIN {pin} for {email}")

    # Optionally, send the PIN to the ESP32
    send_pin_to_esp32(email, pin)

    return jsonify(success=True, message='OTP sent to your email ', email=email, pin=pin)

def send_otp(email, otp):
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is {otp}.'
    mail.send(msg)

def generate_random_pin():
    return random.randint(1000, 9999)  # Generate a 4-digit PIN

def send_pin_to_esp32(email, pin):
    # Implement the logic to send the PIN to the ESP32
    pass

if __name__ == '__main__':
    app.run(debug=True)