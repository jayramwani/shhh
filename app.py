from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from flask_cors import CORS
import secrets  # Use secrets for secure random generation
import sqlite3
import logging
import os
import requests  # Import requests to send HTTP requests
import time  # Import time for managing expiration

logging.getLogger("urllib3").setLevel(logging.WARNING)

# Set up logging to send logs to a remote logging server
class HTTPLogger(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        # Send log entry to the logging server
        try:
            requests.post("https://serverbb.onrender.com/log", json={"log": log_entry})  # Replace with your logging server URL
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
esp32_ip_storage = {}  # New storage for ESP32 IP addresses

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
http_handler = HTTPLogger()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
http_handler.setFormatter(formatter)
logger.addHandler(http_handler)

# Define the expiration time for PINs
PIN_EXPIRATION_TIME = 303  # 5 minutes and 3 seconds in seconds

def create_connection():
    logger.debug("Creating a new database connection.")
    conn = sqlite3.connect('users.db')
    return conn

@app.route('/')  # Route for the root URL
def home():
    logger.info("Home route accessed.")
    return "Welcome to the Login API! Use /api/login to log in, /api/requestOtp to request an OTP, and /api/sendPin to generate a PIN."

@app.route('/api/login', methods=['POST'])
def login():
    logger.info("Login request received.")
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    logger.debug(f"Attempting to log in with email: {email}")
    
    # Validate the email and password against the database
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        otp = secrets.randbelow(1000000)  # Generate a secure 6-digit OTP
        otp_storage[email] = otp  # Store OTP in memory
        send_otp(email, otp)  # Send OTP to the user's email
        logger.info(f"OTP sent to {email}.")
        return jsonify(success=True, message='OTP sent to your email')
    else:
        logger.warning(f"Invalid login attempt for email: {email}")
        return jsonify(success=False, message='Invalid email or password'), 401

@app.route('/api/requestOtp', methods=['POST'])
def request_otp():
    logger.info("Request OTP received.")
    data = request.get_json()
    email = data.get('email')

    if not email:
        logger.error("Email is required for OTP request.")
        return jsonify(success=False, message='Email is required'), 400

    # Generate a secure 6-digit OTP
    otp = secrets.randbelow(1000000)
    otp_storage[email] = otp  # Store OTP in memory
    send_otp(email, otp)  # Send OTP to the user's email
    logger.info(f"OTP sent to {email}.")
    return jsonify(success=True, message='OTP sent to your email')

def send_otp(email, otp):
    logger.debug(f"Sending OTP {otp} to {email}")
    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP code is {otp}'
    try:
        mail.send(msg)
        logger.info(f"OTP sent successfully to {email}")
    except Exception as e:
        logger.error(f"Failed to send OTP: {str(e)}")
        logger.error("Check your email configuration and credentials.")

@app.route('/api/verifyOtp', methods=['POST'])
def verify_otp():
    logger.info("Verify OTP request received.")
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    logger.debug(f"Received OTP for {email}: {otp}")
    stored_otp = otp_storage.get(email)
    logger.debug(f"Stored OTP for {email}: {stored_otp}")

    # Verify the OTP
    if email in otp_storage and stored_otp == int(otp):
        del otp_storage[email]  # Remove OTP after verification
        logger.info(f"OTP verified successfully for {email}")
        return jsonify(success=True, message='OTP verified successfully', verified=True)
    else:
        logger.warning(f"Invalid OTP attempt for {email}: {otp}")
        return jsonify(success=False, message='Invalid OTP', verified=False), 400

@app.route('/api/sendPin', methods=['POST'])
def send_pin():
    logger.info("Send PIN request received.")
    data = request.get_json()
    logger.debug(f"Received data: {data}")  # Log the incoming data
    email = data.get('email')
    pin = secrets.randbelow(10000)  # Generate a secure 4-digit PIN

    if not email:
        logger.error("Email is required.")
        return jsonify(success=False, message='Email is required'), 400

    # Store the PIN in memory with expiration
    pin_storage[email] = {'pin': pin, 'timestamp': time.time()}  # Store PIN and timestamp
    logger.info(f"Generated PIN {pin} for {email}")

    return jsonify(success=True, message='PIN generated successfully', pin=pin)

@app.route('/api/sendIp', methods=['POST'])  # New route to receive IP address
def send_ip():
    logger.info("Send IP request received.")
    data = request.get_json()
    ip_address = data.get('ip')

    if not ip_address:
        logger.error("IP address is required.")
        return jsonify(success=False, message='IP address is required'), 400

    logger.info(f"Received IP address from ESP32: {ip_address}")
    return jsonify(success=True, message='IP address received successfully')

def expire_pins():
    logger.debug("Checking for expired PINs.")
    current_time = time.time()
    for email in list(pin_storage.keys()):
        if current_time - pin_storage[email]['timestamp'] > PIN_EXPIRATION_TIME:
            del pin_storage[email]  # Remove PIN after expiration
            logger.info(f"PIN for {email} has expired and has been removed.")

# Call expire_pins periodically (you can implement a scheduler or a background thread for this)

if __name__ == '__main__':
    logger.info("Starting the Flask application.")
    app.run(debug=True)


# ------------------------------------------------------------------------------------------------------------


# from flask import Flask, request, jsonify
# from flask_mail import Mail, Message
# from flask_cors import CORS
# import secrets  # Use secrets for secure random generation
# import sqlite3
# import logging
# import os
# import requests  # Import requests to send HTTP requests
# import time  # Import time for managing expiration

# logging.getLogger("urllib3").setLevel(logging.WARNING)

# # Set up logging to send logs to a remote logging server
# class HTTPLogger(logging.Handler):
#     def emit(self, record):
#         log_entry = self.format(record)
#         # Send log entry to the logging server
#         try:
#             requests.post("https://serverbb.onrender.com/log", json={"log": log_entry})  # Replace with your logging server URL
#         except Exception as e:
#             print(f"Failed to send log to server: {e}")

# # Initialize the Flask application
# app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes

# # Configure Flask-Mail using environment variables
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Use environment variable
# app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Use environment variable
# app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')  # Use environment variable

# mail = Mail(app)

# # In-memory storage for OTP and PIN
# otp_storage = {}
# pin_storage = {}

# # Set up logging
# logging.basicConfig(level=logging.DEBUG)
# logger = logging.getLogger(__name__)
# http_handler = HTTPLogger()
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# http_handler.setFormatter(formatter)
# logger.addHandler(http_handler)

# # Define the expiration time for PINs
# PIN_EXPIRATION_TIME = 303  # 5 minutes and 3 seconds in seconds

# def create_connection():
#     conn = sqlite3.connect('users.db')
#     return conn

# @app.route('/')  # Route for the root URL
# def home():
#     return "Welcome to the Login API! Use /api/login to log in, /api/requestOtp to request an OTP, and /api/sendPin to generate a PIN."

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')

#     # Validate the email and password against the database
#     conn = create_connection()
#     cursor = conn.cursor()
#     cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
#     user = cursor.fetchone()
#     conn.close()

#     if user:
#         otp = secrets.randbelow(1000000)  # Generate a secure 6-digit OTP
#         otp_storage[email] = otp  # Store OTP in memory
#         send_otp(email, otp)  # Send OTP to the user's email
#         logger.info(f"OTP sent to {email}.")
#         return jsonify(success=True, message='OTP sent to your email')
#     else:
#         logger.warning(f"Invalid login attempt for email: {email}")
#         return jsonify(success=False, message='Invalid email or password'), 401

# @app.route('/api/requestOtp', methods=['POST'])
# def request_otp():
#     data = request.get_json()
#     email = data.get('email')

#     if not email:
#         logger.error("Email is required for OTP request.")
#         return jsonify(success=False, message='Email is required'), 400

#     # Generate a secure 6-digit OTP
#     otp = secrets.randbelow(1000000)
#     otp_storage[email] = otp  # Store OTP in memory
#     send_otp(email, otp)  # Send OTP to the user's email
#     logger.info(f"OTP sent to {email}.")
#     return jsonify(success=True, message='OTP sent to your email')

# def send_otp(email, otp):
#     logger.debug(f"Sending OTP {otp} to {email}")
#     msg = Message('Your OTP Code', recipients=[email])
#     msg.body = f'Your OTP code is {otp}'
#     try:
#         mail.send(msg)
#         logger.info(f"OTP sent successfully to {email}")
#     except Exception as e:
#         logger.error(f"Failed to send OTP: {str(e)}")
#         logger.error("Check your email configuration and credentials.")

# @app.route('/api/verifyOtp', methods=['POST'])
# def verify_otp():
#     data = request.get_json()
#     email = data.get('email')
#     otp = data.get('otp')

#     logger.debug(f"Received OTP for {email}: {otp}")
#     stored_otp = otp_storage.get(email)
#     logger.debug(f"Stored OTP for {email}: {stored_otp}")

#     # Verify the OTP
#     if email in otp_storage and stored_otp == int(otp):
#         del otp_storage[email]  # Remove OTP after verification
#         logger.info(f"OTP verified successfully for {email}")
#         return jsonify(success=True, message='OTP verified successfully', verified=True)
#     else:
#         logger.warning(f"Invalid OTP attempt for {email}: {otp}")
#         return jsonify(success=False, message='Invalid OTP', verified=False), 400

# @app.route('/api/sendPin', methods=['POST'])
# def send_pin():
#     data = request.get_json()
#     logger.debug(f"Received data: {data}")  # Log the incoming data
#     email = data.get('email')
#     pin = secrets.randbelow(1000000)  # Generate a secure 6-digit PIN

#     if not email:
#         logger.error("Email is required.")
#         return jsonify(success=False, message='Email is required'), 400

#     # Store the PIN in memory with expiration
#     pin_storage[email] = {'pin': pin, 'timestamp': time.time()}  # Store PIN and timestamp
#     logger.info(f"Generated PIN {pin} for {email}")

#     # Send the PIN to NodeMCU ESP32
#     esp32_url = "http://<192.168.1.100>/receivePin"  # Replace with your ESP32's IP address
#     try:
#         response = requests.post(esp32_url, json={'email': email, 'pin': pin})
#         if response.status_code == 200:
#             logger.info(f"PIN {pin} sent to ESP32 successfully.")
#         else:
#             logger.error(f"Failed to send PIN to ESP32: {response.text}")
#     except Exception as e:
#         logger.error(f"Error sending PIN to ESP32: {str(e)}")

#     return jsonify(success=True, message='PIN received successfully')

# @app.route('/api/sendIp', methods=['POST'])  # New route to receive IP address
# def send_ip():
#     data = request.get_json()
#     ip_address = data.get('ip')

#     if not ip_address:
#         logger.error("IP address is required.")
#         return jsonify(success=False, message='IP address is required'), 400

#     logger.info(f"Received IP address from ESP32: {ip_address}")
#     return jsonify(success=True, message='IP address received successfully')

# def expire_pins():
#     current_time = time.time()
#     for email in list(pin_storage.keys()):
#         if current_time - pin_storage[email]['timestamp'] > PIN_EXPIRATION_TIME:
#             del pin_storage[email]  # Remove PIN after expiration
#             logger.info(f"PIN for {email} has expired and has been removed.")

# # Call expire_pins periodically (you can implement a scheduler or a background thread for this)

# if __name__ == '__main__':
#     app.run(debug=True)

# ---------------------------------------------------------------------------------------------------------------------------

# from flask import Flask, request, jsonify
# from flask_mail import Mail, Message
# from flask_cors import CORS
# import secrets  # Use secrets for secure random generation
# import sqlite3
# import logging
# import os
# import requests  # Import requests to send HTTP requests
# import time  # Import time for managing expiration

# logging.getLogger("urllib3").setLevel(logging.WARNING)

# # Set up logging to send logs to a remote logging server
# class HTTPLogger(logging.Handler):
#     def emit(self, record):
#         log_entry = self.format(record)
#         # Send log entry to the logging server
#         try:
#             requests.post("https://serverbb.onrender.com/log", json={"log": log_entry})  # Replace with your logging server URL
#         except Exception as e:
#             print(f"Failed to send log to server: {e}")

# # Initialize the Flask application
# app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes

# # Configure Flask-Mail using environment variables
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Use environment variable
# app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Use environment variable
# app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')  # Use environment variable

# mail = Mail(app)

# # In-memory storage for OTP and PIN
# otp_storage = {}
# pin_storage = {}

# # Set up logging
# logging.basicConfig(level=logging.DEBUG)
# logger = logging.getLogger(__name__)
# http_handler = HTTPLogger()
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# http_handler.setFormatter(formatter)
# logger.addHandler(http_handler)

# # Define the expiration time for PINs
# PIN_EXPIRATION_TIME = 303  # 5 minutes and 3 seconds in seconds

# def create_connection():
#     conn = sqlite3.connect('users.db')
#     return conn

# @app.route('/')  # Route for the root URL
# def home():
#     return "Welcome to the Login API! Use /api/login to log in, /api/requestOtp to request an OTP, and /api/sendPin to generate a PIN."

# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')

#     # Validate the email and password against the database
#     conn = create_connection()
#     cursor = conn.cursor()
#     cursor.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password))
#     user = cursor.fetchone()
#     conn.close()

#     if user:
#         otp = secrets.randbelow(1000000)  # Generate a secure 6-digit OTP
#         otp_storage[email] = otp  # Store OTP in memory
#         send_otp(email, otp)  # Send OTP to the user's email
#         logger.info(f"OTP sent to {email}.")
#         return jsonify(success=True, message='OTP sent to your email')
#     else:
#         logger.warning(f"Invalid login attempt for email: {email}")
#         return jsonify(success=False, message='Invalid email or password'), 401

# @app.route('/api/requestOtp', methods=['POST'])
# def request_otp():
#     data = request.get_json()
#     email = data.get('email')

#     if not email:
#         logger.error("Email is required for OTP request.")
#         return jsonify(success=False, message='Email is required'), 400

#     # Generate a secure 6-digit OTP
#     otp = secrets.randbelow(1000000)
#     otp_storage[email] = otp  # Store OTP in memory
#     send_otp(email, otp)  # Send OTP to the user's email
#     logger.info(f"OTP sent to {email}.")
#     return jsonify(success=True, message='OTP sent to your email')

# def send_otp(email, otp):
#     logger.debug(f"Sending OTP {otp} to {email}")
#     msg = Message('Your OTP Code', recipients=[email])
#     msg.body = f'Your OTP code is {otp}'
#     try:
#         mail.send(msg)
#         logger.info(f"OTP sent successfully to {email}")
#     except Exception as e:
#         logger.error(f"Failed to send OTP: {str(e)}")
#         logger.error("Check your email configuration and credentials.")

# @app.route('/api/verifyOtp', methods=['POST'])
# def verify_otp():
#     data = request.get_json()
#     email = data.get('email')
#     otp = data.get('otp')


#     logger.debug(f"Received OTP for {email}: {otp}")
#     stored_otp = otp_storage.get(email)
#     logger.debug(f"Stored OTP for {email}: {stored_otp}")

#     # Verify the OTP
#     if email in otp_storage and stored_otp == int(otp):
#         del otp_storage[email]  # Remove OTP after verification
#         logger.info(f"OTP verified successfully for {email}")
#         return jsonify(success=True, message='OTP verified successfully', verified=True)
#     else:
#         logger.warning(f"Invalid OTP attempt for {email}: {otp}")
#         return jsonify(success=False, message='Invalid OTP', verified=False), 400

# @app.route('/api/sendPin', methods=['POST'])
# def send_pin():
#     data = request.get_json()
#     logger.debug(f"Received data: {data}")  # Log the incoming data
#     email = data.get('email')
#     pin = secrets.randbelow(1000000)  # Generate a secure 6-digit PIN

#     if not email:
#         logger.error("Email is required.")
#         return jsonify(success=False, message='Email is required'), 400

#     # Store the PIN in memory with expiration
#     pin_storage[email] = {'pin': pin, 'timestamp': time.time()}  # Store PIN and timestamp
#     logger.info(f"Generated PIN {pin} for {email}")

#     # Send the PIN to NodeMCU ESP32
#     esp32_url = "http://<192.168.1.100>/receivePin"  # Replace with your ESP32's IP address
#     try:
#         response = requests.post(esp32_url, json={'email': email, 'pin': pin})
#         if response.status_code == 200:
#             logger.info(f"PIN {pin} sent to ESP32 successfully.")
#         else:
#             logger.error(f"Failed to send PIN to ESP32: {response.text}")
#     except Exception as e:
#         logger.error(f"Error sending PIN to ESP32: {str(e)}")

#     return jsonify(success=True, message='PIN received successfully')

# def expire_pins():
#     current_time = time.time()
#     for email in list(pin_storage.keys()):
#         if current_time - pin_storage[email]['timestamp'] > PIN_EXPIRATION_TIME:
#             del pin_storage[email]  # Remove PIN after expiration
#             logger.info(f"PIN for {email} has expired and has been removed.")

# # Call expire_pins periodically (you can implement a scheduler or a background thread for this)

# if __name__ == '__main__':
#     app.run(debug=True)