# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "your_secret_key_here"   # used for sessions

# Super Admin / Owner Login
SUPERADMIN_EMAIL = "owner@smartkart.com"
SUPERADMIN_PASSWORD = "owner123"

# SQLite Database Configuration
DB_PATH = "smartkart.db"

# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'dhanushnemmoju@gmail.com'
MAIL_PASSWORD = 'iivj wfqi nhkk hidj'   # Gmail App Password

# Razorpay API Keys
RAZORPAY_KEY_ID = 'rzp_test_SwHPZCgTazz2NR'
RAZORPAY_KEY_SECRET = 'zg5P9lmda3fRi1oxc5xNrreb'
