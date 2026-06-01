from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import importlib
import os
import re
from werkzeug.utils import secure_filename
import razorpay
from flask import request, jsonify, render_template
import traceback
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import make_response, render_template
from utils.pdf_generator import generate_pdf
from datetime import datetime

# Initialize Razorpay Client
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)


app = Flask(__name__)
app.secret_key = config.SECRET_KEY

password_reset_serializer = URLSafeTimedSerializer(app.secret_key)
PASSWORD_RESET_MAX_AGE = 1800
ORDER_STATUSES = ["Pending", "Confirmed", "Packed", "Shipped", "Delivered"]
ADMIN_APPROVAL_STATUSES = ["pending", "approved", "rejected"]


class SQLiteCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def execute(self, query, params=None):
        query = self._translate_query(query)
        params = self._translate_params(params)
        if params is None:
            return self.cursor.execute(query)
        return self.cursor.execute(query, params)

    def executemany(self, query, seq_of_params):
        query = self._translate_query(query)
        seq_of_params = [self._translate_params(params) for params in seq_of_params]
        return self.cursor.executemany(query, seq_of_params)

    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(row) for row in self.cursor.fetchall()]

    def close(self):
        self.cursor.close()

    @staticmethod
    def _translate_query(query):
        query = query.replace("%s", "?")
        query = re.sub(
            r"\bINT\s+AUTO_INCREMENT\s+PRIMARY\s+KEY\b",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            query,
            flags=re.IGNORECASE
        )
        query = re.sub(
            r"DATE_SUB\(CURDATE\(\),\s*INTERVAL\s+(\d+)\s+DAY\)",
            r"DATE('now', '-\1 day')",
            query,
            flags=re.IGNORECASE
        )
        return query

    @staticmethod
    def _translate_params(params):
        if params is None:
            return None
        if isinstance(params, bytes):
            return params.decode("utf-8")
        if isinstance(params, tuple):
            return tuple(SQLiteCursor._translate_params(param) for param in params)
        if isinstance(params, list):
            return [SQLiteCursor._translate_params(param) for param in params]
        if isinstance(params, dict):
            return {key: SQLiteCursor._translate_params(value) for key, value in params.items()}
        return params


class SQLiteConnection:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def cursor(self, dictionary=False):
        return SQLiteCursor(self.conn.cursor())

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()


def get_razorpay_client():
    importlib.reload(config)
    return razorpay.Client(
        auth=(config.RAZORPAY_KEY_ID.strip(), config.RAZORPAY_KEY_SECRET.strip())
    )


def is_safe_next_url(next_url):
    return next_url and next_url.startswith("/") and not next_url.startswith("//")


def generate_password_reset_token(email, account_type):
    return password_reset_serializer.dumps(
        {"email": email, "account_type": account_type},
        salt="password-reset"
    )


def verify_password_reset_token(token, account_type):
    data = password_reset_serializer.loads(
        token,
        salt="password-reset",
        max_age=PASSWORD_RESET_MAX_AGE
    )

    if data.get("account_type") != account_type:
        return None

    return data.get("email")


def get_superadmin_credentials():
    return (
        getattr(config, "SUPERADMIN_EMAIL", os.environ.get("SUPERADMIN_EMAIL", "owner@smartkart.com")),
        getattr(config, "SUPERADMIN_PASSWORD", os.environ.get("SUPERADMIN_PASSWORD", "owner123"))
    )


def ensure_admin_approval_column():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("PRAGMA table_info(admin)")
    column = next(
        (existing_column for existing_column in cursor.fetchall() if existing_column["name"] == "approval_status"),
        None
    )

    if not column:
        cursor.close()
        cursor = conn.cursor()
        cursor.execute(
            "ALTER TABLE admin ADD COLUMN approval_status VARCHAR(20) NOT NULL DEFAULT 'approved'"
        )
        conn.commit()

    cursor.close()
    conn.close()


def ensure_superadmin_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS super_admins (
            superadmin_id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    cursor.close()
    conn.close()


def superadmin_required():
    if not session.get('superadmin_id'):
        flash("Please login as super admin.", "danger")
        return False
    return True

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)

# ---------------- DATABASE CONNECTION ----------------
def get_db_connection():
    db_path = getattr(config, "DB_PATH", "smartkart.db")
    return SQLiteConnection(db_path)


def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            profile_image VARCHAR(255),
            approval_status VARCHAR(20) NOT NULL DEFAULT 'approved',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(150) NOT NULL,
            description TEXT,
            category VARCHAR(100),
            price REAL NOT NULL,
            image VARCHAR(255),
            admin_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admin(admin_id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS addresses (
            address_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name VARCHAR(100) NOT NULL,
            phone VARCHAR(15) NOT NULL,
            address_line TEXT NOT NULL,
            city VARCHAR(50) NOT NULL,
            state VARCHAR(50) NOT NULL,
            pincode VARCHAR(10) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            razorpay_order_id VARCHAR(150),
            razorpay_payment_id VARCHAR(150),
            amount REAL NOT NULL DEFAULT 0,
            payment_status VARCHAR(30) NOT NULL DEFAULT 'pending',
            order_status VARCHAR(30) NOT NULL DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER,
            product_name VARCHAR(150) NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            price REAL NOT NULL DEFAULT 0,
            FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE SET NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS super_admins (
            superadmin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def get_carousel_products(cursor):
    cursor.execute(
        """
        SELECT *
        FROM products
        WHERE LOWER(category) IN ('smartphone', 'smartphones', 'mobile', 'mobiles')
           OR LOWER(name) LIKE '%marshall%'
        ORDER BY
            CASE WHEN LOWER(name) LIKE '%marshall%' THEN 1 ELSE 0 END,
            product_id DESC
        LIMIT 5
        """
    )
    return cursor.fetchall()


# ---------------- HOME PAGE ----------------
@app.route('/')
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    carousel_products = get_carousel_products(cursor)
    cursor.execute("SELECT * FROM products ORDER BY product_id DESC")
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/index.html", products=products, carousel_products=carousel_products)


@app.route('/about')
def about():
    return render_template("admin/about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash("Thanks for contacting SmartKart. We will get back to you soon.", "success")
        return redirect(url_for('contact'))

    return render_template("admin/contact.html")


# ---------------- ADMIN SIGNUP ----------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    ensure_admin_approval_column()

    # Show Signup Page
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # Get Form Data
    name = request.form['name']
    email = request.form['email']

    # Check Existing Email
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT admin_id FROM admin WHERE email=%s",
        (email,)
    )

    existing_admin = cursor.fetchone()

    cursor.close()
    conn.close()

    # Email Exists
    if existing_admin:
        flash("Email already registered.", "danger")
        return redirect(url_for('admin_signup'))

    # Store Data in Session
    session['signup_name'] = name
    session['signup_email'] = email

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Save OTP
    session['otp'] = otp

    # Send Email
    message = Message(
        subject="SmartCart OTP Verification",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )

    message.body = f"Your OTP is: {otp}"

    mail.send(message)

    flash("OTP sent successfully.", "success")

    return redirect(url_for('verify_otp'))


# ---------------- VERIFY OTP ----------------
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    # Show OTP Page
    if request.method == 'GET':
        return render_template("admin/verify_otp.html")

    # Get Form Data
    user_otp = request.form['otp']
    password = request.form['password']

    # Check OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP.", "danger")
        return redirect(url_for('verify_otp'))

    # Hash Password
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    # Save Admin
    conn = get_db_connection()
    cursor = conn.cursor()

    ensure_admin_approval_column()

    cursor.execute(
        """
        INSERT INTO admin(name, email, password, approval_status)
        VALUES(%s, %s, %s, %s)
        """,
        (
            session['signup_name'],
            session['signup_email'],
            hashed_password,
            "pending"
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    # Clear Session
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Registration Successful!", "success")

    return redirect(url_for('admin_login'))


# ---------------- ADMIN LOGIN ----------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    ensure_admin_approval_column()

    # Show Login Page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # Get Form Data
    email = request.form['email']
    password = request.form['password']

    # Database Connection
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM admin WHERE email=%s",
        (email,)
    )

    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    # Email Not Found
    if admin is None:
        flash("Email not found.", "danger")
        return redirect(url_for('admin_login'))

    if admin.get('approval_status') == 'pending':
        flash("Your admin account is waiting for super admin approval.", "danger")
        return redirect(url_for('admin_login'))

    if admin.get('approval_status') == 'rejected':
        flash("Your admin account has been rejected by the super admin.", "danger")
        return redirect(url_for('admin_login'))

    # Stored Password
    stored_hashed_password = admin['password']

    # Convert if Needed
    if isinstance(stored_hashed_password, str):
        stored_hashed_password = stored_hashed_password.encode('utf-8')

    # Check Password
    if not bcrypt.checkpw(
        password.encode('utf-8'),
        stored_hashed_password
    ):
        flash("Incorrect password.", "danger")
        return redirect(url_for('admin_login'))

    # Create Session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin-forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():

    if request.method == 'GET':
        return render_template("admin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not admin:
        flash("Admin email not found.", "danger")
        return redirect(url_for('admin_forgot_password'))

    token = generate_password_reset_token(email, "admin")
    reset_link = url_for('admin_reset_password', token=token, _external=True)

    message = Message(
        subject="SmartKart Admin Password Reset Link",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = (
        "Click this link to reset your SmartKart admin password:\n\n"
        f"{reset_link}\n\n"
        "This link will expire in 30 minutes."
    )
    mail.send(message)

    flash("Password reset link sent to your admin email.", "success")
    return redirect(url_for('admin_login'))


@app.route('/admin-reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):

    try:
        email = verify_password_reset_token(token, "admin")
    except SignatureExpired:
        flash("Password reset link expired. Please request a new one.", "danger")
        return redirect(url_for('admin_forgot_password'))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('admin_forgot_password'))

    if not email:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('admin_forgot_password'))

    if request.method == 'GET':
        return render_template("admin/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('admin_reset_password', token=token))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET password=%s WHERE email=%s",
        (hashed_password, email)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Admin password reset successful. Please login.", "success")
    return redirect(url_for('admin_login'))


# ---------------- DASHBOARD ----------------
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect Dashboard
    if 'admin_id' not in session:
        flash("Please login first.", "danger")
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    admin_id = session['admin_id']

    cursor.execute("SELECT COUNT(*) AS total_products FROM products WHERE admin_id=%s", (admin_id,))
    total_products = cursor.fetchone()['total_products']

    cursor.execute("""
        SELECT COUNT(DISTINCT o.order_id) AS total_orders,
               COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN oi.quantity * oi.price ELSE 0 END), 0) AS total_revenue,
               COALESCE(SUM(oi.quantity), 0) AS items_sold
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        JOIN orders o ON oi.order_id = o.order_id
        WHERE p.admin_id=%s
    """, (admin_id,))
    stats = cursor.fetchone()

    cursor.execute("""
        SELECT product_id, name, category, price, image
        FROM products
        WHERE admin_id=%s
        ORDER BY product_id DESC
        LIMIT 6
    """, (admin_id,))
    recent_products = cursor.fetchall()

    cursor.execute("""
        SELECT o.order_id, o.payment_status, o.order_status, o.created_at,
               u.name AS username,
               COALESCE(SUM(oi.quantity * oi.price), 0) AS admin_amount,
               COALESCE(SUM(oi.quantity), 0) AS item_count
        FROM orders o
        JOIN order_items oi ON o.order_id = oi.order_id
        JOIN products p ON oi.product_id = p.product_id
        LEFT JOIN users u ON o.user_id = u.user_id
        WHERE p.admin_id=%s
        GROUP BY o.order_id, o.payment_status, o.order_status, o.created_at, u.name
        ORDER BY o.created_at DESC
        LIMIT 5
    """, (admin_id,))
    recent_orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/dashboard.html",
        admin_name=session['admin_name'],
        total_products=total_products,
        total_orders=stats['total_orders'],
        total_revenue=stats['total_revenue'],
        items_sold=stats['items_sold'],
        recent_products=recent_products,
        recent_orders=recent_orders
    )



# ------------------- IMAGE UPLOAD PATH -------------------
UPLOAD_FOLDER = 'static/uploads/product_images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database
    conn = get_db_connection()
    cursor = conn.cursor()

    admin_id = session['admin_id']
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image, admin_id) VALUES (%s, %s, %s, %s, %s, %s)",
        (name, description, category, price, filename, admin_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE admin_id=%s"
    params = [session['admin_id']]

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )



#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM products WHERE product_id=%s AND admin_id=%s",
        (item_id, session['admin_id'])
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)



# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM products WHERE product_id=%s AND admin_id=%s",
        (item_id, session['admin_id'])
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE-12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s AND admin_id = %s", (item_id, session['admin_id']))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":
        
        # Secure filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, image=%s
        WHERE product_id=%s AND admin_id=%s
    """, (name, description, category, price, final_image_name, item_id, session['admin_id']))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
#  route-13 DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch product to get image name
    cursor.execute(
    "SELECT image FROM products WHERE product_id=%s AND admin_id=%s",
    (item_id, session['admin_id']))

    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute("DELETE FROM products WHERE product_id=%s AND admin_id=%s", (item_id, session['admin_id']))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config['ADMIN_UPLOAD_FOLDER'] = os.path.join(
    BASE_DIR,
    'static',
    'admin_uploads'
)

@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        new_filename = secure_filename(new_image.filename)

        # Save new image
        # Create folder if not exists
        os.makedirs(app.config['ADMIN_UPLOAD_FOLDER'], exist_ok=True)

        # Save new image
        image_path = os.path.join(
            app.config['ADMIN_UPLOAD_FOLDER'],
            new_filename
        )

        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')




# ---------------- LOGOUT ----------------
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")

    return redirect(url_for('admin_login'))




# =================================================================
# ROUTE: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')



# =================================================================
# ROUTE: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    next_url = request.args.get('next') or request.form.get('next') or ''
    if not is_safe_next_url(next_url):
        next_url = ''

    if request.method == 'GET':
        return render_template("user/user_login.html", next_url=next_url)

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect(url_for('user_login', next=next_url) if next_url else url_for('user_login'))

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect(url_for('user_login', next=next_url) if next_url else url_for('user_login'))

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect(next_url or url_for('user_dashboard'))


@app.route('/user-forgot-password', methods=['GET', 'POST'])
def user_forgot_password():

    if request.method == 'GET':
        return render_template("user/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        flash("User email not found.", "danger")
        return redirect(url_for('user_forgot_password'))

    token = generate_password_reset_token(email, "user")
    reset_link = url_for('user_reset_password', token=token, _external=True)

    message = Message(
        subject="SmartKart Password Reset Link",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = (
        "Click this link to reset your SmartKart password:\n\n"
        f"{reset_link}\n\n"
        "This link will expire in 30 minutes."
    )
    mail.send(message)

    flash("Password reset link sent to your email.", "success")
    return redirect(url_for('user_login'))


@app.route('/user-reset-password/<token>', methods=['GET', 'POST'])
def user_reset_password(token):

    try:
        email = verify_password_reset_token(token, "user")
    except SignatureExpired:
        flash("Password reset link expired. Please request a new one.", "danger")
        return redirect(url_for('user_forgot_password'))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('user_forgot_password'))

    if not email:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('user_forgot_password'))

    if request.method == 'GET':
        return render_template("user/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('user_reset_password', token=token))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password=%s WHERE email=%s",
        (hashed_password.decode('utf-8'), email)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password reset successful. Please login.", "success")
    return redirect(url_for('user_login'))




# =================================================================
# ROUTE: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT DISTINCT category FROM products ORDER BY category")
    categories = cursor.fetchall()

    carousel_products = get_carousel_products(cursor)

    cursor.execute("SELECT * FROM products ORDER BY product_id DESC")
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_home.html",
        user_name=session['user_name'],
        products=products,
        carousel_products=carousel_products,
        categories=categories
    )



# =================================================================
# ROUTE: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')



# =================================================================
# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================
@app.route('/user/products')
def user_products():

    # Optional: restrict only logged-in users
    if 'user_id' not in session:
        flash("Please login to view products!", "danger")
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )



# =================================================================
# ROUTE: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect(url_for('user_login', next=url_for('user_product_details', product_id=product_id)))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect(url_for('user_login', next=url_for('user_product_details', product_id=product_id)))

    session.pop('checkout_cart', None)

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer)   # ⭐ Return to same page

# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)


# =================================================================
# CHECKOUT SELECTED CART ITEMS
# =================================================================
@app.route('/user/cart/checkout', methods=['POST'])
def checkout_selected_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    session.pop('checkout_cart', None)
    cart = session.get('cart', {})
    selected_products = request.form.getlist('selected_products')

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    if not selected_products:
        flash("Please select at least one product to checkout.", "danger")
        return redirect('/user/cart')

    checkout_cart = {
        pid: cart[pid]
        for pid in selected_products
        if pid in cart
    }

    if not checkout_cart:
        flash("Selected products are no longer in your cart.", "danger")
        return redirect('/user/cart')

    session['checkout_cart'] = checkout_cart
    return redirect('/user/select-address')


# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    session.pop('checkout_cart', None)
    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    session.pop('checkout_cart', None)
    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    session.pop('checkout_cart', None)
    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')


# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('checkout_cart') or session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    try:
        razorpay_order = get_razorpay_client().order.create({
            "amount": razorpay_amount,
            "currency": "INR",
            "payment_capture": "1"
        })
    except razorpay.errors.BadRequestError as e:
        app.logger.error("Razorpay authentication/order error: %s", str(e))
        flash("Razorpay authentication failed. Please check that the Test Key ID and Test Key Secret are copied correctly, then try again.", "danger")
        return redirect('/user/select-address')

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )

# =================================================================
# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )



# =================================================================
# ROUTE: BUY NOW → ADD TO CART + GO TO ADDRESS PAGE
# =================================================================
@app.route('/user/buy-now/<int:product_id>')
def buy_now(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect(url_for('user_login', next=url_for('user_product_details', product_id=product_id)))

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect('/user/products')

    pid = str(product_id)

    # Add to cart (or increase qty)
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    session['checkout_cart'] = {pid: cart[pid]}

    return redirect('/user/select-address')


# =================================================================
# ROUTE: SELECT ADDRESS PAGE (before checkout)
# =================================================================
@app.route('/user/select-address')
def select_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('checkout_cart') or session.get('cart', {})
    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM addresses WHERE user_id=%s ORDER BY address_id DESC",
        (session['user_id'],)
    )
    addresses = cursor.fetchall()
    cursor.close()
    conn.close()

    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template(
        "user/select_address.html",
        addresses=addresses,
        grand_total=grand_total
    )


# =================================================================
# ROUTE: ADD NEW ADDRESS
# =================================================================
@app.route('/user/add-address', methods=['GET', 'POST'])
def add_address():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    if request.method == 'GET':
        return render_template("user/add_address.html")

    # Get form data
    full_name = request.form['full_name']
    phone = request.form['phone']
    address_line = request.form['address_line']
    city = request.form['city']
    state = request.form['state']
    pincode = request.form['pincode']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO addresses (user_id, full_name, phone, address_line, city, state, pincode)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (session['user_id'], full_name, phone, address_line, city, state, pincode))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Address added successfully!", "success")
    return redirect('/user/select-address')


# =================================================================
# ROUTE: EDIT ADDRESS
# =================================================================
@app.route('/user/edit-address/<int:address_id>', methods=['GET', 'POST'])
def edit_address(address_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'GET':
        cursor.execute(
            "SELECT * FROM addresses WHERE address_id=%s AND user_id=%s",
            (address_id, session['user_id'])
        )
        address = cursor.fetchone()
        cursor.close()
        conn.close()

        if not address:
            flash("Address not found!", "danger")
            return redirect('/user/select-address')

        return render_template("user/edit_address.html", address=address)

    # POST - update address
    full_name = request.form['full_name']
    phone = request.form['phone']
    address_line = request.form['address_line']
    city = request.form['city']
    state = request.form['state']
    pincode = request.form['pincode']

    cursor.execute("""
        UPDATE addresses
        SET full_name=%s, phone=%s, address_line=%s, city=%s, state=%s, pincode=%s
        WHERE address_id=%s AND user_id=%s
    """, (full_name, phone, address_line, city, state, pincode, address_id, session['user_id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Address updated!", "success")
    return redirect('/user/select-address')


# =================================================================
# ROUTE: DELETE ADDRESS
# =================================================================
@app.route('/user/delete-address/<int:address_id>')
def delete_address(address_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM addresses WHERE address_id=%s AND user_id=%s",
        (address_id, session['user_id'])
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted!", "success")
    return redirect('/user/select-address')


# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        get_razorpay_client().utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('checkout_cart') or session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Remove purchased items while keeping unchecked cart items.
        full_cart = session.get('cart', {})
        for pid_str in cart.keys():
            full_cart.pop(pid_str, None)

        if full_cart:
            session['cart'] = full_cart
        else:
            session.pop('cart', None)

        session.pop('checkout_cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ----------------------------
# GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"
    return response


# ================================================================
# ADMIN: VIEW ALL ORDERS
# ================================================================
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount,
               o.payment_status, o.order_status, o.created_at,
               u.name AS username, u.email AS user_email,
               COUNT(oi.product_id) AS item_count
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        LEFT JOIN order_items oi ON o.order_id = oi.order_id
        GROUP BY o.order_id, o.user_id, o.amount, o.payment_status, o.order_status,
                 o.created_at, u.name, u.email
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("admin/order_list.html", orders=orders, statuses=ORDER_STATUSES)

# ================================================================
# ADMIN: VIEW ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT o.*,
               u.name AS username,
               u.email AS user_email,
               a.full_name,
               a.phone,
               a.address_line,
               a.city,
               a.state,
               a.pincode
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        LEFT JOIN addresses a ON a.address_id = (
            SELECT a2.address_id
            FROM addresses a2
            WHERE a2.user_id = o.user_id
            ORDER BY a2.address_id DESC
            LIMIT 1
        )
        WHERE o.order_id=%s
    """, (order_id,))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/admin/orders')

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    current_status = order.get('order_status') or ORDER_STATUSES[0]
    status_index = ORDER_STATUSES.index(current_status) if current_status in ORDER_STATUSES else 0

    return render_template(
        "admin/order_details.html",
        order=order,
        items=items,
        statuses=ORDER_STATUSES,
        status_index=status_index
    )


# ================================================================
# ADMIN: UPDATE ORDER STATUS
# ================================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    if new_status not in ORDER_STATUSES:
        flash("Invalid order status.", "danger")
        return redirect(f"/admin/order/{order_id}")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET order_status=%s WHERE order_id=%s",
                    (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")


# ================================================================
# SUPER ADMIN: OWNER PANEL
# ================================================================
@app.route('/superadmin-login', methods=['GET', 'POST'])
def superadmin_login():

    ensure_superadmin_table()

    if request.method == 'GET':
        return render_template("superadmin/login.html")

    email = request.form['email']
    password = request.form['password']
    super_email, super_password = get_superadmin_credentials()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM super_admins WHERE email=%s", (email,))
    superadmin = cursor.fetchone()
    cursor.close()
    conn.close()

    config_login = email == super_email and password == super_password
    db_login = False

    if superadmin:
        stored_password = superadmin['password']
        if isinstance(stored_password, str):
            stored_password = stored_password.encode('utf-8')
        db_login = bcrypt.checkpw(password.encode('utf-8'), stored_password)

    if not config_login and not db_login:
        flash("Invalid super admin credentials.", "danger")
        return redirect(url_for('superadmin_login'))

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)
    session['superadmin_id'] = superadmin['superadmin_id'] if superadmin else 'owner'
    session['superadmin_name'] = superadmin['name'] if superadmin else 'Owner'
    session['superadmin_email'] = email

    flash("Super admin login successful.", "success")
    return redirect(url_for('superadmin_dashboard'))


@app.route('/superadmin-register', methods=['GET', 'POST'])
def superadmin_register():

    ensure_superadmin_table()

    if request.method == 'GET':
        return render_template("superadmin/register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('superadmin_register'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT superadmin_id FROM super_admins WHERE email=%s", (email,))
    existing_superadmin = cursor.fetchone()

    if existing_superadmin:
        cursor.close()
        conn.close()
        flash("Super admin email already registered.", "danger")
        return redirect(url_for('superadmin_register'))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.close()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO super_admins (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_password.decode('utf-8'))
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Super admin registered successfully. Please login.", "success")
    return redirect(url_for('superadmin_login'))


@app.route('/superadmin-forgot-password', methods=['GET', 'POST'])
def superadmin_forgot_password():

    ensure_superadmin_table()

    if request.method == 'GET':
        return render_template("superadmin/forgot_password.html")

    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT superadmin_id FROM super_admins WHERE email=%s", (email,))
    superadmin = cursor.fetchone()
    cursor.close()
    conn.close()

    if not superadmin:
        flash("Registered super admin email not found.", "danger")
        return redirect(url_for('superadmin_forgot_password'))

    token = generate_password_reset_token(email, "superadmin")
    reset_link = url_for('superadmin_reset_password', token=token, _external=True)

    message = Message(
        subject="SmartKart Super Admin Password Reset Link",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = (
        "Click this link to reset your SmartKart super admin password:\n\n"
        f"{reset_link}\n\n"
        "This link will expire in 30 minutes."
    )
    mail.send(message)

    flash("Password reset link sent to your super admin email.", "success")
    return redirect(url_for('superadmin_login'))


@app.route('/superadmin-reset-password/<token>', methods=['GET', 'POST'])
def superadmin_reset_password(token):

    ensure_superadmin_table()

    try:
        email = verify_password_reset_token(token, "superadmin")
    except SignatureExpired:
        flash("Password reset link expired. Please request a new one.", "danger")
        return redirect(url_for('superadmin_forgot_password'))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('superadmin_forgot_password'))

    if not email:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for('superadmin_forgot_password'))

    if request.method == 'GET':
        return render_template("superadmin/reset_password.html", token=token)

    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('superadmin_reset_password', token=token))

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE super_admins SET password=%s WHERE email=%s",
        (hashed_password.decode('utf-8'), email)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Super admin password reset successful. Please login.", "success")
    return redirect(url_for('superadmin_login'))


@app.route('/superadmin-logout')
def superadmin_logout():
    session.pop('superadmin_id', None)
    session.pop('superadmin_name', None)
    session.pop('superadmin_email', None)
    flash("Super admin logged out successfully.", "success")
    return redirect(url_for('superadmin_login'))


@app.route('/superadmin/dashboard')
def superadmin_dashboard():
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    ensure_admin_approval_column()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total_admins FROM admin")
    total_admins = cursor.fetchone()['total_admins']

    cursor.execute("SELECT COUNT(*) AS pending_admins FROM admin WHERE approval_status='pending'")
    pending_admins = cursor.fetchone()['pending_admins']

    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    total_products = cursor.fetchone()['total_products']

    cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
    total_orders = cursor.fetchone()['total_orders']

    cursor.execute("SELECT COALESCE(SUM(amount), 0) AS total_revenue FROM orders WHERE payment_status='paid'")
    total_revenue = cursor.fetchone()['total_revenue']

    cursor.execute("SELECT COUNT(*) AS paid_orders FROM orders WHERE payment_status='paid'")
    paid_orders = cursor.fetchone()['paid_orders']

    cursor.execute("""
        SELECT DATE(created_at) AS order_date,
               COUNT(*) AS order_count,
               COALESCE(SUM(CASE WHEN payment_status='paid' THEN amount ELSE 0 END), 0) AS revenue
        FROM orders
        WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """)
    sales_rows = cursor.fetchall()
    max_daily_revenue = max([float(row['revenue'] or 0) for row in sales_rows] + [1])
    sales_chart = [
        {
            "label": datetime.strptime(row['order_date'], "%Y-%m-%d").strftime("%d %b") if isinstance(row['order_date'], str) else (row['order_date'].strftime("%d %b") if hasattr(row['order_date'], "strftime") else (row['order_date'] or "N/A")),
            "orders": row['order_count'],
            "revenue": row['revenue'],
            "height": max(8, int((float(row['revenue'] or 0) / max_daily_revenue) * 100))
        }
        for row in sales_rows
    ]

    cursor.execute("""
        SELECT COALESCE(order_status, 'Pending') AS status, COUNT(*) AS total
        FROM orders
        GROUP BY COALESCE(order_status, 'Pending')
        ORDER BY total DESC
    """)
    status_rows = cursor.fetchall()

    cursor.execute("""
        SELECT a.name AS admin_name,
               COUNT(DISTINCT p.product_id) AS products,
               COUNT(DISTINCT o.order_id) AS orders,
               COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN oi.quantity * oi.price ELSE 0 END), 0) AS revenue
        FROM admin a
        LEFT JOIN products p ON a.admin_id = p.admin_id
        LEFT JOIN order_items oi ON p.product_id = oi.product_id
        LEFT JOIN orders o ON oi.order_id = o.order_id
        GROUP BY a.admin_id, a.name
        ORDER BY revenue DESC, orders DESC
        LIMIT 5
    """)
    top_admins = cursor.fetchall()

    cursor.execute("""
        SELECT o.order_id, o.amount, o.payment_status, o.order_status, o.created_at,
               u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
        LIMIT 5
    """)
    recent_orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "superadmin/dashboard.html",
        total_admins=total_admins,
        pending_admins=pending_admins,
        total_products=total_products,
        total_orders=total_orders,
        total_revenue=total_revenue,
        paid_orders=paid_orders,
        sales_chart=sales_chart,
        status_rows=status_rows,
        top_admins=top_admins,
        recent_orders=recent_orders
    )


@app.route('/superadmin/admins')
def superadmin_admins():
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    ensure_admin_approval_column()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT a.admin_id, a.name, a.email, a.approval_status,
               COUNT(p.product_id) AS product_count
        FROM admin a
        LEFT JOIN products p ON a.admin_id = p.admin_id
        GROUP BY a.admin_id, a.name, a.email, a.approval_status
        ORDER BY a.admin_id DESC
    """)
    admins = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("superadmin/admins.html", admins=admins, statuses=ADMIN_APPROVAL_STATUSES)


@app.route('/superadmin/admin/<int:admin_id>/status', methods=['POST'])
def superadmin_update_admin_status(admin_id):
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    ensure_admin_approval_column()
    new_status = request.form.get('approval_status')

    if new_status not in ADMIN_APPROVAL_STATUSES:
        flash("Invalid admin approval status.", "danger")
        return redirect(url_for('superadmin_admins'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE admin SET approval_status=%s WHERE admin_id=%s",
        (new_status, admin_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Admin status updated successfully.", "success")
    return redirect(url_for('superadmin_admins'))


@app.route('/superadmin/products')
def superadmin_products():
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    ensure_admin_approval_column()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, a.name AS admin_name, a.email AS admin_email, a.approval_status
        FROM products p
        LEFT JOIN admin a ON p.admin_id = a.admin_id
        ORDER BY p.product_id DESC
    """)
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("superadmin/products.html", products=products)


@app.route('/superadmin/orders')
def superadmin_orders():
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, o.payment_status, o.order_status, o.created_at,
               u.name AS username, u.email AS user_email,
               COUNT(oi.product_id) AS item_count
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        LEFT JOIN order_items oi ON o.order_id = oi.order_id
        GROUP BY o.order_id, o.user_id, o.amount, o.payment_status, o.order_status,
                 o.created_at, u.name, u.email
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("superadmin/orders.html", orders=orders)


@app.route('/superadmin/revenue')
def superadmin_revenue():
    if not superadmin_required():
        return redirect(url_for('superadmin_login'))

    ensure_admin_approval_column()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COALESCE(SUM(amount), 0) AS total_revenue FROM orders WHERE payment_status='paid'")
    total_revenue = cursor.fetchone()['total_revenue']

    cursor.execute("SELECT COUNT(*) AS paid_orders FROM orders WHERE payment_status='paid'")
    paid_orders = cursor.fetchone()['paid_orders']

    cursor.execute("""
        SELECT a.admin_id, a.name AS admin_name, a.email AS admin_email,
               COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN oi.quantity * oi.price ELSE 0 END), 0) AS revenue,
               COUNT(DISTINCT CASE WHEN o.payment_status='paid' THEN o.order_id END) AS order_count
        FROM admin a
        LEFT JOIN products p ON a.admin_id = p.admin_id
        LEFT JOIN order_items oi ON p.product_id = oi.product_id
        LEFT JOIN orders o ON oi.order_id = o.order_id
        GROUP BY a.admin_id, a.name, a.email
        ORDER BY revenue DESC
    """)
    admin_revenue = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "superadmin/revenue.html",
        total_revenue=total_revenue,
        paid_orders=paid_orders,
        admin_revenue=admin_revenue
    )



# ---------------- RUN APP ----------------
initialize_database()


if __name__ == '__main__':
    app.run(debug=True)
