from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os, uuid, datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber-hub-secret-change-in-prod-2025')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# ✅ Ensure folders exist (IMPORTANT for Render)
os.makedirs('instance', exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# ─── Models ─────────────────────────────────

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class ContentCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    full_content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(60), default='General')
    thumbnail = db.Column(db.String(200), default='')
    icon = db.Column(db.String(10), default='🔒')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    order_index = db.Column(db.Integer, default=0)

# ─── Helpers ─────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ─────────────────────────────────

@app.route('/')
def index():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    return render_template('index.html', cards=cards)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))

        flash('Invalid credentials')

    return render_template('admin_login.html')

@app.route('/admin')
@login_required
def admin_dashboard():
    cards = ContentCard.query.all()
    return render_template('admin_dashboard.html', cards=cards)

# ─── DB INIT FIX (IMPORTANT) ─────────────────

def init_db():
    db.create_all()

    if not Admin.query.first():
        admin = Admin(username='shivam')
        admin.set_password('admin123')
        db.session.add(admin)

    db.session.commit()

# ✅ THIS IS THE MAIN FIX (Render ke liye)
with app.app_context():
    init_db()

# ─── Run ─────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True)
