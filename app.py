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
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db = SQLAlchemy(app)

# ─── Models ───────────────────────────────────────────────────────────────────

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

# ─── Helpers ──────────────────────────────────────────────────────────────────

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# ─── Public Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    return render_template('index.html', cards=cards)

@app.route('/api/card/<int:card_id>')
def get_card(card_id):
    card = ContentCard.query.get_or_404(card_id)
    return jsonify({
        'id': card.id,
        'title': card.title,
        'description': card.description,
        'full_content': card.full_content,
        'category': card.category,
        'thumbnail': card.thumbnail,
        'icon': card.icon,
        'created_at': card.created_at.strftime('%B %d, %Y')
    })

# ─── Admin Routes ──────────────────────────────────────────────────────────────

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    return render_template('admin_dashboard.html', cards=cards)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def admin_add():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        full_content = request.form.get('full_content', '').strip()
        category = request.form.get('category', 'General').strip()
        icon = request.form.get('icon', '🔒').strip()
        order_index = int(request.form.get('order_index', 0))

        thumbnail = ''
        if 'thumbnail' in request.files:
            file = request.files['thumbnail']
            if file and file.filename and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                thumbnail = f"uploads/{filename}"

        card = ContentCard(
            title=title, description=description,
            full_content=full_content, category=category,
            thumbnail=thumbnail, icon=icon, order_index=order_index
        )
        db.session.add(card)
        db.session.commit()
        flash('Card added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add.html')

@app.route('/admin/edit/<int:card_id>', methods=['GET', 'POST'])
@login_required
def admin_edit(card_id):
    card = ContentCard.query.get_or_404(card_id)
    if request.method == 'POST':
        card.title = request.form.get('title', '').strip()
        card.description = request.form.get('description', '').strip()
        card.full_content = request.form.get('full_content', '').strip()
        card.category = request.form.get('category', 'General').strip()
        card.icon = request.form.get('icon', '🔒').strip()
        card.order_index = int(request.form.get('order_index', 0))

        if 'thumbnail' in request.files:
            file = request.files['thumbnail']
            if file and file.filename and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                card.thumbnail = f"uploads/{filename}"

        db.session.commit()
        flash('Card updated!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit.html', card=card)

@app.route('/admin/delete/<int:card_id>', methods=['POST'])
@login_required
def admin_delete(card_id):
    card = ContentCard.query.get_or_404(card_id)
    db.session.delete(card)
    db.session.commit()
    flash('Card deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Init ──────────────────────────────────────────────────────────────────────

def init_db():
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            admin = Admin(username='shivam')
            admin.set_password('admin123')  # CHANGE THIS
            db.session.add(admin)

        if not ContentCard.query.first():
            sample_cards = [
                ContentCard(
                    title='WiFi Security Basics',
                    description='Most people leave their WiFi completely exposed. Here\'s what you should actually know.',
                    full_content='''## WiFi Security: What You\'re Missing

Your home WiFi is the front door to your digital life. Most people never change the default router password, use weak encryption, or even know what\'s connected to their network.

**Key Steps:**
- Always use WPA3 or WPA2 encryption (check router settings)
- Change default router admin credentials immediately
- Use a strong, unique WiFi password (16+ chars)
- Enable guest network for IoT devices
- Disable WPS — it has known vulnerabilities
- Regularly check connected devices list
- Keep router firmware updated

**What attackers look for:**
Open networks, WEP encryption (crackable in minutes), and default passwords are primary targets.

**Quick check:** Visit 192.168.1.1 or 192.168.0.1 in your browser. If your router admin password is still "admin" — fix it today.''',
                    category='WiFi Security', icon='📡', order_index=1
                ),
                ContentCard(
                    title='Common Phone Threats in 2025',
                    description='Your smartphone holds more personal data than your home. These are the real threats.',
                    full_content='''## Phone Security: Modern Threats Explained

Smartphones are the #1 target for attackers in 2025. Understanding threats is the first step to protection.

**Common Attack Vectors:**
- **Phishing SMS (Smishing):** Fake messages pretending to be banks, delivery services, or government agencies
- **Malicious Apps:** Side-loaded APKs that request excessive permissions
- **SIM Swapping:** Attackers convince your carrier to transfer your number to their SIM
- **Public WiFi MITM:** Your traffic intercepted on unsecured networks
- **Stalkerware:** Hidden apps monitoring location, calls, and messages

**How to stay protected:**
- Only install apps from official stores
- Review app permissions regularly
- Enable 2FA on all accounts (use authenticator apps, not SMS if possible)
- Use a VPN on public WiFi
- Lock your SIM card with a PIN via carrier settings''',
                    category='Mobile Security', icon='📱', order_index=2
                ),
                ContentCard(
                    title='Privacy Tips That Actually Work',
                    description='Not paranoia — just smart habits that protect your digital footprint.',
                    full_content='''## Real Privacy: Beyond Incognito Mode

Incognito mode doesn\'t make you private. It only hides your local browser history. Here\'s what actually helps.

**Browser Privacy:**
- Use Firefox with uBlock Origin extension
- Enable DNS-over-HTTPS (DoH) in browser settings
- Regularly clear cookies and storage
- Use different browsers for different purposes

**Account Security:**
- Use a password manager (Bitwarden is free and open source)
- Never reuse passwords
- Enable 2FA everywhere possible
- Use email aliases for signups (SimpleLogin)

**Data Minimization:**
- Review what Google/Facebook knows about you (myaccount.google.com)
- Regularly audit app permissions on your phone
- Be careful about what you share in "free" apps — you\'re the product

**Communication:**
- Signal for private messaging
- ProtonMail for sensitive emails''',
                    category='Privacy', icon='🛡️', order_index=3
                ),
                ContentCard(
                    title='How to Stay Safe Online',
                    description='A no-nonsense guide to everyday digital safety that anyone can follow.',
                    full_content='''## Staying Safe Online: The Fundamentals

You don\'t need to be a tech expert. These habits protect 95% of people from 95% of threats.

**Password Hygiene:**
- Minimum 12 characters, mix of letters, numbers, symbols
- Never use personal info (name, birthday, pet\'s name)
- Never reuse across sites
- Use a password manager

**Recognizing Phishing:**
- Check sender email carefully — fake domains look similar
- Hover over links before clicking
- Never enter credentials via email links — go directly to the website
- Banks never ask for passwords via email or call

**Software Updates:**
- Keep OS and apps updated — most attacks exploit known vulnerabilities
- Enable automatic updates where possible

**Backups:**
- 3-2-1 rule: 3 copies, 2 different media types, 1 offsite (cloud)
- Test your backups periodically

**Social Engineering Awareness:**
- Verify identity before sharing any info
- Be suspicious of urgency and fear tactics''',
                    category='General Safety', icon='🔐', order_index=4
                ),
            ]
            for card in sample_cards:
                db.session.add(card)

        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
