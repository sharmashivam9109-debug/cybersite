from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os, uuid, datetime, json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber-hub-ultra-secret-2025-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

SUPPORTED_LANGUAGES = ['en', 'hi', 'es', 'fr', 'de', 'zh', 'ar', 'pt', 'ru', 'ja']

db = SQLAlchemy(app)

# ─── Models ───────────────────────────────────────────────────────────────────

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='owner')  # 'owner' or 'guest'

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

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

class SiteSettings(db.Model):
    """Owner-controlled global site settings."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, default='')

class GuestCustomization(db.Model):
    """Per-guest frontend customizations. Only visible to that guest when logged in."""
    id = db.Column(db.Integer, primary_key=True)
    guest_username = db.Column(db.String(80), nullable=False)
    key = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Text, default='')
    # unique per guest+key
    __table_args__ = (db.UniqueConstraint('guest_username', 'key'),)

class PageView(db.Model):
    """Analytics: one row per visit."""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.date.today)
    ip_hash = db.Column(db.String(64), default='')  # hashed for privacy
    card_id = db.Column(db.Integer, db.ForeignKey('content_card.id'), nullable=True)

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

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        if session.get('admin_role') != 'owner':
            flash('Owner access only.', 'error')
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated

def get_setting(key, default=''):
    s = SiteSettings.query.filter_by(key=key).first()
    return s.value if s else default

def set_setting(key, value):
    s = SiteSettings.query.filter_by(key=key).first()
    if s:
        s.value = value
    else:
        db.session.add(SiteSettings(key=key, value=value))
    db.session.commit()

def get_guest_custom(username, key, default=''):
    g = GuestCustomization.query.filter_by(guest_username=username, key=key).first()
    return g.value if g else default

def set_guest_custom(username, key, value):
    g = GuestCustomization.query.filter_by(guest_username=username, key=key).first()
    if g:
        g.value = value
    else:
        db.session.add(GuestCustomization(guest_username=username, key=key, value=value))
    db.session.commit()

def record_visit(card_id=None):
    import hashlib
    ip = request.remote_addr or '0.0.0.0'
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:32]
    pv = PageView(date=datetime.date.today(), ip_hash=ip_hash, card_id=card_id)
    db.session.add(pv)
    db.session.commit()

def get_current_language():
    """Get current language from session, cookie, or default to 'en'."""
    lang = session.get('language') or request.cookies.get('language', 'en')
    if lang not in SUPPORTED_LANGUAGES:
        lang = 'en'
    return lang

# ─── Language Route ────────────────────────────────────────────────────────────

@app.route('/set-language', methods=['POST'])
def set_language():
    """Set language preference via POST. Saves to session + cookie."""
    lang = request.form.get('language', 'en')
    if lang not in SUPPORTED_LANGUAGES:
        lang = 'en'
    
    # Save in session
    session['language'] = lang
    
    # Redirect back to where user came from
    next_url = request.form.get('next') or request.referrer or url_for('index')
    
    # Also save in cookie (persists across sessions)
    response = make_response(redirect(next_url))
    response.set_cookie('language', lang, max_age=60*60*24*365, samesite='Lax', httponly=True)
    return response

@app.route('/get-language')
def get_language():
    """API endpoint to get current language."""
    return jsonify({'language': get_current_language()})

# ─── Public Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    record_visit()

    # Determine what settings to show
    # If logged in as guest → use guest customizations (overlay on top of owner settings)
    # If logged in as owner or not logged in → use owner settings
    role = session.get('admin_role', None)
    username = session.get('admin_username', None)

    # Owner base settings
    site_settings = {
        'hero_title': get_setting('hero_title', 'Cyber Hub'),
        'hero_subtitle': get_setting('hero_subtitle', 'Your digital safety, simplified.'),
        'hero_badge': get_setting('hero_badge', 'SECURITY KNOWLEDGE BASE'),
        'about_title': get_setting('about_title', 'About This Hub'),
        'about_text': get_setting('about_text', 'A curated collection of cybersecurity knowledge for everyday people.'),
        'accent_color': get_setting('accent_color', '#00b4ff'),
        'bg_color': get_setting('bg_color', '#020408'),
    }

    # If guest is logged in, overlay their personal customizations
    if role == 'guest' and username:
        guest_overrides = {
            'hero_title': get_guest_custom(username, 'hero_title', ''),
            'hero_subtitle': get_guest_custom(username, 'hero_subtitle', ''),
            'hero_badge': get_guest_custom(username, 'hero_badge', ''),
            'about_title': get_guest_custom(username, 'about_title', ''),
            'about_text': get_guest_custom(username, 'about_text', ''),
            'accent_color': get_guest_custom(username, 'accent_color', ''),
            'bg_color': get_guest_custom(username, 'bg_color', ''),
        }
        for k, v in guest_overrides.items():
            if v:  # only override if guest has set something
                site_settings[k] = v

    current_language = get_current_language()

    return render_template('index.html', cards=cards, site_settings=site_settings,
                           current_language=current_language)

@app.route('/api/card/<int:card_id>')
def get_card(card_id):
    card = ContentCard.query.get_or_404(card_id)
    record_visit(card_id=card.id)
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

# ─── Admin Auth ────────────────────────────────────────────────────────────────

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['admin_role'] = admin.role
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

# ─── Admin Dashboard ───────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
def admin_dashboard():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    role = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')

    # Analytics (owner only)
    analytics = None
    if role == 'owner':
        today = datetime.date.today()
        # Last 7 days daily visits
        daily = []
        for i in range(6, -1, -1):
            day = today - datetime.timedelta(days=i)
            count = PageView.query.filter_by(date=day).filter(PageView.card_id == None).count()
            daily.append({'date': day.strftime('%d %b'), 'count': count})
        # Unique visitors today (by ip_hash)
        unique_today = db.session.query(PageView.ip_hash).filter_by(date=today).distinct().count()
        # Total visits
        total_visits = PageView.query.count()
        # Top cards
        top_cards = db.session.query(
            ContentCard.title, ContentCard.icon,
            db.func.count(PageView.id).label('views')
        ).join(PageView, PageView.card_id == ContentCard.id)\
         .group_by(ContentCard.id)\
         .order_by(db.text('views DESC'))\
         .limit(5).all()
        analytics = {
            'daily': daily,
            'unique_today': unique_today,
            'total_visits': total_visits,
            'top_cards': top_cards,
        }

    # Site settings (owner sees global, guest sees their customizations)
    if role == 'owner':
        settings = {
            'hero_title': get_setting('hero_title', 'Cyber Hub'),
            'hero_subtitle': get_setting('hero_subtitle', 'Your digital safety, simplified.'),
            'hero_badge': get_setting('hero_badge', 'SECURITY KNOWLEDGE BASE'),
            'about_title': get_setting('about_title', 'About This Hub'),
            'about_text': get_setting('about_text', 'A curated collection of cybersecurity knowledge for everyday people.'),
            'accent_color': get_setting('accent_color', '#00b4ff'),
            'bg_color': get_setting('bg_color', '#020408'),
        }
    else:
        # Guest sees their own customizations (pre-filled with owner defaults)
        settings = {
            'hero_title': get_guest_custom(username, 'hero_title', get_setting('hero_title', 'Cyber Hub')),
            'hero_subtitle': get_guest_custom(username, 'hero_subtitle', get_setting('hero_subtitle', 'Your digital safety, simplified.')),
            'hero_badge': get_guest_custom(username, 'hero_badge', get_setting('hero_badge', 'SECURITY KNOWLEDGE BASE')),
            'about_title': get_guest_custom(username, 'about_title', get_setting('about_title', 'About This Hub')),
            'about_text': get_guest_custom(username, 'about_text', get_setting('about_text', 'A curated collection of cybersecurity knowledge for everyday people.')),
            'accent_color': get_guest_custom(username, 'accent_color', get_setting('accent_color', '#00b4ff')),
            'bg_color': get_guest_custom(username, 'bg_color', get_setting('bg_color', '#020408')),
        }

    # Guest list (owner only)
    guests = Admin.query.filter_by(role='guest').all() if role == 'owner' else []

    current_language = get_current_language()

    return render_template('admin_dashboard.html',
        cards=cards, role=role, username=username,
        analytics=analytics, settings=settings, guests=guests,
        current_language=current_language
    )

# ─── Site Settings ─────────────────────────────────────────────────────────────

@app.route('/admin/settings', methods=['POST'])
@login_required
def admin_save_settings():
    role = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')
    keys = ['hero_title', 'hero_subtitle', 'hero_badge', 'about_title', 'about_text', 'accent_color', 'bg_color']

    if role == 'owner':
        for k in keys:
            val = request.form.get(k, '').strip()
            if val:
                set_setting(k, val)
        flash('Site settings updated!', 'success')
    else:
        # Guest: save to their personal customizations
        for k in keys:
            val = request.form.get(k, '').strip()
            if val:
                set_guest_custom(username, k, val)
        flash('Your personal customizations saved! Only you can see these.', 'success')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings/reset', methods=['POST'])
@login_required
def admin_reset_guest_settings():
    """Guest can reset their customizations back to owner defaults."""
    role = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')
    if role == 'guest':
        GuestCustomization.query.filter_by(guest_username=username).delete()
        db.session.commit()
        flash('Your customizations reset to default.', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Password Change ────────────────────────────────────────────────────────────

@app.route('/admin/change-password', methods=['POST'])
@login_required
def admin_change_password():
    username = session.get('admin_username', '')
    current = request.form.get('current_password', '')
    new_pw = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    admin = Admin.query.filter_by(username=username).first()
    if not admin or not admin.check_password(current):
        flash('Current password is wrong.', 'error')
        return redirect(url_for('admin_dashboard'))
    if len(new_pw) < 8:
        flash('New password must be at least 8 characters.', 'error')
        return redirect(url_for('admin_dashboard'))
    if new_pw != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('admin_dashboard'))

    admin.set_password(new_pw)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Guest Management (Owner Only) ─────────────────────────────────────────────

@app.route('/admin/guests/add', methods=['POST'])
@owner_required
def admin_add_guest():
    username = request.form.get('guest_username', '').strip()
    password = request.form.get('guest_password', '')

    if not username or not password:
        flash('Username and password required.', 'error')
        return redirect(url_for('admin_dashboard'))
    if len(password) < 6:
        flash('Guest password must be at least 6 characters.', 'error')
        return redirect(url_for('admin_dashboard'))
    if Admin.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('admin_dashboard'))

    guest = Admin(username=username, role='guest')
    guest.set_password(password)
    db.session.add(guest)
    db.session.commit()
    flash(f'Guest "{username}" created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/guests/delete/<int:guest_id>', methods=['POST'])
@owner_required
def admin_delete_guest(guest_id):
    guest = Admin.query.get_or_404(guest_id)
    if guest.role == 'owner':
        flash('Cannot delete owner.', 'error')
        return redirect(url_for('admin_dashboard'))
    # Also delete their customizations
    GuestCustomization.query.filter_by(guest_username=guest.username).delete()
    db.session.delete(guest)
    db.session.commit()
    flash(f'Guest "{guest.username}" removed.', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Card Management (Owner Only) ──────────────────────────────────────────────

@app.route('/admin/add', methods=['GET', 'POST'])
@owner_required
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
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                thumbnail = f"uploads/{filename}"

        card = ContentCard(
            title=title, description=description, full_content=full_content,
            category=category, thumbnail=thumbnail, icon=icon, order_index=order_index
        )
        db.session.add(card)
        db.session.commit()
        flash('Card added!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_add.html')

@app.route('/admin/edit/<int:card_id>', methods=['GET', 'POST'])
@owner_required
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
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                card.thumbnail = f"uploads/{filename}"

        db.session.commit()
        flash('Card updated!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit.html', card=card)

@app.route('/admin/delete/<int:card_id>', methods=['POST'])
@owner_required
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

        # Create owner admin
        if not Admin.query.filter_by(role='owner').first():
            admin = Admin(username='shivam', role='owner')
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)

        # Default site settings
        defaults = {
            'hero_title': 'Cyber Hub',
            'hero_subtitle': 'Your digital safety, simplified.',
            'hero_badge': 'SECURITY KNOWLEDGE BASE',
            'about_title': 'About This Hub',
            'about_text': 'A curated collection of cybersecurity knowledge for everyday people.',
            'accent_color': '#00b4ff',
            'bg_color': '#020408',
        }
        for k, v in defaults.items():
            if not SiteSettings.query.filter_by(key=k).first():
                db.session.add(SiteSettings(key=k, value=v))

        # Sample cards
        if not ContentCard.query.first():
            sample_cards = [
                ContentCard(
                    title='WiFi Security Basics',
                    description='Most people leave their WiFi completely exposed. Here\'s what you should actually know.',
                    full_content='''## WiFi Security: What You\'re Missing\n\nYour home WiFi is the front door to your digital life.\n\n**Key Steps:**\n- Always use WPA3 or WPA2 encryption\n- Change default router admin credentials\n- Use a strong, unique WiFi password (16+ chars)\n- Enable guest network for IoT devices\n- Disable WPS\n- Keep router firmware updated''',
                    category='WiFi Security', icon='📡', order_index=1
                ),
                ContentCard(
                    title='Common Phone Threats in 2025',
                    description='Your smartphone holds more personal data than your home.',
                    full_content='''## Phone Security: Modern Threats\n\n**Common Attack Vectors:**\n- Phishing SMS (Smishing)\n- Malicious Apps\n- SIM Swapping\n- Public WiFi MITM\n- Stalkerware''',
                    category='Mobile Security', icon='📱', order_index=2
                ),
                ContentCard(
                    title='Privacy Tips That Actually Work',
                    description='Not paranoia — just smart habits that protect your digital footprint.',
                    full_content='''## Real Privacy\n\n**Browser Privacy:**\n- Use Firefox with uBlock Origin\n- Enable DNS-over-HTTPS\n\n**Account Security:**\n- Use a password manager\n- Enable 2FA everywhere''',
                    category='Privacy', icon='🛡️', order_index=3
                ),
            ]
            for c in sample_cards:
                db.session.add(c)

        db.session.commit()

init_db()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
