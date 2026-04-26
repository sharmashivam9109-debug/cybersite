from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os, uuid, datetime, json, mimetypes

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber-hub-ultra-secret-2025-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['FILES_FOLDER'] = os.path.join('static', 'files')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)

# All file types allowed
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
# No restriction on file types for sharing
BLOCKED_EXTENSIONS = {'exe', 'bat', 'cmd', 'sh', 'php', 'py', 'js', 'vbs'}  # block executables only

db = SQLAlchemy(app)

# ─── Models ───────────────────────────────────────────────────────────────────

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='owner')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class PublicUser(db.Model):
    """Public registered users — can post, share files."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_banned = db.Column(db.Boolean, default=False)
    # Per-user UI customizations (JSON stored as text)
    ui_customizations = db.Column(db.Text, default='{}')

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def get_ui(self):
        try:
            return json.loads(self.ui_customizations or '{}')
        except:
            return {}

    def set_ui(self, data):
        self.ui_customizations = json.dumps(data)

class ContentCard(db.Model):
    """Owner-created content cards (articles)."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    full_content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(60), default='General')
    thumbnail = db.Column(db.String(200), default='')
    icon = db.Column(db.String(10), default='🔒')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    order_index = db.Column(db.Integer, default=0)

class UserPost(db.Model):
    """Posts created by public users. Visible to everyone."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('public_user.id'), nullable=False)
    author = db.relationship('PublicUser', backref='posts')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # Attached file (optional)
    file_name = db.Column(db.String(300), default='')       # stored filename
    file_original = db.Column(db.String(300), default='')   # original filename
    file_size = db.Column(db.Integer, default=0)            # bytes
    file_type = db.Column(db.String(100), default='')       # mime type

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, default='')

class GuestCustomization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_username = db.Column(db.String(80), nullable=False)
    key = db.Column(db.String(100), nullable=False)
    value = db.Column(db.Text, default='')
    __table_args__ = (db.UniqueConstraint('guest_username', 'key'),)

class PageView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.date.today)
    ip_hash = db.Column(db.String(64), default='')
    card_id = db.Column(db.Integer, db.ForeignKey('content_card.id'), nullable=True)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def allowed_share_file(filename):
    if '.' not in filename:
        return True
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in BLOCKED_EXTENSIONS

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

def user_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_logged_in' not in session:
            flash('Please log in to do that.', 'error')
            return redirect(url_for('user_login'))
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

def format_file_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    else:
        return f"{size_bytes/(1024*1024):.1f} MB"

# ─── Public Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    cards = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    # Public posts — newest first
    posts = UserPost.query.order_by(UserPost.created_at.desc()).all()
    record_visit()

    role = session.get('admin_role', None)
    admin_username = session.get('admin_username', None)
    current_user_id = session.get('user_id', None)
    current_user = PublicUser.query.get(current_user_id) if current_user_id else None

    # Site settings
    site_settings = {
        'hero_title':    get_setting('hero_title',    'Cyber Hub'),
        'hero_subtitle': get_setting('hero_subtitle', 'Your digital safety, simplified.'),
        'hero_badge':    get_setting('hero_badge',    'SECURITY KNOWLEDGE BASE'),
        'about_title':   get_setting('about_title',   'About This Hub'),
        'about_text':    get_setting('about_text',    'A curated collection of cybersecurity knowledge for everyday people.'),
        'accent_color':  get_setting('accent_color',  '#00b4ff'),
        'bg_color':      get_setting('bg_color',      '#020408'),
    }

    # Admin guest overlays
    if role == 'guest' and admin_username:
        for k in site_settings:
            v = get_guest_custom(admin_username, k, '')
            if v:
                site_settings[k] = v

    # Public user UI customizations
    if current_user:
        ui = current_user.get_ui()
        for k in ['accent_color', 'bg_color']:
            if ui.get(k):
                site_settings[k] = ui[k]

    return render_template('index.html',
        cards=cards,
        posts=posts,
        site_settings=site_settings,
        current_user=current_user,
        format_file_size=format_file_size,
    )

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

# ─── Public User Auth ──────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def user_register():
    if 'user_logged_in' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('user_register'))
        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return redirect(url_for('user_register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('user_register'))
        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('user_register'))
        if PublicUser.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('user_register'))
        if PublicUser.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('user_register'))

        user = PublicUser(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_logged_in'] = True
        session['user_id'] = user.id
        session['user_username'] = user.username
        flash(f'Welcome, {username}!', 'success')
        return redirect(url_for('index'))

    return render_template('user_register.html')

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if 'user_logged_in' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = PublicUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_banned:
                flash('Your account has been banned.', 'error')
                return redirect(url_for('user_login'))
            session['user_logged_in'] = True
            session['user_id'] = user.id
            session['user_username'] = user.username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'error')
    return render_template('user_login.html')

@app.route('/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_id', None)
    session.pop('user_username', None)
    return redirect(url_for('index'))

# ─── User Posts ────────────────────────────────────────────────────────────────

@app.route('/post/new', methods=['POST'])
@user_login_required
def create_post():
    user_id = session['user_id']
    user = PublicUser.query.get_or_404(user_id)
    if user.is_banned:
        flash('Your account has been banned.', 'error')
        return redirect(url_for('index'))

    title = request.form.get('title', '').strip()
    body  = request.form.get('body', '').strip()

    if not title or not body:
        flash('Title and content are required.', 'error')
        return redirect(url_for('index'))

    post = UserPost(title=title, body=body, author_id=user_id)

    # File attachment
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename and allowed_share_file(file.filename):
            original_name = secure_filename(file.filename)
            ext = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else ''
            stored_name = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
            os.makedirs(app.config['FILES_FOLDER'], exist_ok=True)
            save_path = os.path.join(app.config['FILES_FOLDER'], stored_name)
            file.save(save_path)
            file_size = os.path.getsize(save_path)
            mime = mimetypes.guess_type(original_name)[0] or 'application/octet-stream'
            post.file_name     = stored_name
            post.file_original = original_name
            post.file_size     = file_size
            post.file_type     = mime
        elif file and file.filename:
            flash('That file type is not allowed.', 'error')
            return redirect(url_for('index'))

    db.session.add(post)
    db.session.commit()
    flash('Post published!', 'success')
    return redirect(url_for('index'))

@app.route('/post/delete/<int:post_id>', methods=['POST'])
@user_login_required
def delete_post(post_id):
    post = UserPost.query.get_or_404(post_id)
    user_id = session['user_id']

    # Only author can delete their own post
    if post.author_id != user_id:
        abort(403)

    # Delete attached file
    if post.file_name:
        try:
            os.remove(os.path.join(app.config['FILES_FOLDER'], post.file_name))
        except:
            pass

    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/files/<filename>')
def download_file(filename):
    """Serve shared files for download."""
    return send_from_directory(app.config['FILES_FOLDER'], filename, as_attachment=True)

# ─── User UI Customization ─────────────────────────────────────────────────────

@app.route('/user/customize', methods=['POST'])
@user_login_required
def user_customize():
    user = PublicUser.query.get(session['user_id'])
    ui = user.get_ui()
    for k in ['accent_color', 'bg_color']:
        v = request.form.get(k, '').strip()
        if v:
            ui[k] = v
    user.set_ui(ui)
    db.session.commit()
    flash('Your theme updated! Only you can see this.', 'success')
    return redirect(url_for('index'))

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
            session['admin_username']  = username
            session['admin_role']      = admin.role
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
    cards    = ContentCard.query.order_by(ContentCard.order_index, ContentCard.created_at.desc()).all()
    role     = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')

    # All user posts (owner sees all, can delete any)
    all_posts = UserPost.query.order_by(UserPost.created_at.desc()).all()

    # Public users list (owner only)
    public_users = PublicUser.query.order_by(PublicUser.created_at.desc()).all() if role == 'owner' else []

    analytics = None
    if role == 'owner':
        today = datetime.date.today()
        daily = []
        for i in range(6, -1, -1):
            day = today - datetime.timedelta(days=i)
            count = PageView.query.filter_by(date=day).filter(PageView.card_id == None).count()
            daily.append({'date': day.strftime('%d %b'), 'count': count})
        unique_today  = db.session.query(PageView.ip_hash).filter_by(date=today).distinct().count()
        total_visits  = PageView.query.count()
        total_users   = PublicUser.query.count()
        total_posts   = UserPost.query.count()
        top_cards     = db.session.query(
            ContentCard.title, ContentCard.icon,
            db.func.count(PageView.id).label('views')
        ).join(PageView, PageView.card_id == ContentCard.id)\
         .group_by(ContentCard.id)\
         .order_by(db.text('views DESC'))\
         .limit(5).all()
        analytics = {
            'daily':        daily,
            'unique_today': unique_today,
            'total_visits': total_visits,
            'total_users':  total_users,
            'total_posts':  total_posts,
            'top_cards':    top_cards,
        }

    if role == 'owner':
        settings = {
            'hero_title':    get_setting('hero_title',    'Cyber Hub'),
            'hero_subtitle': get_setting('hero_subtitle', 'Your digital safety, simplified.'),
            'hero_badge':    get_setting('hero_badge',    'SECURITY KNOWLEDGE BASE'),
            'about_title':   get_setting('about_title',   'About This Hub'),
            'about_text':    get_setting('about_text',    'A curated collection.'),
            'accent_color':  get_setting('accent_color',  '#00b4ff'),
            'bg_color':      get_setting('bg_color',      '#020408'),
        }
    else:
        settings = {
            'hero_title':    get_guest_custom(username, 'hero_title',    get_setting('hero_title',    'Cyber Hub')),
            'hero_subtitle': get_guest_custom(username, 'hero_subtitle', get_setting('hero_subtitle', 'Your digital safety, simplified.')),
            'hero_badge':    get_guest_custom(username, 'hero_badge',    get_setting('hero_badge',    'SECURITY KNOWLEDGE BASE')),
            'about_title':   get_guest_custom(username, 'about_title',   get_setting('about_title',   'About This Hub')),
            'about_text':    get_guest_custom(username, 'about_text',    get_setting('about_text',    'A curated collection.')),
            'accent_color':  get_guest_custom(username, 'accent_color',  get_setting('accent_color',  '#00b4ff')),
            'bg_color':      get_guest_custom(username, 'bg_color',      get_setting('bg_color',      '#020408')),
        }

    guests = Admin.query.filter_by(role='guest').all() if role == 'owner' else []

    return render_template('admin_dashboard.html',
        cards=cards, role=role, username=username,
        analytics=analytics, settings=settings,
        guests=guests, all_posts=all_posts,
        public_users=public_users,
        format_file_size=format_file_size,
    )

# ─── Owner: Delete any post ────────────────────────────────────────────────────

@app.route('/admin/post/delete/<int:post_id>', methods=['POST'])
@owner_required
def admin_delete_post(post_id):
    post = UserPost.query.get_or_404(post_id)
    if post.file_name:
        try:
            os.remove(os.path.join(app.config['FILES_FOLDER'], post.file_name))
        except:
            pass
    db.session.delete(post)
    db.session.commit()
    flash('Post removed.', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Owner: Ban/Unban user ─────────────────────────────────────────────────────

@app.route('/admin/user/ban/<int:user_id>', methods=['POST'])
@owner_required
def admin_ban_user(user_id):
    user = PublicUser.query.get_or_404(user_id)
    user.is_banned = not user.is_banned
    db.session.commit()
    status = 'banned' if user.is_banned else 'unbanned'
    flash(f'User {user.username} {status}.', 'success')
    return redirect(url_for('admin_dashboard'))

# ─── Settings + Password + Cards (unchanged) ───────────────────────────────────

@app.route('/admin/settings', methods=['POST'])
@login_required
def admin_save_settings():
    role     = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')
    keys     = ['hero_title', 'hero_subtitle', 'hero_badge', 'about_title', 'about_text', 'accent_color', 'bg_color']
    if role == 'owner':
        for k in keys:
            val = request.form.get(k, '').strip()
            if val:
                set_setting(k, val)
        flash('Site settings updated!', 'success')
    else:
        for k in keys:
            val = request.form.get(k, '').strip()
            if val:
                set_guest_custom(username, k, val)
        flash('Your personal customizations saved!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings/reset', methods=['POST'])
@login_required
def admin_reset_guest_settings():
    role     = session.get('admin_role', 'guest')
    username = session.get('admin_username', '')
    if role == 'guest':
        GuestCustomization.query.filter_by(guest_username=username).delete()
        db.session.commit()
        flash('Customizations reset.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/change-password', methods=['POST'])
@login_required
def admin_change_password():
    username = session.get('admin_username', '')
    current  = request.form.get('current_password', '')
    new_pw   = request.form.get('new_password', '')
    confirm  = request.form.get('confirm_password', '')
    admin    = Admin.query.filter_by(username=username).first()
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
    flash('Password changed!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/guests/add', methods=['POST'])
@owner_required
def admin_add_guest():
    username = request.form.get('guest_username', '').strip()
    password = request.form.get('guest_password', '')
    if not username or not password:
        flash('Username and password required.', 'error')
        return redirect(url_for('admin_dashboard'))
    if Admin.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('admin_dashboard'))
    guest = Admin(username=username, role='guest')
    guest.set_password(password)
    db.session.add(guest)
    db.session.commit()
    flash(f'Guest "{username}" created!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/guests/delete/<int:guest_id>', methods=['POST'])
@owner_required
def admin_delete_guest(guest_id):
    guest = Admin.query.get_or_404(guest_id)
    if guest.role == 'owner':
        flash('Cannot delete owner.', 'error')
        return redirect(url_for('admin_dashboard'))
    GuestCustomization.query.filter_by(guest_username=guest.username).delete()
    db.session.delete(guest)
    db.session.commit()
    flash(f'Guest "{guest.username}" removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add', methods=['GET', 'POST'])
@owner_required
def admin_add():
    if request.method == 'POST':
        title        = request.form.get('title', '').strip()
        description  = request.form.get('description', '').strip()
        full_content = request.form.get('full_content', '').strip()
        category     = request.form.get('category', 'General').strip()
        icon         = request.form.get('icon', '🔒').strip()
        order_index  = int(request.form.get('order_index', 0))
        thumbnail    = ''
        if 'thumbnail' in request.files:
            file = request.files['thumbnail']
            if file and file.filename and allowed_image(file.filename):
                ext      = file.filename.rsplit('.', 1)[1].lower()
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
        card.title        = request.form.get('title', '').strip()
        card.description  = request.form.get('description', '').strip()
        card.full_content = request.form.get('full_content', '').strip()
        card.category     = request.form.get('category', 'General').strip()
        card.icon         = request.form.get('icon', '🔒').strip()
        card.order_index  = int(request.form.get('order_index', 0))
        if 'thumbnail' in request.files:
            file = request.files['thumbnail']
            if file and file.filename and allowed_image(file.filename):
                ext      = file.filename.rsplit('.', 1)[1].lower()
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
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['FILES_FOLDER'], exist_ok=True)

        if not Admin.query.filter_by(role='owner').first():
            admin = Admin(username='shivam', role='owner')
            admin.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
            db.session.add(admin)

        defaults = {
            'hero_title':    'Cyber Hub',
            'hero_subtitle': 'Your digital safety, simplified.',
            'hero_badge':    'SECURITY KNOWLEDGE BASE',
            'about_title':   'About This Hub',
            'about_text':    'A curated collection of cybersecurity knowledge for everyday people.',
            'accent_color':  '#00b4ff',
            'bg_color':      '#020408',
        }
        for k, v in defaults.items():
            if not SiteSettings.query.filter_by(key=k).first():
                db.session.add(SiteSettings(key=k, value=v))

        if not ContentCard.query.first():
            sample_cards = [
                ContentCard(
                    title='WiFi Security Basics',
                    description='Most people leave their WiFi completely exposed.',
                    full_content='## WiFi Security\n\n**Key Steps:**\n- Use WPA3 or WPA2\n- Change default credentials\n- Strong password (16+ chars)',
                    category='WiFi Security', icon='📡', order_index=1
                ),
                ContentCard(
                    title='Common Phone Threats in 2025',
                    description='Your smartphone holds more personal data than your home.',
                    full_content='## Phone Security\n\n**Threats:**\n- Smishing\n- Malicious Apps\n- SIM Swapping',
                    category='Mobile Security', icon='📱', order_index=2
                ),
            ]
            for c in sample_cards:
                db.session.add(c)

        db.session.commit()

init_db()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
