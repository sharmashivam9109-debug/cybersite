# 🌐 Cyber Awareness Hub — Setup Guide
**By Shivam Sharma** | Flask + SQLite | Futuristic Dark Theme

---

## 📁 Folder Structure

```
cybersite/
├── app.py                   ← Flask backend (main file)
├── requirements.txt         ← Python dependencies
├── README.md
├── instance/
│   └── cybersite.db         ← SQLite DB (auto-created on first run)
├── static/
│   ├── uploads/             ← Uploaded thumbnails stored here
│   ├── css/                 ← (optional custom CSS files)
│   ├── js/                  ← (optional custom JS files)
│   └── img/
└── templates/
    ├── index.html           ← Public homepage
    ├── admin_login.html     ← /admin/login
    ├── admin_dashboard.html ← /admin (manage cards)
    ├── admin_add.html       ← /admin/add
    └── admin_edit.html      ← /admin/edit/<id>
```

---

## ⚡ Termux Setup (Phone)

```bash
# 1. Install Python & pip
pkg install python

# 2. Navigate to project folder
cd cybersite

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Then open in browser: `http://localhost:5000`

---

## 🔑 Admin Access

- URL: `http://localhost:5000/admin/login`
- Default Username: `shivam`
- Default Password: `admin123`

⚠️ **IMPORTANT: Change the password before deploying!**

To change password, edit `app.py` line in `init_db()`:
```python
admin.set_password('YOUR_NEW_STRONG_PASSWORD')
```

Or better, add an admin password change route (can help with that separately).

---

## 🚀 Deploying on Railway / Render

### Railway:
```bash
# In your Railway project, set environment variable:
SECRET_KEY = your-random-secret-string-here

# Procfile (create this file):
web: gunicorn app:app
```

### Render:
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`
- Environment: `SECRET_KEY=your-secret`

---

## 🛡️ Security Checklist Before Going Live

- [ ] Change admin password from default `admin123`
- [ ] Set a strong `SECRET_KEY` environment variable (don't hardcode)
- [ ] Consider rate-limiting the /admin/login route
- [ ] Use HTTPS (Railway/Render provide this automatically)
- [ ] Regularly backup the SQLite DB file

---

## 📱 Features Summary

| Feature | Status |
|---|---|
| Futuristic dark UI | ✅ |
| GSAP hero animations | ✅ |
| Particle canvas background | ✅ |
| Glassmorphism cards | ✅ |
| Modal content viewer | ✅ |
| Scroll reveal animations | ✅ |
| Custom cursor | ✅ |
| Instagram button (real logo) | ✅ |
| Admin login system | ✅ |
| Add / Edit / Delete cards | ✅ |
| Image thumbnail upload | ✅ |
| SQLite database | ✅ |
| Mobile responsive | ✅ |

---

## 🎨 Customization

**Colors** — Edit CSS variables in `index.html`:
```css
--neon-blue: #00b4ff;
--neon-purple: #9b59ff;
--neon-cyan: #00f5ff;
```

**Hero Text** — Search for "Shivam Sharma" and "Cyber Awareness & Tech Explorer" in `index.html`

**Instagram** — Already set to `shivam_sharma.01`. To change, search `shivam_sharma.01` in `index.html`.

---

For questions or help: Build on. 🚀
