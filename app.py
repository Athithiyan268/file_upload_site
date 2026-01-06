from flask import Flask, request, redirect, flash, render_template, send_file, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
from functools import wraps
from models import db, User, File
from models import ShareLink, AuditLog
from datetime import datetime, timedelta
import uuid

import config

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

import os, io, hashlib, subprocess

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.config.from_object(config)

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

limiter = Limiter(get_remote_address, app=app, default_limits=[])

cipher = Fernet(app.config['FILE_ENCRYPTION_KEY'])

# ---------------- DRIVE ----------------
SCOPES = ['https://www.googleapis.com/auth/drive']
credentials = service_account.Credentials.from_service_account_file(
    "service_account.json", scopes=SCOPES
)
drive = build('drive', 'v3', credentials=credentials)

# ---------------- HELPERS ----------------
def file_hash(file):
    h = hashlib.sha256()
    for chunk in file.stream:
        h.update(chunk)
    file.stream.seek(0)
    return h.hexdigest()

def encrypt_file(path):
    with open(path, 'rb') as f:
        data = f.read()
    with open(path, 'wb') as f:
        f.write(cipher.encrypt(data))

def decrypt_bytes(data):
    return cipher.decrypt(data)

def scan_file(path):
    try:
        result = subprocess.run(['clamscan', path], capture_output=True, text=True)
        return "OK" in result.stdout
    except:
        return True  # allow in dev

def used_storage(user_id):
    total = db.session.query(db.func.sum(File.size)) \
        .filter_by(owner_id=user_id, is_deleted=False).scalar()
    return total or 0

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.before_first_request
def create_tables():
    db.create_all()

# ---------------- AUTH ----------------
@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Invalid credentials")
            return redirect('/login')

        if user.is_locked:
            flash("Account locked")
            return redirect('/login')

        login_user(user)
        return redirect('/')

    return render_template('login.html')
@app.route('/logs')
@login_required
def user_logs():
    logs = AuditLog.query.filter_by(
        user_id=current_user.id
    ).order_by(AuditLog.created_at.desc()).all()

    return render_template('logs.html', logs=logs, admin=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']

        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect('/register')

        password = bcrypt.generate_password_hash(
            request.form['password']
        ).decode('utf-8')

        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully")
        return redirect('/login')

    return render_template('register.html')
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    logs = AuditLog.query.order_by(
        AuditLog.created_at.desc()
    ).all()

    return render_template('logs.html', logs=logs, admin=True)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            flash("Admin access only")
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

# ---------------- DASHBOARD ----------------
@app.route('/')
@login_required
def index():
    files = File.query.filter_by(owner_id=current_user.id, is_deleted=False).all()
    used = used_storage(current_user.id)
    quota = current_user.storage_quota
    return render_template('index.html', files=files, used=used, quota=quota)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()

    user_data = []
    for u in users:
        used = db.session.query(db.func.sum(File.size)) \
            .filter_by(owner_id=u.id, is_deleted=False).scalar() or 0

        user_data.append({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "locked": u.is_locked,
            "used": used,
            "quota": u.storage_quota
        })

    return render_template('admin.html', users=user_data)

# ---------------- UPLOAD ----------------
@limiter.limit("10 per minute")
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files.get('file')
    if not file:
        return redirect('/')

    if used_storage(current_user.id) + file.content_length > current_user.storage_quota:
        flash("Storage quota exceeded")
        return redirect('/')

    sha = file_hash(file)
    if File.query.filter_by(owner_id=current_user.id, hash=sha).first():
        flash("Duplicate file")
        return redirect('/')

    temp = f"temp_{file.filename}"
    file.save(temp)

    if not scan_file(temp):
        os.remove(temp)
        flash("Malware detected")
        return redirect('/')

    encrypt_file(temp)

    meta = {'name': file.filename}
    media = MediaFileUpload(temp, resumable=True)
    drive_file = drive.files().create(
        body=meta, media_body=media, fields='id'
    ).execute()

    db.session.add(File(
        name=file.filename,
        size=os.path.getsize(temp),
        hash=sha,
        drive_file_id=drive_file['id'],
        owner_id=current_user.id
    ))
    db.session.commit()
    os.remove(temp)

    flash("Uploaded")
    return redirect('/')
db.session.add(AuditLog(
    user_id=current_user.id,
    action="UPLOAD",
    file_id=new_file.id
))
db.session.commit()


# ---------------- DOWNLOAD ----------------
@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.filter_by(
        id=file_id, owner_id=current_user.id
    ).first_or_404()

    req = drive.files().get_media(fileId=file.drive_file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req)

    done = False
    while not done:
        _, done = downloader.next_chunk()

    decrypted = decrypt_bytes(fh.getvalue())
    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=file.name
    )
db.session.add(AuditLog(
    user_id=current_user.id,
    action="DOWNLOAD",
    file_id=file.id
))
db.session.commit()

# ---------------- TRASH ----------------

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete(file_id):
    file = File.query.filter_by(
        id=file_id,
        owner_id=current_user.id,
        is_deleted=False
    ).first_or_404()

    # Mark file as deleted
    file.is_deleted = True

    # Add to Trash table
    db.session.add(Trash(
        file_id=file.id,
        owner_id=current_user.id
    ))

    # 🔴 ADD TRASH AUDIT LOG HERE
    db.session.add(AuditLog(
        user_id=current_user.id,
        action="TRASH",
        file_id=file.id
    ))

    db.session.commit()
    flash("File moved to Trash")
    return redirect('/')

# ---------------- SHARE ----------------


@app.route('/share/<int:file_id>', methods=['GET','POST'])
@login_required
def share(file_id):
    file = File.query.filter_by(
        id=file_id,
        owner_id=current_user.id,
        is_deleted=False
    ).first_or_404()

    if request.method == 'POST':
        hours = int(request.form['hours'])
        password = request.form.get('password')

        token = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(hours=hours)

        hashed = bcrypt.generate_password_hash(password).decode('utf-8') if password else None

        link = ShareLink(
            token=token,
            file_id=file.id,
            password=hashed,
            expires_at=expiry
        )

        db.session.add(link)

        # ✅ SHARE AUDIT LOG
        db.session.add(AuditLog(
            user_id=current_user.id,
            action="SHARE",
            file_id=file.id
        ))

        db.session.commit()

        flash(f"Share link created: /shared/{token}")
        return redirect('/')

    return render_template('share.html')
@app.route('/shared/<token>', methods=['GET','POST'])
def shared_access(token):
    link = ShareLink.query.filter_by(token=token).first_or_404()

    if datetime.utcnow() > link.expires_at:
        return "Link expired", 403

    file = File.query.get_or_404(link.file_id)

    if link.password:
        if request.method == 'POST':
            if bcrypt.check_password_hash(link.password, request.form['password']):

                # ✅ ACCESS AUDIT LOG
                db.session.add(AuditLog(
                    user_id=file.owner_id,
                    action="SHARED_ACCESS",
                    file_id=file.id
                ))
                db.session.commit()

                return download(file.id)

            flash("Wrong password")
        return render_template('share_password.html')

    # no password
    db.session.add(AuditLog(
        user_id=file.owner_id,
        action="SHARED_ACCESS",
        file_id=file.id
    ))
    db.session.commit()

    return download(file.id)




# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)

