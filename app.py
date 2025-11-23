# app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, uuid, random, string
from flask_migrate import Migrate
from flask_mail import Mail, Message
import requests # Import pustaka requests
from dotenv import load_dotenv # Import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import logging
import re # Import modul regular expression
from itsdangerous import URLSafeTimedSerializer
import pyotp
import qrcode
import base64
from io import BytesIO
from mailjet_rest import Client as MailjetClient

app = Flask(__name__)

# KRUSIAL: Terapkan ProxyFix untuk mendapatkan IP asli pengguna di belakang reverse proxy (seperti di Railway)
# x_for=1 berarti kita percaya pada 1 lapis proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- Konfigurasi Logging ---
logging.basicConfig(
    filename='e-perpus.log', # Nama file log
    level=logging.INFO,      # Level log (INFO, WARNING, ERROR, DEBUG)
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Konfigurasi Database ---
load_dotenv() # Muat variabel lingkungan dari file .env

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24) # Gunakan dari .env, fallback ke os.urandom
# --- Validasi dan set DATABASE_URL ---
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    # Ini akan menghentikan aplikasi dengan pesan yang jelas jika variabel tidak ada di Railway
    raise RuntimeError("FATAL ERROR: Variabel lingkungan 'DATABASE_URL' tidak ditemukan atau kosong. Pastikan sudah diatur di dashboard Railway.")
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# --- Konfigurasi Keamanan Cookie Sesi ---
app.config['SESSION_COOKIE_SECURE'] = True  # Hanya kirim cookie melalui HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Mencegah akses cookie dari JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mencegah cookie dikirim pada request cross-site

# Konfigurasi File Upload
# Jadikan path absolut untuk keandalan yang lebih baik
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# KRITIS: Pindahkan folder upload ke luar direktori 'static' untuk mencegah eksekusi file.
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'private_uploads', 'books')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Ekstensi file yang diizinkan untuk buku
ALLOWED_EXTENSIONS = {'pdf', 'epub', 'doc', 'docx', 'txt'}

# Pastikan folder upload ada
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# --- Konfigurasi Flask-Mail untuk Gmail ---
# PENTING: Gunakan "App Password" dari akun Google Anda, bukan password utama.
# Kunjungi: https://myaccount.google.com/apppasswords
# --- Konfigurasi Flask-Mail untuk Mailjet ---
app.config['MAIL_SERVER'] = 'in-v3.mailjet.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAILJET_API_KEY')
app.config['MAIL_PASSWORD'] = os.environ.get('MAILJET_SECRET_KEY')
# Pastikan email ini sudah diverifikasi sebagai "Sender" di akun Mailjet Anda.
app.config['MAIL_DEFAULT_SENDER'] = (
    'E-Perpus SMAN 1 Tinombo',
    os.environ.get('MAIL_SENDER_EMAIL') # Ambil dari variabel lingkungan
)

# --- Konfigurasi Google reCAPTCHA ---
# Ambil dari .env
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')

# Serializer untuk token reset password
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Konfigurasi Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"], # Batasan default untuk semua rute
    storage_uri="memory://", # Penyimpanan state limiter
)

db = SQLAlchemy(app)

# ... setelah db = SQLAlchemy(app) ...

@app.context_processor
def inject_user():
    """
    Menyuntikkan variabel 'current_user' ke dalam semua template.
    Ini membuat data pengguna yang sedang login tersedia secara global di Jinja2.
    """
    if 'user_id' in session:
        # Mengambil data pengguna dari database berdasarkan ID di sesi
        user = User.query.get(session['user_id'])
        return dict(current_user=user)
    # Jika tidak ada user_id di sesi, kembalikan None
    return dict(current_user=None)

# --- Rute Aplikasi ---
# ... (lanjutkan dengan @app.route('/') dst.) ...


migrate = Migrate(app, db)
mail = Mail(app) # Inisialisasi Mail
csrf = CSRFProtect(app) # Inisialisasi CSRF Protection

# --- Model Database ---
class Buku(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(200), nullable=False)
    penulis = db.Column(db.String(100), nullable=False)
    tahun_terbit = db.Column(db.Integer, nullable=False)
    deskripsi = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=False) # Path ke file buku (PDF, etc.)

    def __repr__(self):
        return f'<Buku {self.judul}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Simpan password yang sudah di-hash!
    role = db.Column(db.String(20), nullable=False, default='pengguna') # 'administrator' atau 'pengguna'
    # Kolom baru untuk verifikasi
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_code_expires = db.Column(db.DateTime, nullable=True)
    otp_secret = db.Column(db.String(32), nullable=True, unique=True)
    login_otp = db.Column(db.String(6), nullable=True)
    login_otp_expires = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

# Jalankan `db.create_all()` sekali dari terminal Python untuk membuat tabel
# from app import app, db
# with app.app_context():
#     db.create_all()

# --- (Rute aplikasi akan ditambahkan di sini) ---
# --- Helper Functions ---

def sanitize_string(text, max_length=100):
    """Membersihkan string dari karakter yang tidak diinginkan."""
    text = text.strip() # Hapus spasi di awal dan akhir
    text = re.sub(r"[<>\"';=(){}`]", "", text) # Hapus karakter berbahaya
    text = text[:max_length] # Batasi panjang string
    return text

def allowed_file(filename):
    """Memeriksa apakah ekstensi file diizinkan."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_verification_code():
    """Menghasilkan kode verifikasi 6 digit acak."""
    return "".join(random.choices(string.digits, k=6))

def send_verification_email(user):
    """Mengirim email verifikasi ke pengguna."""
        # --- GANTI DARI FLASK-MAIL KE MAILJET API ---
    try:
        api_key = os.environ.get('MAILJET_API_KEY')
        api_secret = os.environ.get('MAILJET_SECRET_KEY')
        sender_email = os.environ.get('MAIL_SENDER_EMAIL')

        if not all([api_key, api_secret, sender_email]):
            logging.error("Variabel lingkungan Mailjet tidak lengkap.")
            return False

        mailjet = MailjetClient(auth=(api_key, api_secret), version='v3.1')
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": sender_email,
                        "Name": "E-Perpus SMAN 1 Tinombo"
                    },
                    "To": [{"Email": user.email, "Name": user.username}],
                    "Subject": "Kode Verifikasi Akun E-Perpus",
                    "TextPart": f"Halo {user.username},\n\nGunakan kode berikut untuk memverifikasi akun Anda:\n\n{user.verification_code}\n\nKode ini akan kedaluwarsa dalam 10 menit."
                }
            ]
        }
        result = mailjet.send.create(data=data)
        if result.status_code != 200:
            logging.error(f"Mailjet API Error: {result.status_code} - {result.json()}")
            return False
        return True
    except Exception as e:
        logging.error(f"Gagal mengirim email verifikasi ke {user.email} via Mailjet API: {e}") # Untuk debugging
        return False
    
def send_password_reset_email(user):
    """Mengirim email reset password ke pengguna."""
    # Buat token yang berlaku selama 30 menit (1800 detik)
    token = s.dumps(user.email, salt='password-reset-salt')
    reset_url = url_for('reset_with_token', token=token, _external=True)
        # --- UPDATE: Menggunakan Mailjet API, bukan Flask-Mail ---
    try:
        api_key = os.environ.get('MAILJET_API_KEY')
        api_secret = os.environ.get('MAILJET_SECRET_KEY')
        sender_email = os.environ.get('MAIL_SENDER_EMAIL')

        mailjet = MailjetClient(auth=(api_key, api_secret), version='v3.1')
        data = {
            'Messages': [{
                "From": {"Email": sender_email, "Name": "E-Perpus SMAN 1 Tinombo"},
                "To": [{"Email": user.email, "Name": user.username}],
                "Subject": "Reset Password Akun E-Perpus",
                "TextPart": f"Halo {user.username},\n\nUntuk mereset password Anda, silakan kunjungi link berikut:\n{reset_url}\n\nJika Anda tidak meminta reset password, abaikan email ini. Link ini akan kedaluwarsa dalam 30 menit."
            }]
        }
        result = mailjet.send.create(data=data)
        if result.status_code != 200:
            logging.error(f"Mailjet API Error (Password Reset): {result.status_code} - {result.json()}")
            return False
        return True
    except Exception as e:
        logging.error(f"Gagal mengirim email reset password ke {user.email} via Mailjet API: {e}")
        return False

def send_login_otp_email(user):
    """Mengirim kode OTP untuk verifikasi login."""
    try:
        api_key = os.environ.get('MAILJET_API_KEY')
        api_secret = os.environ.get('MAILJET_SECRET_KEY')
        sender_email = os.environ.get('MAIL_SENDER_EMAIL')

        mailjet = MailjetClient(auth=(api_key, api_secret), version='v3.1')
        data = {
            'Messages': [{
                "From": {"Email": sender_email, "Name": "E-Perpus SMAN 1 Tinombo"},
                "To": [{"Email": user.email, "Name": user.username}],
                "Subject": "Kode Verifikasi Login Anda",
                "TextPart": f"Halo {user.username},\n\nSeseorang mencoba login ke akun Anda. Gunakan kode berikut untuk menyelesaikan proses login:\n\n{user.login_otp}\n\nKode ini hanya berlaku selama 5 menit. Jika ini bukan Anda, Anda dapat mengabaikan email ini."
            }]
        }
        result = mailjet.send.create(data=data)
        if result.status_code != 200:
            logging.error(f"Mailjet API Error (Login OTP): {result.status_code} - {result.json()}")
            return False
        return True
    except Exception as e:
        logging.error(f"Gagal mengirim email login OTP ke {user.email} via Mailjet API: {e}")
        return False

# app.py (lanjutan...)

# --- Rute Aplikasi ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning(f"Akses tidak sah atau sesi berakhir ke endpoint '{request.endpoint}' dari IP {request.remote_addr}. Diperlukan login.")
            flash('Sesi Anda telah berakhir atau Anda belum login. Silakan login kembali.', 'warning')
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user:
            # User tidak ditemukan di DB — bersihkan session dan arahkan ke login
            logging.warning(f"Sesi mengandung user_id yang tidak ditemukan: {session.get('user_id')}. Menghapus sesi.")
            session.clear()
            flash('Sesi Anda tidak valid. Silakan login kembali.', 'warning')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Akun Anda belum diverifikasi. Silakan cek email Anda.', 'warning')
            return redirect(url_for('verify'))
        return f(*args, **kwargs)
    return decorated_function


# Rute Halaman Utama (Untuk Pengguna)
@app.route('/')
@login_required
def index():
    # Ambil semua buku dari database dan urutkan berdasarkan judul
    books = Buku.query.order_by(Buku.judul).all()
    return render_template('index.html', books=books)

# Rute untuk melihat detail buku
@app.route('/buku/<int:buku_id>')
@login_required
def detail_buku(buku_id):
    buku = Buku.query.get_or_404(buku_id)
    logging.info(f"User '{session.get('user_id')}' melihat detail buku: '{buku.judul}' (ID: {buku.id})")
    return render_template('detail_buku.html', buku=buku)


# Rute untuk mengunduh buku
@app.route('/download/<int:buku_id>')
@limiter.limit("10 per minute") # Tambahkan rate limit untuk mencegah penyalahgunaan bandwidth
@login_required
def download_buku(buku_id):
    buku = Buku.query.get_or_404(buku_id)
    logging.info(f"User '{session.get('user_id')}' mengunduh buku: '{buku.judul}' (File: {buku.file_path})")
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], buku.file_path, as_attachment=True)
    except FileNotFoundError:
        logging.error(f"File tidak ditemukan saat user '{session.get('user_id')}' mencoba mengunduh buku ID: {buku_id} (Path: {buku.file_path})")
        flash('Maaf, file untuk buku ini tidak dapat ditemukan.', 'danger')
        return redirect(url_for('index'))


# Rute Login
@app.route('/login', methods=['GET', 'POST'])
# Batasan spesifik untuk login, KECUALI jika sedang mengirimkan respons captcha
@limiter.limit("5 per minute", exempt_when=lambda: 'g-recaptcha-response' in request.form)
def login():

    if request.method == 'POST':
        # Jika captcha seharusnya ditampilkan (karena banyak percobaan gagal), maka wajib diverifikasi
        if 'g-recaptcha-response' in request.form:
            captcha_response = request.form.get('g-recaptcha-response')
            if not captcha_response:
                flash('Mohon selesaikan verifikasi "Saya bukan robot".', 'danger')
                return render_template('login.html', show_captcha=True, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])

            # Verifikasi respons captcha ke Google
            secret_key = app.config['RECAPTCHA_SECRET_KEY']
            verification_url = f'https://www.google.com/recaptcha/api/siteverify?secret={secret_key}&response={captcha_response}'
            response = requests.post(verification_url)
            result = response.json()

            if not result.get('success'):
                flash('Verifikasi reCAPTCHA gagal. Silakan coba lagi.', 'danger')
                return render_template('login.html', show_captcha=True, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])
            

        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        
        if user and check_password_hash(user.password, password):
            logging.info(f"Login berhasil untuk user '{username}' dari IP: {request.remote_addr}")
            session.pop('login_attempts', None) # Hapus penghitung jika ada
            
            # --- ALUR VERIFIKASI LANJUTAN ---

            # 1. Jika akun belum diverifikasi sama sekali (paska registrasi),
            #    arahkan ke alur verifikasi akun awal.
            if not user.is_verified:
                # Pastikan kode ada dan belum kedaluwarsa, atau buat yang baru
                if not user.verification_code or datetime.utcnow() > user.verification_code_expires:
                    user.verification_code = generate_verification_code()
                    user.verification_code_expires = datetime.utcnow() + timedelta(minutes=10)
                    db.session.commit()
                    send_verification_email(user) # Kirim email
                
                session['user_id'] = user.id # Simpan ID untuk halaman verifikasi
                flash('Akun Anda belum diverifikasi. Kami telah mengirimkan kode ke email Anda.', 'info')
                return redirect(url_for('verify'))

            # 2. Jika user adalah admin dan 2FA (Aplikasi Authenticator) aktif, arahkan ke sana.
            if user.role == 'administrator' and user.otp_secret:
                session['2fa_user_id'] = user.id  # Simpan ID user untuk diverifikasi
                logging.info(f"Admin '{username}' diarahkan ke verifikasi 2FA.")
                return redirect(url_for('verify_2fa'))
            # 3. Untuk SEMUA PENGGUNA LAINNYA (pengguna biasa atau admin tanpa 2FA),
            #    wajibkan verifikasi login via email SETIAP SAAT.
            user.login_otp = generate_verification_code()
            user.login_otp_expires = datetime.utcnow() + timedelta(minutes=5) # OTP berlaku 5 menit
            db.session.commit()
            send_login_otp_email(user)
            session['login_verify_user_id'] = user.id # Simpan ID user sementara
            flash('Password benar. Kami telah mengirimkan kode verifikasi ke email Anda untuk menyelesaikan login.', 'info')
            return redirect(url_for('verify_login'))
        else:
            logging.warning(f"Login gagal untuk username: '{username}' dari IP: {request.remote_addr}")
            flash('Username atau password salah.', 'danger')
            
    # Secara default, captcha tidak ditampilkan.
    return render_template('login.html', show_captcha=False, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'])



@app.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['2fa_user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(code):
            # Kode benar, selesaikan proses login
            session.pop('2fa_user_id', None)
            session['user_id'] = user.id
            session['role'] = user.role
            session['2fa_passed'] = True # Tandai bahwa 2FA sudah dilewati
            session.permanent = True
            logging.info(f"Admin '{user.username}' berhasil melewati 2FA.")
            flash('Login berhasil!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            logging.warning(f"Admin '{user.username}' gagal 2FA (kode salah).")
            flash('Kode verifikasi salah.', 'danger')

    return render_template('verify_2fa.html')

@app.route('/verify-login', methods=['GET', 'POST'])
@limiter.limit("10 per 5 minutes")
def verify_login():
    if 'login_verify_user_id' not in session:
        flash('Silakan mulai proses login dari awal.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['login_verify_user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code')

        # Cek apakah kode benar dan belum kedaluwarsa
        if user.login_otp and code == user.login_otp and datetime.utcnow() < user.login_otp_expires:
            # Kode benar, selesaikan proses login
            user.login_otp = None
            user.login_otp_expires = None
            db.session.commit()

            session.pop('login_verify_user_id', None) # Hapus session sementara
            session['user_id'] = user.id
            session['role'] = user.role
            session.permanent = True
            
            logging.info(f"User '{user.username}' berhasil login setelah verifikasi OTP email.")
            flash('Login berhasil!', 'success')

            if user.role == 'administrator':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            logging.warning(f"User '{user.username}' gagal verifikasi login OTP (kode salah atau kedaluwarsa).")
            flash('Kode verifikasi salah atau sudah kedaluwarsa.', 'danger')

    return render_template('verify_login.html')

# Error handler kustom untuk Rate Limit (429)
@app.errorhandler(429)
def ratelimit_handler(e):
    # Cek apakah error terjadi di halaman login
    logging.warning(f"Rate limit terpicu untuk IP: {request.remote_addr} pada endpoint: {request.endpoint}")
    if request.endpoint == 'login':
        flash('Maaf, Anda mencoba login lebih dari 5 kali dalam 1 menit. Silakan verifikasi bahwa Anda bukan robot.', 'warning')
        # Langsung render template login dengan captcha, dan kembalikan status 429
        return render_template('login.html', 
                               show_captcha=True, 
                               recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY']), 429
            # Tambahkan penanganan untuk halaman verifikasi 2FA
    elif request.endpoint == 'verify_2fa':
        flash('Anda telah mencoba terlalu banyak. Silakan tunggu sebentar sebelum mencoba lagi.', 'danger')
        # LANGSUNG RENDER template, jangan redirect untuk menghindari loop.
        return render_template('verify_2fa.html'), 429
    # Untuk halaman lain, kembalikan response default dari error
    return e.get_response()




@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour") # Batasan spesifik untuk register
def register():
    if request.method == 'POST':
        logging.info(f"Upaya registrasi baru dari IP: {request.remote_addr} dengan email: {request.form.get('email')}")

        username = sanitize_string(request.form['username'], max_length=80)
        email = sanitize_string(request.form['email'], max_length=120)
        password = request.form['password']
        
                # --- Validasi Kompleksitas Password ---
        if len(password) < 8:
            flash('Password harus memiliki minimal 8 karakter.', 'danger')
            return redirect(url_for('register'))
        if not re.search(r"[a-z]", password):
            flash('Password harus mengandung setidaknya satu huruf kecil.', 'danger')
            return redirect(url_for('register'))
        if not re.search(r"[A-Z]", password):
            flash('Password harus mengandung setidaknya satu huruf besar.', 'danger')
            return redirect(url_for('register'))
        if not re.search(r"[0-9]", password):
            flash('Password harus mengandung setidaknya satu angka.', 'danger')
            return redirect(url_for('register'))
        # --- Akhir Validasi ---
        
        # Cek apakah email sudah ada
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email sudah terdaftar. Silakan gunakan email lain atau login.', 'danger')
            return redirect(url_for('register'))

        # Cek apakah username sudah ada
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username sudah digunakan. Silakan pilih yang lain.', 'danger')
            return redirect(url_for('register'))

        # Hash password untuk keamanan
        hashed_password = generate_password_hash(password)

        # Tentukan role: user pertama yang mendaftar akan menjadi administrator
        role = 'administrator' if User.query.count() == 0 else 'pengguna'

        # Buat user baru dan simpan ke database
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        logging.info(f"User baru '{username}' (Role: {role}) berhasil dibuat.")
        flash(f'Akun berhasil dibuat! Anda terdaftar sebagai {role}. Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    session.clear()
    logging.info(f"User dengan ID '{user_id}' telah logout.")
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

# --- Rute Lupa Password ---

@app.route('/reset_password', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            if send_password_reset_email(user):
                logging.info(f"Link reset password dikirim ke email: {email} dari IP: {request.remote_addr}")
                flash('Instruksi untuk mereset password telah dikirim ke email Anda.', 'success')
            else:
                flash('Gagal mengirim email. Silakan coba lagi nanti.', 'danger')
            return redirect(url_for('login'))
        else:
            logging.warning(f"Upaya reset password untuk email tidak terdaftar: {email} dari IP: {request.remote_addr}")
            flash('Email tidak terdaftar. Silakan buat akun terlebih dahulu.', 'danger')
            return redirect(url_for('register'))
    return render_template('request_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        # Token berlaku selama 30 menit (1800 detik)
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except Exception:
        flash('Link reset password tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('request_password_reset'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok.', 'danger')
            return render_template('reset_with_token.html', token=token)

        # Validasi Kompleksitas Password (sama seperti di register)
        if len(password) < 8 or not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
            flash('Password tidak memenuhi syarat keamanan (minimal 8 karakter, mengandung huruf besar, kecil, dan angka).', 'danger')
            return render_template('reset_with_token.html', token=token)
        
        user.password = generate_password_hash(password)
        db.session.commit()
        logging.info(f"Password untuk user '{user.username}' (ID: {user.id}) berhasil direset melalui token.")
        flash('Password Anda telah berhasil direset! Silakan login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_with_token.html', token=token)


# --- Rute Verifikasi ---

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Sesi tidak valid. Silakan login kembali.', 'warning')
        return redirect(url_for('login'))

    if user.is_verified:
        return redirect(url_for('index'))

    if request.method == 'POST':
        code = request.form['code']
        
        if user.verification_code and code == user.verification_code and datetime.utcnow() < user.verification_code_expires:
            user.is_verified = True
            user.verification_code = None
            user.verification_code_expires = None
            db.session.commit()
            logging.info(f"User '{user.username}' (ID: {user.id}) berhasil verifikasi akun.")
            flash('Akun Anda berhasil diverifikasi!', 'success')
            
            if user.role == 'administrator':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            logging.warning(f"User '{user.username}' (ID: {user.id}) gagal verifikasi. Kode salah atau kedaluwarsa.")
            flash('Kode verifikasi salah atau sudah kedaluwarsa.', 'danger')

    return render_template('verify.html')

@app.route('/resend_code')
def resend_code():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Sesi tidak valid. Silakan login kembali.', 'warning')
        return redirect(url_for('login'))

    if user.is_verified:
        return redirect(url_for('index'))

    user.verification_code = generate_verification_code()
    user.verification_code_expires = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    
    if send_verification_email(user):
        logging.info(f"Kode verifikasi baru dikirim ulang untuk user '{user.username}' (ID: {user.id}).")
        flash('Kode verifikasi baru telah dikirim ke email Anda.', 'success')
    else:
        logging.error(f"Gagal mengirim ulang email verifikasi untuk user '{user.username}' (ID: {user.id}).")
        flash('Gagal mengirim email verifikasi. Coba lagi nanti.', 'danger')

    return redirect(url_for('verify'))

# --- Rute Khusus Admin ---

# Decorator untuk memastikan hanya admin yang bisa akses
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Cek apakah user adalah admin
        if session.get('role') != 'administrator':
            logging.warning(f"Akses DITOLAK (403) - Bukan Admin. User ID: {session.get('user_id')}, IP: {request.remote_addr}, Endpoint: {request.endpoint}")
            abort(403)
        
        # Cek apakah 2FA sudah dilewati untuk sesi ini
        user = User.query.get(session.get('user_id'))
        if user and user.otp_secret and not session.get('2fa_passed'):
            logging.warning(f"Akses DITOLAK (403) - 2FA Belum Dilewati. User ID: {user.id}, IP: {request.remote_addr}, Endpoint: {request.endpoint}")
            flash('Anda harus menyelesaikan verifikasi dua langkah untuk mengakses halaman ini.', 'warning')
            return redirect(url_for('verify_2fa'))

        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    books = Buku.query.order_by(Buku.id.desc()).limit(10).all() # Ambil 10 buku terbaru
    total_buku = Buku.query.count()
    total_pengguna = User.query.count()
    return render_template('admin/dashboard.html', 
                           books=books, 
                           total_buku=total_buku, total_pengguna=total_pengguna)

# 2fa

# SILAKAN COPY DAN GANTI FUNGSI LAMA ANDA DENGAN YANG INI
@app.route('/admin/setup-2fa', methods=['GET', 'POST'])
@login_required
@admin_required
def setup_2fa():
    user = User.query.get(session['user_id'])
    
    if user.otp_secret:
        flash('Two-Factor Authentication sudah aktif.', 'info')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        secret = session.get('otp_secret_temp')
        code = request.form.get('code')
        
        if not secret or not code:
            flash('Sesi tidak valid, silakan coba lagi.', 'danger')
            return redirect(url_for('setup_2fa'))

        try:
            totp = pyotp.TOTP(secret)
            # --- PERUBAHAN 1: Menambahkan toleransi waktu ---
            # Ini untuk mengatasi masalah "kode verifikasi salah" karena perbedaan waktu.
            if totp.verify(code, valid_window=1):
                user.otp_secret = secret
                db.session.commit()
                session.pop('otp_secret_temp', None)
                logging.info(f"Admin (ID: {user.id}) berhasil mengaktifkan 2FA.")
                flash('Two-Factor Authentication berhasil diaktifkan!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                # --- PERUBAHAN: Jika kode salah, batalkan proses dan kembali ke dashboard ---
                # --- LANGKAH DEBUGGING: Catat kode yang diterima dan yang diharapkan server ---
                expected_code = totp.now()
                logging.warning(f"Admin (ID: {user.id}) gagal verifikasi 2FA. Kode Diterima: '{code}', Kode Diharapkan Server: '{expected_code}'. Proses dibatalkan.")
                session.pop('otp_secret_temp', None) # Hapus secret sementara dari session
                return redirect(url_for('admin_dashboard'))
        except Exception as e:
            logging.error(f"Error saat inisialisasi TOTP atau verifikasi di setup_2fa: {e}")
            flash('Terjadi kesalahan internal saat memproses kode 2FA. Silakan coba lagi.', 'danger')
            return redirect(url_for('setup_2fa'))

    # Generate secret baru untuk setup (bagian ini tidak berubah)
    secret = pyotp.random_base32()
    session['otp_secret_temp'] = secret
    
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name="E-Perpus SMAN 1 Tinombo"
    )
    
    img = qrcode.make(otp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    qr_code_data_uri = f"data:image/png;base64,{img_str}"

    return render_template('admin/setup_2fa.html', secret=secret, qr_code=qr_code_data_uri, current_user=user)


@app.route('/admin/disable-2fa', methods=['GET', 'POST'])
@login_required
@admin_required
def disable_2fa():
    """Menangani proses penonaktifan 2FA dengan re-autentikasi password."""
    user = User.query.get(session['user_id'])

    # Jika 2FA memang tidak aktif, langsung kembalikan ke dashboard
    if not user.otp_secret:
        flash('Two-Factor Authentication memang sudah tidak aktif.', 'info')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        password = request.form.get('password')

        # Verifikasi password pengguna
        if user and check_password_hash(user.password, password):
            # Password benar, nonaktifkan 2FA
            user.otp_secret = None
            db.session.commit()
            
            # Hapus flag 2fa_passed dari sesi untuk keamanan
            session.pop('2fa_passed', None)
            
            logging.info(f"Admin (ID: {user.id}) berhasil menonaktifkan 2FA.")
            flash('Two-Factor Authentication telah berhasil dinonaktifkan.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            logging.warning(f"Admin (ID: {user.id}) gagal menonaktifkan 2FA: Password salah.")
            flash('Password yang Anda masukkan salah. Penonaktifan dibatalkan.', 'danger')
            return redirect(url_for('disable_2fa'))

    return render_template('admin/disable_2fa.html')

# --- Rute Manajemen Pengguna oleh Admin ---

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    """Menampilkan halaman untuk mengelola semua pengguna."""
    # Ambil semua user, urutkan berdasarkan ID
    all_users = User.query.order_by(User.id).all()
    return render_template('admin/users.html', users=all_users)


@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Memproses penghapusan pengguna."""
    # Mencegah admin menghapus akunnya sendiri
    if user_id == session.get('user_id'):
        flash('Anda tidak dapat menghapus akun Anda sendiri.', 'danger')
        return redirect(url_for('manage_users'))

    user_to_delete = User.query.get_or_404(user_id)
    username = user_to_delete.username
    
    db.session.delete(user_to_delete)
    db.session.commit()

    logging.info(f"Admin (ID: {session.get('user_id')}) telah menghapus pengguna '{username}' (ID: {user_id}).")
    flash(f'Pengguna {username} berhasil dihapus.', 'success')
    return redirect(url_for('manage_users'))


# Rute Tambah Buku
@app.route('/admin/buku/tambah', methods=['GET', 'POST'])
@admin_required
def tambah_buku():
    if request.method == 'POST':
        judul = sanitize_string(request.form['judul'], max_length=200)
        penulis = sanitize_string(request.form['penulis'], max_length=100)
        tahun_terbit = request.form['tahun_terbit']
        deskripsi = request.form['deskripsi']
        
        # Handle file upload
        if 'file_buku' not in request.files:
            flash('Tidak ada bagian file.', 'danger')
            return redirect(request.url)
        
        file = request.files['file_buku']
        
        if file.filename == '':
            flash('Tidak ada file yang dipilih.', 'danger')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash('Tipe file tidak diizinkan. Hanya PDF, EPUB, DOC, DOCX, TXT yang diperbolehkan.', 'danger')
            return redirect(request.url)
        
        if file:
            # Buat nama file unik
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            new_buku = Buku(
                judul=judul,
                penulis=penulis,
                tahun_terbit=tahun_terbit,
                deskripsi=deskripsi,
                file_path=unique_filename # Simpan hanya nama file unik
            )
            db.session.add(new_buku)
            db.session.commit()
            logging.info(f"Admin (ID: {session.get('user_id')}) menambahkan buku baru: '{new_buku.judul}' (ID: {new_buku.id})")
            flash('Buku berhasil ditambahkan!', 'success')
            return redirect(url_for('admin_dashboard'))
            
    return render_template('admin/form_buku.html', title='Tambah Buku', buku=None)

# Rute Edit Buku
@app.route('/admin/buku/edit/<int:buku_id>', methods=['GET', 'POST'])
@admin_required
def edit_buku(buku_id):
    buku = Buku.query.get_or_404(buku_id)
    if request.method == 'POST':
        buku.judul = sanitize_string(request.form['judul'], max_length=200)
        buku.penulis = sanitize_string(request.form['penulis'], max_length=100)
        buku.tahun_terbit = request.form['tahun_terbit']
        buku.deskripsi = request.form['deskripsi']
        
        # Handle file upload jika ada file baru
        if 'file_buku' in request.files:
            file = request.files['file_buku']
            if file.filename != '':
                if not allowed_file(file.filename):
                    flash('Tipe file tidak diizinkan. Hanya PDF, EPUB, DOC, DOCX, TXT yang diperbolehkan.', 'danger')
                    return redirect(request.url)
                # Hapus file lama jika ada
                if buku.file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], buku.file_path)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], buku.file_path))
                
                # Simpan file baru
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                buku.file_path = unique_filename
        
        db.session.commit()
        logging.info(f"Admin (ID: {session.get('user_id')}) mengedit buku: '{buku.judul}' (ID: {buku.id})")
        flash('Buku berhasil diperbarui!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin/form_buku.html', title='Edit Buku', buku=buku)

# Rute Hapus Buku
@app.route('/admin/buku/hapus/<int:buku_id>', methods=['POST'])
@admin_required
def hapus_buku(buku_id):
    buku = Buku.query.get_or_404(buku_id)
    logging.info(f"Admin (ID: {session.get('user_id')}) menghapus buku: '{buku.judul}' (ID: {buku.id})")
    # Hapus file fisik dari server
    if buku.file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], buku.file_path)):
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], buku.file_path))
        
    db.session.delete(buku)
    db.session.commit()
    flash('Buku berhasil dihapus!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logs')
@admin_required
def view_logs():
    """Menampilkan log aktivitas pengguna dari file e-perpus.log."""
    parsed_logs = []
    log_file_path = 'e-perpus.log'
    
    # Keyword untuk memfilter log yang relevan dengan aktivitas pengguna
    user_activity_keywords = [
        'login', 'logout', 'gagal', 'berhasil', 'verifikasi', 'dihapus', 
        'menambahkan', 'mengedit', 'mengunduh', 'Akses', 'reset', '2FA', 'membersihkan'
    ]

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            # Baca 200 baris terakhir untuk efisiensi
            lines = f.readlines()[-200:]

            for line in lines:
                # Hanya proses baris yang mengandung keyword aktivitas pengguna (case-insensitive)
                if any(keyword.lower() in line.lower() for keyword in user_activity_keywords):
                    # Coba parse baris log dengan format yang diharapkan
                    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (.*)", line)
                    if match:
                        timestamp, level, message = match.groups()
                        
                        # Coba ekstrak alamat IP dari pesan
                        ip_match = re.search(r"IP: ([\d\.]+)", message)
                        ip_address = ip_match.group(1) if ip_match else "N/A"
                        
                        parsed_logs.append({
                            "timestamp": timestamp,
                            "level": level,
                            "message": message.strip(),
                            "ip": ip_address
                        })
        # Balik urutan list yang sudah diproses agar log terbaru muncul di paling atas
        parsed_logs.reverse()
    except FileNotFoundError:
        flash('File log tidak ditemukan.', 'danger')
    except Exception as e:
        flash(f'Terjadi kesalahan saat membaca file log: {e}', 'danger')
        
    return render_template('admin/logs.html', logs=parsed_logs)
        

# @app.route('/admin/logs/delete', methods=['POST'])
# @admin_required
# def delete_logs():
#     log_file = 'e-perpus.log'
#     try:
#         open(log_file, 'w').close()  # Kosongkan isi file
#         flash('Semua log berhasil dihapus.', 'success')
#     except Exception as e:
#         flash(f'Gagal menghapus log: {str(e)}', 'danger')
#     return redirect(url_for('view_logs'))


# --- Middleware untuk Header Keamanan ---
@app.after_request
def add_security_headers(response):
    # Mencegah browser dari menebak tipe konten (MIME sniffing)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Mencegah clickjacking dengan tidak mengizinkan halaman dirender dalam frame
    response.headers['X-Frame-Options'] = 'DENY'
    # (Opsional) Header keamanan lainnya bisa ditambahkan di sini
    return response

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    logging.warning(f"404 Not Found: Pengguna mencoba mengakses {request.path} dari IP {request.remote_addr}")
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    # Pesan log sudah ada di decorator @admin_required, jadi tidak perlu duplikat di sini
    # Cukup tampilkan halaman errornya
    return render_template('errors/403.html'), 403

# --- Akhir Error Handlers ---


if __name__ == '__main__':
    app.run(debug=False)

