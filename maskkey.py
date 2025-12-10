from flask import Flask, request, render_template, redirect, url_for, session, flash
import requests, time, os, pandas as pd, json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

# ----------------- CONFIG -----------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = "supersecretkey123"  # ganti sesuai kebutuhan

ACCESS_TOKEN = "gjXPpqcD2gsURRoTgViy"
FONNTE_API = "https://api.fonnte.com/send"
DB_FILE = 'users.db'

# ----------------- LOGIN DECORATOR -----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Silakan login terlebih dahulu.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- DATABASE INIT -----------------
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # Users table (profile_pic optional)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Rate limit table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limit (
                id INTEGER PRIMARY KEY,
                enabled INTEGER DEFAULT 1,
                delay_per_message REAL DEFAULT 1.0,
                max_per_minute INTEGER DEFAULT 20
            )
        ''')
        cursor.execute("INSERT OR IGNORE INTO rate_limit (id) VALUES (1)")
        
        # Templates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Proxy settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS proxy_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy_list TEXT NOT NULL
            )
        """)
        
        # HISTORY TABLE (BARU)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                number TEXT NOT NULL,
                template_id INTEGER,
                template_name TEXT,
                message_used TEXT,
                response TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (template_id) REFERENCES templates(id)
            )
        """)

        conn.commit()

# ----------------- ADD PROFILE_PIC COLUMN IF MISSING -----------------
def add_profile_pic_column():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if "profile_pic" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
            conn.commit()

# ----------------- ADD ROLE COLUMN IF MISSING -----------------
def add_role_column():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if "role" not in columns:
            # Tambahkan kolom role default 'user'
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
            conn.commit()

# Initialize DB and add optional columns if missing
init_db()
add_profile_pic_column()
add_role_column()

# ----------------- ADMIN DECORATOR -----------------
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Anda tidak memiliki akses ke halaman ini!", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

# ------------ PROXY SYSTEM ------------
def load_proxies_from_db():
    """Load proxies from the most recent proxy_settings row, split by newline."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT proxy_list FROM proxy_settings ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()

    if not row:
        return []  # tidak ada proxy

    raw_text = row[0]
    proxies = [line.strip() for line in raw_text.split("\n") if line.strip()]
    return proxies

# gunakan nama fungsi yang benar saat inisialisasi pool
PROXY_POOL = load_proxies_from_db()
PROXY_INDEX = 0

def next_proxy():
    """Return next proxy string from pool (circular)."""
    global PROXY_INDEX
    if not PROXY_POOL:
        return None  # fallback tanpa proxy
    proxy = PROXY_POOL[PROXY_INDEX]
    PROXY_INDEX = (PROXY_INDEX + 1) % len(PROXY_POOL)
    return proxy

def delete_proxy_from_db(bad_proxy):
    """Hapus proxy buruk dari database & reload pool."""
    global PROXY_POOL, PROXY_INDEX
    if not bad_proxy:
        return
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Hapus baris yang mengandung proxy tersebut
        cursor.execute("DELETE FROM proxy_settings WHERE proxy_list LIKE ?", ("%"+bad_proxy+"%",))
        conn.commit()

    PROXY_POOL = load_proxies_from_db()
    PROXY_INDEX = 0
    print("🗑️ Proxy dihapus otomatis:", bad_proxy)

def normalize_proxy(proxy):
    """Pastikan proxy memiliki skema http:// atau https://
    Jika user hanya masukkan ip:port, tambahkan http://"""
    if not proxy:
        return proxy
    p = proxy.strip()
    if p.startswith("http://") or p.startswith("https://"):
        return p
    return "http://" + p

def test_proxy(proxy):
    """Cek apakah proxy masih hidup & support HTTPS (simple test ke google)."""
    if not proxy:
        return False
    p = normalize_proxy(proxy)
    proxies = {"http": p, "https": p}
    try:
        # small timeout; tujuan hanya untuk memastikan koneksi dapat dibuat
        r = requests.get("https://www.google.com", proxies=proxies, timeout=6)
        return r.status_code == 200
    except Exception:
        return False

def get_working_proxy(try_count=5):
    """
    Ambil proxy yang hidup. 
    Mencoba `try_count` proxy (memutar pool dengan next_proxy()).
    Jika proxy gagal test_proxy -> hapus via delete_proxy_from_db() dan lanjut.
    Return: proxy string (as saved in DB), atau None jika tidak ada yang hidup.
    """
    # jika PROXY_POOL kosong, langsung return None
    global PROXY_POOL, PROXY_INDEX
    if not PROXY_POOL:
        return None

    # Coba sejumlah proxy; gunakan next_proxy() untuk mengambil tiap kali.
    for _ in range(try_count):
        proxy = next_proxy()
        if not proxy:
            return None

        print("🔍 Testing proxy:", proxy)
        try:
            if test_proxy(proxy):
                print("✅ Proxy OK:", proxy)
                return proxy
            else:
                print("❌ Proxy mati/timeout, hapus:", proxy)
                delete_proxy_from_db(proxy)
                # continue loop; next_proxy() will pick the next one
        except Exception as e:
            # jika test_proxy raise (jarang karena kita catch di test_proxy), hapus juga
            print("Error saat test proxy:", e)
            delete_proxy_from_db(proxy)

    # jika tidak ketemu proxy yang OK
    print("⚠️ Tidak ada proxy hidup setelah pengecekan.")
    return None  # no working proxy

def send_via_proxy(url, data, files=None, proxy=None):
    """Kirim request via proxy (jika proxy None → tanpa proxy).
    Jika proxy menyebabkan error network yang jelas, hapus proxy dari DB."""
    proxies = None
    if proxy:
        p = normalize_proxy(proxy)
        proxies = {"http": p, "https": p}

    try:
        r = requests.post(url, headers={"Authorization": ACCESS_TOKEN}, data=data,
                          files=files, proxies=proxies, timeout=20)
        # Return JSON if endpoint provides it, otherwise basic status
        try:
            return r.json()
        except:
            return {"status": True, "http_status": r.status_code, "text": r.text}

    except requests.exceptions.ProxyError as e:
        # Proxy tidak bisa digunakan
        err = str(e)
        print("ProxyError:", err)
        if proxy:
            delete_proxy_from_db(proxy)
        return {"status": False, "error": "ProxyError: " + err}

    except requests.exceptions.ConnectTimeout as e:
        err = str(e)
        print("ConnectTimeout:", err)
        if proxy:
            delete_proxy_from_db(proxy)
        return {"status": False, "error": "ConnectTimeout: " + err}

    except requests.exceptions.ReadTimeout as e:
        err = str(e)
        print("ReadTimeout:", err)
        # Bukan selalu proxy, tapi kemungkinan proxy lelet → hapus
        if proxy:
            delete_proxy_from_db(proxy)
        return {"status": False, "error": "ReadTimeout: " + err}

    except requests.exceptions.SSLError as e:
        err = str(e)
        print("SSLError (likely proxy not supporting HTTPS):", err)
        if proxy:
            delete_proxy_from_db(proxy)
        return {"status": False, "error": "SSLError: " + err}

    except Exception as e:
        err = str(e)
        print("Other send error:", err)
        # untuk safety, jika menunjukan proxy failure → hapus
        if proxy and ("timed out" in err.lower() or "failed to establish" in err.lower()):
            delete_proxy_from_db(proxy)
        return {"status": False, "error": err}

# ----------------- ADMIN PROXY PAGE -----------------
def admin_only():
    return session.get("role") == "admin" or session.get("username") == "admin"


@app.route("/admin/proxy", methods=["GET", "POST"])
@login_required
def admin_proxy():
    if not admin_only():
        flash("Anda tidak memiliki akses ke halaman admin!", "error")
        return redirect(url_for('dashboard'))

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Tambah proxy
        if request.method == "POST":
            proxy_text = request.form.get("proxy")
            if proxy_text:
                cursor.execute("INSERT INTO proxy_settings (proxy_list) VALUES (?)", (proxy_text,))
                conn.commit()
                flash("Proxy berhasil ditambahkan!", "success")

                # Reload PROXY POOL
                global PROXY_POOL, PROXY_INDEX
                PROXY_POOL = load_proxies_from_db()
                PROXY_INDEX = 0

            return redirect(url_for("admin_proxy"))

        # Ambil proxy list
        cursor.execute("SELECT id, proxy_list FROM proxy_settings ORDER BY id ASC")
        current_proxy = cursor.fetchall()

    return render_template("admin/admin_proxy.html", proxy_list=current_proxy)


@app.route("/admin/proxy/delete/<int:proxy_id>", methods=["POST"])
@login_required
def delete_proxy(proxy_id):
    if not admin_only():
        flash("Anda tidak memiliki akscmdes ke halaman admin!", "error")
        return redirect(url_for('dashboard'))

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM proxy_settings WHERE id=?", (proxy_id,))
        conn.commit()

    global PROXY_POOL, PROXY_INDEX
    PROXY_POOL = load_proxies_from_db()
    PROXY_INDEX = 0

    flash("Proxy berhasil dihapus!", "success")
    return redirect(url_for("admin_proxy"))

# ----------------- ADMIN USER MANAGEMENT -----------------
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_required
def admin_user():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if request.method == "POST":
            username = request.form["username"]
            email = request.form["email"]
            password = generate_password_hash(request.form["password"])
            role = request.form.get("role", "user")

            cursor.execute(
                "INSERT INTO users(username,email,password,role) VALUES (?,?,?,?)",
                (username, email, password, role)
            )
            conn.commit()

            flash("User berhasil ditambahkan!", "success")
            return redirect(url_for("admin_user"))

        cursor.execute("SELECT * FROM users ORDER BY id ASC")
        users = cursor.fetchall()

    return render_template("admin/admin_user.html", users=users)

@app.route("/admin/users/edit/<int:user_id>", methods=["GET","POST"])
@login_required
@admin_required
def edit_user(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()

        if request.method == "POST":
            new_username = request.form["username"]
            new_email = request.form["email"]
            new_role = request.form["role"]
            new_password = request.form.get("password")

            if new_password:
                new_password = generate_password_hash(new_password)
                cursor.execute(
                    "UPDATE users SET username=?, email=?, role=?, password=? WHERE id=?",
                    (new_username, new_email, new_role, new_password, user_id)
                )
            else:
                cursor.execute(
                    "UPDATE users SET username=?, email=?, role=? WHERE id=?",
                    (new_username, new_email, new_role, user_id)
                )

            conn.commit()
            flash("User berhasil diperbarui!", "success")
            return redirect(url_for("admin_user"))

    return render_template("admin/edit_user.html", user=user)

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()

    flash("User berhasil dihapus!", "success")
    return redirect(url_for("admin_user"))

# ----------------- ADMIN ACTIVITY -----------------
@app.route("/admin/activity")
@login_required
@admin_required
def admin_activity():
    if not admin_only():
        flash("Akses ditolak!", "error")
        return redirect(url_for("dashboard"))
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT h.*, u.username 
            FROM history h 
            LEFT JOIN users u ON h.user_id=u.id 
            ORDER BY h.created_at DESC
        """)
        activities = cursor.fetchall()

    return render_template("admin/activity.html", activities=activities)

# ----------------- ADMIN PROGRESS -----------------
@app.route("/admin/progress", methods=["GET","POST"])
@login_required
@admin_required
def admin_progress():
    search_user = request.form.get("username")

    query = """
    SELECT 
        u.username,
        h.number,
        h.template_name,
        h.message_used,
        h.response,
        h.created_at
    FROM history h
    JOIN users u ON h.user_id = u.id
    """
    params = []

    if search_user:
        query += " WHERE u.username LIKE ?"
        params.append("%" + search_user + "%")

    query += " ORDER BY h.created_at DESC"

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        history = cursor.fetchall()

    return render_template("admin/progress.html", history=history, search_user=search_user)

# ----------------- EXPORT CSV -----------------
@app.route("/admin/export/csv")
@login_required
def export_all_csv():
    if not admin_only():
        flash("Akses ditolak!", "error")
        return redirect(url_for("dashboard"))

    import csv

    filepath = "static/all_history.csv"

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT h.*, u.username 
            FROM history h 
            JOIN users u ON h.user_id=u.id 
            ORDER BY h.created_at DESC
        """)
        rows = cursor.fetchall()

    # Tulis CSV
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID","User","Number","Template","Message","Response","Date"])
        for r in rows:
            writer.writerow(r)

    return redirect("/" + filepath)

# ----------------- ADMIN SEARCH USER -----------------
@app.route("/admin/search-user")
@login_required
@admin_required
def admin_search_user():
    q = request.args.get("q", "")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if q:
            cursor.execute(
                "SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?",
                (f"%{q}%", f"%{q}%")
            )
            results = cursor.fetchall()
        else:
            results = []

    return render_template("admin/search_user.html", results=results, query=q)

# ----------------- RATE LIMIT FUNCTIONS -----------------
def get_rate_limit():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT enabled, delay_per_message, max_per_minute FROM rate_limit WHERE id=1")
        row = cursor.fetchone()
        if row:
            return row
        # fallback default
        return (1, 1.0, 20)

def update_rate_limit(enabled, delay, max_min):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE rate_limit SET enabled=?, delay_per_message=?, max_per_minute=? WHERE id=1
        """, (enabled, delay, max_min))
        conn.commit()

# ----------------- HELPER FUNCTIONS -----------------
import random
import re

def spin_text(text):
    """
    Fungsi spin text: format {a|b|c}, bisa nested.
    Contoh:
        "Halo {teman|sobat}" -> "Halo teman" atau "Halo sobat"
        "Pilih {merah|{biru|hijau}}" -> "Pilih merah" atau "Pilih biru" atau "Pilih hijau"
    """
    pattern = re.compile(r'\{([^{}]+)\}')

    # Selama masih ada pola {a|b|c}, ganti dengan pilihan acak
    while True:
        match = pattern.search(text)
        if not match:
            break
        options = match.group(1).split('|')
        choice = random.choice(options)
        text = text[:match.start()] + choice + text[match.end():]

    return text

def read_numbers(filepath):
    df = pd.read_excel(filepath)
    possible_columns = ["nomor", "number", "phone", "no", "whatsapp"]
    selected_column = None
    for col in df.columns:
        if str(col).lower() in possible_columns:
            selected_column = col
            break
    if not selected_column:
        selected_column = df.columns[0]

    numbers = []
    for num in df[selected_column]:
        num = str(num).strip().replace(".0", "")
        if num.startswith("0"):
            num = "62" + num[1:]
        if num.isdigit():
            numbers.append(num)
    return numbers

def send_text(number, message):
    headers = {"Authorization": ACCESS_TOKEN}
    data = {"target": number, "message": message, "schedule": 0}
    try:
        return requests.post(FONNTE_API, headers=headers, data=data).json()
    except:
        return {"status": False, "error": "Request failed"}

def send_image(number, image_path, message=None):
    headers = {"Authorization": ACCESS_TOKEN}
    if not message:
        message = " "
    data = {"target": number, "message": message, "schedule": 0}
    with open(image_path, "rb") as f:
        files = {"file": (os.path.basename(image_path), f, "image/jpeg")}
        try:
            return requests.post(FONNTE_API, headers=headers, data=data, files=files).json()
        except:
            return {"status": False, "error": "Request failed"}

# ----------------- TEMPLATE ROUTES -----------------
@app.route("/templates", methods=["GET", "POST"])
@login_required
def templates_page():
    user_id = session['user_id']

    # Handle POST dari modal (add atau edit)
    if request.method == "POST":
        template_id = request.form.get("template_id")
        name = request.form.get("name")
        content = request.form.get("content")

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()

            if template_id:  # edit template
                cursor.execute(
                    "UPDATE templates SET name=?, content=? WHERE id=? AND user_id=?",
                    (name, content, template_id, user_id)
                )
            else:  # tambah template baru
                cursor.execute(
                    "INSERT INTO templates (name, content, user_id) VALUES (?, ?, ?)",
                    (name, content, user_id)
                )
            conn.commit()
        flash("Template berhasil disimpan!", "success")
        return redirect(url_for("templates_page"))

    # GET: tampilkan halaman templates
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM templates WHERE user_id=? ORDER BY created_at DESC", (user_id,))
        templates = cursor.fetchall()

    return render_template("templates.html", templates=templates)


@app.route("/templates/delete/<int:id>")
@login_required
def delete_template(id):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM templates WHERE id=? AND user_id=?",
            (id, session['user_id'])
        )
        conn.commit()
    flash("Template berhasil dihapus!", "success")
    return redirect(url_for("templates_page"))

# ----------------- AUTH ROUTES -----------------
@app.route("/register", methods=["GET", "POST"]) # <<===== Register route
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                               (username, email, password))
                conn.commit()
            flash("Registrasi berhasil! Silakan login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username atau email sudah digunakan.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user["password"], password):
            # Simpan session
            session['user_id'] = user["id"]
            session['username'] = user["username"]
            session['profile_pic'] = user["profile_pic"] if user["profile_pic"] else None
            session['role'] = user["role"] if user["role"] else 'user'
            flash("Login berhasil!", "success")

            return redirect(url_for("dashboard"))

        flash("Username atau password salah.", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Anda berhasil logout.", "success")
    return redirect(url_for("login"))

# ----------------- PROFILE -----------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session['user_id']
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, profile_pic FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()  # (username, email, profile_pic)

    if request.method == "POST":
        if "update_info" in request.form:
            new_username = request.form.get("username")
            new_email = request.form.get("email")
            profile_file = request.files.get("profile_pic")

            try:
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()

                    if profile_file and profile_file.filename != "":
                        filename = secure_filename(profile_file.filename)
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        profile_file.save(filepath)
                        cursor.execute(
                            "UPDATE users SET username=?, email=?, profile_pic=? WHERE id=?",
                            (new_username, new_email, filename, user_id)
                        )
                        session['profile_pic'] = filename
                    else:
                        cursor.execute(
                            "UPDATE users SET username=?, email=? WHERE id=?",
                            (new_username, new_email, user_id)
                        )

                    conn.commit()
                session['username'] = new_username
                flash("Info akun berhasil diperbarui!", "success")
            except sqlite3.IntegrityError:
                flash("Username atau email sudah digunakan.", "error")

            return redirect(url_for("profile"))

        # Update password
        if "update_password" in request.form:
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM users WHERE id=?", (user_id,))
                hashed_pw = cursor.fetchone()[0]

                if not check_password_hash(hashed_pw, old_password):
                    flash("Password lama salah!", "error")
                elif new_password != confirm_password:
                    flash("Konfirmasi password tidak cocok!", "error")
                else:
                    cursor.execute(
                        "UPDATE users SET password=? WHERE id=?",
                        (generate_password_hash(new_password), user_id)
                    )
                    conn.commit()
                    flash("Password berhasil diperbarui!", "success")

            return redirect(url_for("profile"))

    # Kirim data user ke template
    return render_template(
        "profile.html",
        user={
            "username": user[0],
            "email": user[1],
            "profile_pic": user[2] if user[2] else None
        }
    )

# ----------------- DASHBOARD -----------------
from datetime import datetime

@app.route("/dashboard")
@login_required
def dashboard():
    # Dashboard untuk user biasa
    user_id = session['user_id']
    
    # Ambil rate limit settings
    enabled, delay_per_msg, max_per_min = get_rate_limit()
    
    # Ambil statistik pesan user
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM history WHERE user_id=?", (user_id,))
        total_messages = cursor.fetchone()[0]
    
    return render_template(
        "dashboard.html",
        rate_enabled=enabled,
        rate_delay=delay_per_msg,
        rate_max=max_per_min,
        total_messages=total_messages
    )

@app.route("/admin/dashboard")
@login_required
@admin_required
def dashboard_admin():
    # Ambil statistik untuk admin
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM history")
        total_messages = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM proxy_settings")
        total_proxies = cursor.fetchone()[0]

    return render_template(
        "admin/dashboard_admin.html",
        total_users=total_users,
        total_messages=total_messages,
        total_proxies=total_proxies
    )

# ----------------- RATE LIMIT -----------------
@app.route("/rate_limit", methods=["GET", "POST"])
@login_required
def rate_limit():
    enabled, delay, max_min = get_rate_limit()
    if request.method == "POST":
        enabled = 1 if request.form.get("enabled") == "on" else 0
        delay = float(request.form.get("delay"))
        max_min = int(request.form.get("max_min"))
        update_rate_limit(enabled, delay, max_min)
        flash("Rate limit berhasil diperbarui!", "success")
        return redirect(url_for("rate_limit"))
    return render_template("admin/rate_limit.html", enabled=enabled, delay=delay, max_min=max_min)

# ----------------- WA BLAST -----------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session['user_id']
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM templates WHERE user_id=?", (user_id,))
        templates = cursor.fetchall()

    if request.method == "POST":
        selected_template_ids = request.form.getlist("template_ids[]")
        manual_message = request.form.get("message")

        # ambil template yang dipilih → simpan sebagai dict
        chosen_messages = []
        for tid in selected_template_ids:
            t = next((t for t in templates if str(t['id']) == tid), None)
            if t:
                chosen_messages.append({
                    "id": t['id'],
                    "name": t['name'],
                    "content": t['content']
                })

        # jika manual message ada
        if manual_message:
            chosen_messages.append({
                "id": 0,
                "name": "Manual",
                "content": manual_message
            })

        # ambil nomor dari file / manual
        numbers = []
        file = request.files.get("numbers_file")
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            if filename.endswith(('.xlsx', '.xls')):
                numbers = read_numbers(filepath)
            else:
                df = pd.read_csv(filepath, header=None)
                numbers = df[0].astype(str).tolist()
        manual_numbers = request.form.get("manual_numbers")
        if manual_numbers:
            numbers.extend([num.strip() for num in manual_numbers.splitlines() if num.strip()])

        # ambil image
        image_path = None
        image = request.files.get("image")
        if image:
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)

        # Kirim ke preview
        return render_template(
            "preview.html",
            numbers=numbers,
            image_path=image_path,
            messages=chosen_messages
        )

    return render_template("index.html", templates=templates)

# ----------------- SEND MESSAGE -----------------
@app.route("/send", methods=["POST"])
@login_required
def send():

    numbers = request.form.getlist("numbers[]")
    raw_messages = request.form.getlist("messages[]")
    image_path = request.form.get("image_path")
    user_id = session["user_id"]

    # Parse pesan yang sudah di-spin dari preview (jangan spin lagi)
    selected_messages = []
    for m in raw_messages:
        try:
            msg = json.loads(m)
            if isinstance(msg, dict) and "content" in msg:
                # Pesan sudah di-spin di preview, jangan spin lagi
                selected_messages.append(msg)
        except:
            # fallback manual string
            selected_messages.append({"id": 0, "name": "Manual", "content": str(m)})

    results = []
    pool_index = 0

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        for number in numbers:
            chosen_template = selected_messages[pool_index]
            pool_index = (pool_index + 1) % len(selected_messages)

            final_message = chosen_template["content"]  # sudah spin

            proxy = get_working_proxy(try_count=5)
            files = None
            if image_path and os.path.exists(image_path):
                with open(image_path, "rb") as f:
                    files = {"file": (os.path.basename(image_path), f, "image/jpeg")}
                    response_data = send_via_proxy(
                        FONNTE_API,
                        data={"target": number, "message": final_message, "schedule": 0},
                        files=files,
                        proxy=proxy
                    )
            else:
                response_data = send_via_proxy(
                    FONNTE_API,
                    data={"target": number, "message": final_message, "schedule": 0},
                    proxy=proxy
                )

            # Simpan history
            cursor.execute("""
                INSERT INTO history (user_id, number, template_id, template_name, message_used, response)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                number,
                chosen_template.get("id", 0),
                chosen_template.get("name", "Manual"),
                final_message,
                json.dumps(response_data)
            ))

            results.append({
                "number": number,
                "template_name": chosen_template.get("name", "Manual"),
                "message_used": final_message,
                "response": response_data
            })

            # Rate limit
            enabled, delay_per_msg, max_min = get_rate_limit()
            if enabled:
                time.sleep(delay_per_msg)

        conn.commit()

    return render_template("status.html", results=results, page=1, total_pages=1)

# ----------------- STATUS PAGE -----------------
@app.route("/status")
@login_required
def status():
    user_id = session["user_id"]

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, number, template_id, template_name, message_used, response, created_at
            FROM history
            WHERE user_id=?
            ORDER BY created_at DESC
        """, (user_id,))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        # Parse status
        try:
            resp = json.loads(r["response"])
            status = 1 if resp.get("status") else 0
        except:
            status = 0

        # Kirim created_at sebagai ISO string
        results.append({
            "number": r["number"],
            "template_id": r["template_id"],
            "template_name": r["template_name"],
            "message_used": r["message_used"],
            "status": status,
            "timestamp": r["created_at"]  # pastikan ini string ISO atau format datetime dari DB
        })

    return render_template("status.html", results=results, page=1, total_pages=1)

# ----------------- PREVIEW PAGE -----------------
@app.route("/preview", methods=["GET", "POST"])
@login_required
def preview():
    if request.method == "POST":
        raw_messages = request.form.getlist("messages[]")
        numbers = request.form.getlist("numbers[]")
        image_path = request.form.get("image_path")

        # Spin semua pesan untuk preview
        preview_messages = []
        for m in raw_messages:
            try:
                msg = json.loads(m)
                if isinstance(msg, dict) and "content" in msg:
                    preview_messages.append({
                        "name": msg.get("name", "Manual"),
                        "content": spin_text(msg["content"])
                    })
            except:
                preview_messages.append({
                    "name": "Manual",
                    "content": spin_text(str(m))
                })

        return render_template(
            "preview.html",
            messages=preview_messages,
            numbers=numbers,
            image_path=image_path,
            page=1,
            total_pages=1
        )

    return redirect(url_for("index"))

# ----------------- PAGINATION -----------------
@app.route("/history")
@login_required
def history_page():
    page = int(request.args.get("page", 1))
    per_page = 20
    offset = (page - 1) * per_page

    user_id = session["user_id"]

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) FROM history WHERE user_id=?
        """, (user_id,))
        total = cursor.fetchone()[0]

        cursor.execute("""
            SELECT * FROM history
            WHERE user_id=?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (user_id, per_page, offset))

        rows = cursor.fetchall()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "history.html",
        history=rows,
        page=page,
        total_pages=total_pages
    )
    
# ----------------- ROUTE EXPORT CSV -----------------
@app.route("/history/export/csv") #<<<===== Route export CSV
@login_required
def export_csv():
    import csv
    user_id = session["user_id"]
    filepath = f"static/history_{user_id}.csv"

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM history WHERE user_id=?", (user_id,))
        rows = cursor.fetchall()

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Number", "Template", "Message", "Response", "Date"])
        for r in rows:
            writer.writerow(r[:6])  # ambil kolom relevan

    return redirect("/" + filepath)

@app.route("/history/export/excel") #<<<===== Route export Excel
@login_required
def export_excel():
    import pandas as pd
    try:
        import openpyxl  # pastikan modul tersedia
    except ImportError:
        flash("Module openpyxl belum terinstall. Silakan install `pip install openpyxl`.", "error")
        return redirect(url_for("history_page"))

    user_id = session["user_id"]
    filepath = f"static/history_{user_id}.xlsx"

    with sqlite3.connect(DB_FILE) as conn:
        df = pd.read_sql_query(
            "SELECT * FROM history WHERE user_id=? ORDER BY created_at DESC",
            conn,
            params=(user_id,)
        )

    df.to_excel(filepath, index=False)
    return redirect("/" + filepath)

# ----------------- RUN APP -----------------
if __name__ == "__main__":
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    # reload PROXY_POOL saat app start (opsional, sudah inisialisasi di atas)
    PROXY_POOL = load_proxies_from_db()
    PROXY_INDEX = 0
    app.run(debug=True)
