import sqlite3
from werkzeug.security import generate_password_hash

DB_FILE = "users.db"

def create_admin():
    username = "Boss"
    email = "boss@gmail.com"
    password = "boss123"   # ← ganti kalau mau
    role = "admin"

    hashed_pw = generate_password_hash(password)

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # cek apakah admin sudah ada
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        existing = cursor.fetchone()

        if existing:
            print("❗ Admin sudah ada, tidak membuat ulang.")
            return

        cursor.execute("""
            INSERT INTO users (username, email, password, role)
            VALUES (?, ?, ?, ?)
        """, (username, email, hashed_pw, role))

        conn.commit()

    print("✅ Admin berhasil dibuat!")
    print(f"Username : {username}")
    print(f"Password : {password}")
    print("Silakan login dan segera ganti password admin.")

if __name__ == "__main__":
    create_admin()
