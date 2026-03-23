import sqlite3
from werkzeug.security import generate_password_hash
from encryption import generate_key

DB_NAME = "healthcare.db"


def init_db():
    generate_key()

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'doctor'))
        );
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name_encrypted BLOB NOT NULL,
            age_encrypted BLOB NOT NULL,
            disease_encrypted BLOB NOT NULL,
            prescription_encrypted BLOB NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
        """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            role TEXT,
            ip_address TEXT,
            event_type TEXT NOT NULL,
            details TEXT
        );
        """
    )

    c.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
    if c.fetchone()[0] == 0:
        admin_pw = generate_password_hash("password123")
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_pw, "admin"),
        )

    # Generate synthetic data for doctors
    synthetic_doctors = [
        ("dr_smith", "cardio123!", "doctor"),
        ("dr_jones", "neuro456!", "doctor"),
        ("dr_taylor", "ortho789!", "doctor"),
        ("dr_brown", "peds321!", "doctor"),
        ("dr_wilson", "onco654!", "doctor"),
        ("dr_miller", "derma987!", "doctor"),
        ("dr_clark", "psych147!", "doctor")
    ]

    for username, password, role in synthetic_doctors:
        c.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if c.fetchone()[0] == 0:
            doc_pw = generate_password_hash(password)
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, doc_pw, role),
            )

    conn.commit()
    conn.close()
    print("Database initialized with admin and synthetic doctor accounts.")


if __name__ == "__main__":
    init_db()