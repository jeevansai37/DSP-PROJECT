import sqlite3
from werkzeug.security import generate_password_hash
from encryption import generate_key
import os

import os

# Determine the absolute path to the database file in the same directory as this script
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "healthcare.db")

def init_db():
    generate_key()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            hospital_name TEXT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'doctor')),
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            last_login TEXT,
            force_password_change INTEGER DEFAULT 0,
            is_2fa_enabled INTEGER DEFAULT 0,
            otp_secret TEXT
        );
        """
    )
    
    # Schema Migration: Ensure 'email' column exists for existing databases
    c.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in c.fetchall()]
    if 'email' not in columns:
        print("Adding 'email' column to users table...")
        c.execute("ALTER TABLE users ADD COLUMN email TEXT")

    # Patients table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name_encrypted BLOB NOT NULL,
            age_encrypted BLOB NOT NULL,
            disease_encrypted BLOB NOT NULL,
            prescription_encrypted BLOB NOT NULL,
            created_by INTEGER NOT NULL,
            is_critical INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
        """
    )

    # Medical reports table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS medical_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
        );
        """
    )

    # Security events table
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

    # Insert default admin if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
    if c.fetchone()[0] == 0:
        admin_pw = generate_password_hash("password123")
        c.execute(
            "INSERT INTO users (username, password_hash, role, hospital_name, email) VALUES (?, ?, ?, ?, ?)",
            ("admin", admin_pw, "admin", "Demo Hospital", "admin@gmail.com"),
        )
    
    # Insert Jeevan user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("jeevan123",))
    if c.fetchone()[0] == 0:
        jeevan_pw = generate_password_hash("Admin@123")
        c.execute(
            "INSERT INTO users (username, password_hash, role, hospital_name, email) VALUES (?, ?, ?, ?, ?)",
            ("jeevan123", jeevan_pw, "doctor", "Demo Hospital", "jeevan@gmail.com"),
        )

    conn.commit()
    conn.close()
    print("Database initialized successfully with SQLite.")

if __name__ == "__main__":
    init_db()