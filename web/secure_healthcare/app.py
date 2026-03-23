from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
)
import os
import sqlite3
from functools import wraps

from werkzeug.security import check_password_hash as wz_check_password_hash
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect

from encryption import encrypt_text, decrypt_text, generate_key

DB_NAME = "healthcare.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-flask-key-change-me"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # set True behind HTTPS in production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

generate_key()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # take first IP in X-Forwarded-For list
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_security_event(event_type: str, details: str, username: str | None = None, role: str | None = None) -> None:
    """Write a security-relevant event to the database."""
    try:
        ip_address = get_client_ip()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO security_events (username, role, ip_address, event_type, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, role, ip_address, event_type, details),
        )
        conn.commit()
    finally:
        conn.close()


@app.before_request
def make_session_secure() -> None:
    session.permanent = False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            log_security_event(
                "unauthenticated_access",
                f"Unauthenticated request to {request.path}",
            )
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_role" not in session:
                log_security_event(
                    "unauthorized_access",
                    f"Missing role accessing {request.path}",
                )
                flash("Unauthorized access.", "danger")
                return redirect(url_for("login"))
            if session["user_role"] not in roles:
                log_security_event(
                    "unauthorized_access",
                    f"Role {session.get('user_role')} attempted to access {request.path}",
                    username=session.get("username"),
                    role=session.get("user_role"),
                )
                flash("You do not have permission to view this page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)

        return decorated_function

    return decorator





@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@csrf.exempt
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()

        ok = False
        if user:
            stored_hash = user["password_hash"]
            try:
                ok = bcrypt.check_password_hash(stored_hash, password)
            except ValueError:
                ok = wz_check_password_hash(stored_hash, password)

        ip_address = get_client_ip()

        if ok:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["user_role"] = user["role"]
            log_security_event(
                "login_success",
                f"Successful login for {username} from {ip_address}",
                username=username,
                role=user["role"],
            )
            flash("Login successful.", "success")
            conn.close()
            return redirect(url_for("dashboard"))
        else:
            log_security_event(
                "login_failed",
                f"Failed login for username '{username}' from {ip_address}",
                username=username or None,
            )
            # detect multiple recent failures from same IP
            cur.execute(
                """
                SELECT COUNT(*) AS failures
                FROM security_events
                WHERE event_type = 'login_failed'
                  AND ip_address = ?
                  AND timestamp >= datetime('now', '-10 minutes')
                """,
                (ip_address,),
            )
            failures = cur.fetchone()[0]
            if failures >= 3:
                log_security_event(
                    "suspicious_activity",
                    f"{failures} failed login attempts in 10 minutes from {ip_address}",
                )
            conn.close()
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session.get("user_id")
    user_role = session.get("user_role")

    conn = get_db_connection()
    cur = conn.cursor()

    if user_role == "doctor":
        cur.execute("SELECT COUNT(*) FROM patients WHERE created_by = ?", (user_id,))
    else:
        cur.execute("SELECT COUNT(*) FROM patients")
        
    total_patients = cur.fetchone()[0]

    base_query = """
        SELECT
            p.id,
            p.name_encrypted,
            p.age_encrypted,
            p.disease_encrypted,
            p.prescription_encrypted,
            u.username AS doctor_username
        FROM patients p
        JOIN users u ON p.created_by = u.id
    """
    
    if user_role == "doctor":
        cur.execute(base_query + " WHERE p.created_by = ? ORDER BY p.id DESC LIMIT 5", (user_id,))
    else:
        cur.execute(base_query + " ORDER BY p.id DESC LIMIT 5")
        
    rows = cur.fetchall()
    conn.close()

    recent_patients = []
    for row in rows:
        try:
            recent_patients.append(
                {
                    "id": row["id"],
                    "name": decrypt_text(row["name_encrypted"]),
                    "age": decrypt_text(row["age_encrypted"]),
                    "disease": decrypt_text(row["disease_encrypted"]),
                    "prescription": decrypt_text(row["prescription_encrypted"]),
                    "doctor_username": row["doctor_username"],
                }
            )
        except Exception:
            recent_patients.append(
                {
                    "id": row["id"],
                    "name": "[Decryption error]",
                    "age": "[Decryption error]",
                    "disease": "[Decryption error]",
                    "prescription": "[Decryption error]",
                    "doctor_username": row["doctor_username"],
                }
            )

    stats = {
        "total_patients": total_patients,
        "critical_cases": 0,
        "recent_records": len(recent_patients),
    }

    return render_template(
        "dashboard.html",
        role=session.get("user_role"),
        stats=stats,
        recent_patients=recent_patients,
    )


@app.route("/api/analytics/patients")
@login_required
@role_required("doctor", "admin")
def analytics_patients():
    user_id = session.get("user_id")
    user_role = session.get("user_role")
    
    conn = get_db_connection()
    cur = conn.cursor()

    if user_role == "doctor":
        cur.execute("SELECT COUNT(*) AS count FROM patients WHERE created_by = ?", (user_id,))
    else:
        cur.execute("SELECT COUNT(*) AS count FROM patients")
        
    rows = cur.fetchall()

    patients_per_day_labels = []
    patients_per_day_data = []
    if rows:
        patients_per_day_labels = ["Today"]
        patients_per_day_data = [rows[0]["count"]]

    if user_role == "doctor":
        cur.execute(
            """
            SELECT
                name_encrypted,
                age_encrypted,
                disease_encrypted
            FROM patients
            WHERE created_by = ?
            """,
            (user_id,)
        )
    else:
        cur.execute(
            """
            SELECT
                name_encrypted,
                age_encrypted,
                disease_encrypted
            FROM patients
            """
        )
        
    all_rows = cur.fetchall()
    conn.close()

    disease_counts = {}
    age_groups = {
        "0-18": 0,
        "19-40": 0,
        "41-65": 0,
        "66+": 0,
    }

    for row in all_rows:
        try:
            disease = decrypt_text(row["disease_encrypted"]) or "Unknown"
            age_str = decrypt_text(row["age_encrypted"]) or ""
        except Exception:
            disease = "Unknown"
            age_str = ""

        disease_key = disease.strip() or "Unknown"
        disease_counts[disease_key] = disease_counts.get(disease_key, 0) + 1

        try:
            age_val = int(age_str)
        except ValueError:
            age_val = None

        if age_val is not None:
            if age_val <= 18:
                age_groups["0-18"] += 1
            elif age_val <= 40:
                age_groups["19-40"] += 1
            elif age_val <= 65:
                age_groups["41-65"] += 1
            else:
                age_groups["66+"] += 1

    disease_labels = list(disease_counts.keys())
    disease_data = [disease_counts[label] for label in disease_labels]

    age_labels = list(age_groups.keys())
    age_data = [age_groups[label] for label in age_labels]

    return jsonify(
        {
            "patients_per_day": {
                "labels": patients_per_day_labels,
                "data": patients_per_day_data,
            },
            "disease_distribution": {
                "labels": disease_labels,
                "data": disease_data,
            },
            "age_groups": {
                "labels": age_labels,
                "data": age_data,
            },
        }
    )


@app.route("/add_patient", methods=["GET", "POST"])
@login_required
@role_required("doctor")
def add_patient():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        age = (request.form.get("age") or "").strip()
        disease = (request.form.get("disease") or "").strip()
        prescription = (request.form.get("prescription") or "").strip()

        errors = []
        if not name:
            errors.append("Patient name is required.")
        if not age.isdigit():
            errors.append("Age must be a valid number.")
        else:
            age_val = int(age)
            if age_val <= 0 or age_val > 120:
                errors.append("Age must be between 1 and 120.")
        if not disease:
            errors.append("Primary condition is required.")
        if not prescription:
            errors.append("Prescription and notes are required.")
        if len(prescription) > 2000:
            errors.append("Prescription is too long.")

        if errors:
            for msg in errors:
                flash(msg, "danger")
            return render_template("add_patient.html")

        name_enc = encrypt_text(" ".join(name.split()))
        age_enc = encrypt_text(str(age_val))
        disease_enc = encrypt_text(disease)
        prescription_enc = encrypt_text(prescription)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO patients
            (name_encrypted, age_encrypted, disease_encrypted, prescription_encrypted, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name_enc,
                age_enc,
                disease_enc,
                prescription_enc,
                session["user_id"],
            ),
        )
        conn.commit()
        conn.close()

        flash("Patient record added securely.", "success")
        return redirect(url_for("view_patients"))

    return render_template("add_patient.html")


@app.route("/patients")
@login_required
@role_required("doctor", "admin")
def view_patients():
    user_id = session.get("user_id")
    user_role = session.get("user_role")
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    base_query = """
        SELECT p.id,
               p.name_encrypted,
               p.age_encrypted,
               p.disease_encrypted,
               p.prescription_encrypted,
               u.username AS doctor_username
        FROM patients p
        JOIN users u ON p.created_by = u.id
    """
    
    if user_role == "doctor":
        cur.execute(base_query + " WHERE p.created_by = ? ORDER BY p.id DESC", (user_id,))
    else:
        cur.execute(base_query + " ORDER BY p.id DESC")
        
    rows = cur.fetchall()
    conn.close()

    patients = []
    doctors = set()
    for row in rows:
        try:
            name = decrypt_text(row["name_encrypted"])
            age = decrypt_text(row["age_encrypted"])
            disease = decrypt_text(row["disease_encrypted"])
            prescription = decrypt_text(row["prescription_encrypted"])
        except Exception:
            name = "[Decryption error]"
            age = "[Decryption error]"
            disease = "[Decryption error]"
            prescription = "[Decryption error]"

        doctor_username = row["doctor_username"]
        doctors.add(doctor_username)

        patients.append(
            {
                "id": row["id"],
                "name": name,
                "age": age,
                "disease": disease,
                "prescription": prescription,
                "doctor_username": doctor_username,
            }
        )

    return render_template(
        "view_patients.html",
        patients=patients,
        doctors=sorted(doctors),
    )


@app.route("/patients/<int:patient_id>")
@login_required
@role_required("doctor", "admin")
def patient_profile(patient_id):
    user_id = session.get("user_id")
    user_role = session.get("user_role")
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    query = """
        SELECT p.id,
               p.name_encrypted,
               p.age_encrypted,
               p.disease_encrypted,
               p.prescription_encrypted,
               p.created_by,
               u.username AS doctor_username
        FROM patients p
        JOIN users u ON p.created_by = u.id
        WHERE p.id = ?
    """
    
    if user_role == "doctor":
        cur.execute(query + " AND p.created_by = ?", (patient_id, user_id))
    else:
        cur.execute(query, (patient_id,))
        
    row = cur.fetchone()
    conn.close()

    if not row:
        flash("Patient not found.", "warning")
        return redirect(url_for("view_patients"))

    try:
        patient = {
            "id": row["id"],
            "name": decrypt_text(row["name_encrypted"]),
            "age": decrypt_text(row["age_encrypted"]),
            "disease": decrypt_text(row["disease_encrypted"]),
            "prescription": decrypt_text(row["prescription_encrypted"]),
            "doctor_username": row["doctor_username"],
        }
    except Exception:
        patient = {
            "id": row["id"],
            "name": "[Decryption error]",
            "age": "[Decryption error]",
            "disease": "[Decryption error]",
            "prescription": "[Decryption error]",
            "doctor_username": row["doctor_username"],
        }

    uploaded_reports = []

    return render_template(
        "patient_profile.html",
        patient=patient,
        uploaded_reports=uploaded_reports,
    )


@app.route("/patients/<int:patient_id>/upload", methods=["POST"])
@login_required
@role_required("doctor")
def upload_report(patient_id):
    file = request.files.get("report")
    if not file:
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("patient_profile", patient_id=patient_id))

    flash("File received (demo only – not stored on disk).", "info")
    return redirect(url_for("patient_profile", patient_id=patient_id))


@app.route("/medical-records")
@login_required
@role_required("doctor", "admin")
def medical_records():
    user_id = session.get("user_id")
    user_role = session.get("user_role")
    
    conn = get_db_connection()
    cur = conn.cursor()

    if user_role == "doctor":
        cur.execute("SELECT COUNT(*) FROM patients WHERE created_by = ?", (user_id,))
    else:
        cur.execute("SELECT COUNT(*) FROM patients")
        
    total_patients = cur.fetchone()[0]

    base_query = """
        SELECT
            p.id,
            p.name_encrypted,
            p.age_encrypted,
            p.disease_encrypted,
            p.prescription_encrypted
        FROM patients p
    """
    
    if user_role == "doctor":
        cur.execute(base_query + " WHERE p.created_by = ? ORDER BY p.id DESC LIMIT 10", (user_id,))
    else:
        cur.execute(base_query + " ORDER BY p.id DESC LIMIT 10")
        
    rows = cur.fetchall()
    conn.close()

    recent_records = []
    for row in rows:
        try:
            recent_records.append(
                {
                    "id": row["id"],
                    "name": decrypt_text(row["name_encrypted"]),
                    "age": decrypt_text(row["age_encrypted"]),
                    "disease": decrypt_text(row["disease_encrypted"]),
                    "prescription": decrypt_text(row["prescription_encrypted"]),
                }
            )
        except Exception:
            recent_records.append(
                {
                    "id": row["id"],
                    "name": "[Decryption error]",
                    "age": "[Decryption error]",
                    "disease": "[Decryption error]",
                    "prescription": "[Decryption error]",
                }
            )

    stats = {
        "total_patients": total_patients,
        "critical_cases": 0,
        "recent_records": len(recent_records),
    }

    return render_template(
        "medical_records.html",
        stats=stats,
        records=recent_records,
    )


@app.route("/security-logs")
@login_required
@role_required("admin")
def security_logs():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT timestamp, username, role, ip_address, event_type, details
        FROM security_events
        ORDER BY timestamp DESC
        LIMIT 200
        """
    )
    logs = cur.fetchall()

    cur.execute(
        """
        SELECT ip_address, COUNT(*) AS failures
        FROM security_events
        WHERE event_type IN ('login_failed', 'suspicious_activity')
          AND ip_address IS NOT NULL
        GROUP BY ip_address
        HAVING failures >= 3
        ORDER BY failures DESC
        """
    )
    suspicious_ips = cur.fetchall()

    cur.execute(
        """
        SELECT
            SUM(CASE WHEN event_type = 'login_failed' THEN 1 ELSE 0 END) AS failed_logins,
            SUM(CASE WHEN event_type = 'suspicious_activity' THEN 1 ELSE 0 END) AS suspicious_events,
            SUM(CASE WHEN event_type IN ('unauthenticated_access', 'unauthorized_access') THEN 1 ELSE 0 END)
                AS unauthorized_attempts
        FROM security_events
        """
    )
    aggregates = cur.fetchone()
    conn.close()

    stats = {
        "failed_logins": aggregates["failed_logins"] if aggregates else 0,
        "suspicious_events": aggregates["suspicious_events"] if aggregates else 0,
        "unauthorized_attempts": aggregates["unauthorized_attempts"] if aggregates else 0,
    }

    return render_template(
        "security_logs.html",
        logs=logs,
        suspicious_ips=suspicious_ips,
        stats=stats,
    )


@app.route("/admin/doctors", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_doctors():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("manage_doctors"))

        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if username already exists
        cur.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cur.fetchone()[0] > 0:
            flash(f"Username '{username}' is already taken.", "danger")
            conn.close()
            return redirect(url_for("manage_doctors"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, "doctor"),
            )
            conn.commit()
            log_security_event(
                "account_created",
                f"Admin created a new doctor account for {username}",
                username=session.get("username"),
                role="admin",
            )
            flash(f"Doctor account '{username}' created successfully.", "success")
        except sqlite3.IntegrityError:
            flash("Database error occurred while creating doctor.", "danger")
        finally:
            conn.close()

        return redirect(url_for("manage_doctors"))

    # GET request - show list of doctors
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE role = 'doctor' ORDER BY id DESC")
    doctors = cur.fetchall()
    conn.close()

    return render_template("manage_doctors.html", doctors=doctors)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user_id = session.get("user_id")

        if not current_password or not new_password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for("settings"))

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("settings"))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()

        if not user:
            flash("User not found.", "danger")
            conn.close()
            return redirect(url_for("login"))

        stored_hash = user["password_hash"]
        ok = False
        try:
            ok = bcrypt.check_password_hash(stored_hash, current_password)
        except ValueError:
            ok = wz_check_password_hash(stored_hash, current_password)

        if not ok:
            log_security_event(
                "password_change_failed",
                "Failed password change attempt: Incorrect current password",
                username=session.get("username"),
                role=session.get("user_role"),
            )
            flash("Incorrect current password.", "danger")
            conn.close()
            return redirect(url_for("settings"))

        # Update password
        new_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        
        log_security_event(
            "password_changed",
            "User changed their password successfully",
            username=session.get("username"),
            role=session.get("user_role"),
        )
        conn.close()

        flash("Password updated successfully.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True)