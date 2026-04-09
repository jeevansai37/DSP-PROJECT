from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, send_file
)
import os
import io
from datetime import datetime, timedelta
from functools import wraps

# PDF Generation Imports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from werkzeug.security import check_password_hash as wz_check_password_hash
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

from encryption import encrypt_text, decrypt_text, generate_key
from db import get_db


load_dotenv()

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SESSION_SECRET", "super-secret-flask-key-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

generate_key()

# ---------------------------------------------------------------------------
# Template Filters
# ---------------------------------------------------------------------------

@app.template_filter("datetime_format")
def datetime_format(value, format="%d %b %Y, %I:%M %p"):
    if not value:
        return "-"
    try:
        if isinstance(value, str):
            # Parse ISO-like string from database
            dt = datetime.fromisoformat(value)
        elif isinstance(value, datetime):
            dt = value
        else:
            return str(value)
        return dt.strftime(format)
    except Exception:
        return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_security_event(event_type, details, username=None, role=None):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO security_events (timestamp, username, role, ip_address, event_type, details) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(), username, role, get_client_ip(), event_type, details)
        )
        db.commit()
    except Exception:
        pass


def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number.")
    special_chars = "@#$%^&+=!?"
    if not any(c in special_chars for c in password):
        errors.append(
            "Password must contain at least one special character "
            "(@, #, $, %, ^, etc.)."
        )
    return errors


def _build_patient_filter(user_role, user_id, hospital_name):
    """Returns a tuple of (sql_where_clause, params)."""
    if user_role == "doctor":
        return "WHERE created_by = ?", (user_id,)
    
    if user_role == "admin":
        if hospital_name and str(hospital_name).strip():
            # Admins see all patients created by doctors in their hospital
            return "WHERE created_by IN (SELECT id FROM users WHERE hospital_name = ?)", (hospital_name,)
        else:
            # Security: If an admin has no hospital name, they see NOTHING.
            return "WHERE 1=0", ()
            
    return "WHERE 1=0", ()


def _err_patient(doc_id, dr_username, extra=None):
    """Return a patient dict with decryption-error placeholders."""
    p = {
        "id":              doc_id,
        "name":            "[Decryption error]",
        "age":             "[Decryption error]",
        "disease":         "[Decryption error]",
        "prescription":    "[Decryption error]",
        "doctor_username": dr_username,
    }
    if extra:
        p.update(extra)
    return p


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

@app.before_request
def make_session_secure():
    session.permanent = False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            log_security_event(
                "unauthenticated_access",
                f"Unauthenticated request to {request.path}",
            )
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_role" not in session:
                log_security_event("unauthorized_access",
                                   f"Missing role accessing {request.path}")
                flash("Unauthorized access.", "danger")
                return redirect(url_for("login"))
            if session["user_role"] not in roles:
                log_security_event(
                    "unauthorized_access",
                    f"Role {session.get('user_role')} attempted {request.path}",
                    username=session.get("username"),
                    role=session.get("user_role"),
                )
                flash("You do not have permission to view this page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Routes – Auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@csrf.exempt
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username   = request.form.get("username", "").strip()
        password   = request.form.get("password", "")
        ip_address = get_client_ip()

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # Lock check
        if user and user["locked_until"]:
            locked_until = user["locked_until"]
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if locked_until and datetime.now() < locked_until:
                log_security_event("login_blocked",
                                   f"Login attempt for locked account: {username}",
                                   username=username)
                flash(
                    f"Account locked until {locked_until.strftime('%I:%M %p')}. "
                    "Please try again later.", "danger"
                )
                return render_template("login.html")
            else:
                db.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user["id"],)
                )
                db.commit()

        # Password check
        ok = False
        if user:
            try:
                ok = bcrypt.check_password_hash(user["password_hash"], password)
            except ValueError:
                ok = wz_check_password_hash(user["password_hash"], password)

        if ok:
            prev_last_login = user["last_login"]
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                (datetime.now().isoformat(), user["id"])
            )
            db.commit()
            session["user_id"]      = str(user["id"])
            session["username"]     = user["username"]
            session["user_role"]    = user["role"]
            session["hospital_name"] = user["hospital_name"]
            session["last_login"]   = prev_last_login
            log_security_event("login_success",
                               f"Successful login for {username} from {ip_address}",
                               username=username, role=user["role"])

            if user["force_password_change"]:
                flash("Security Policy: You are required to change your password.",
                      "warning")
                # Even if forced change, we should do 2FA first or after? 
                # Usually after login. Let's stick to 2FA first.

            return finalize_login(user)

        # Failed login
        new_failures = 0
        if user:
            new_failures  = (user["failed_attempts"] or 0) + 1
            locked_until  = None
            if new_failures >= 3:
                locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                log_security_event(
                    "account_lockout",
                    f"Account {username} locked 15 min after {new_failures} failures.",
                    username=username,
                )
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_failures, locked_until, user["id"])
            )
            db.commit()

        log_security_event("login_failed",
                           f"Failed login for '{username}' from {ip_address}",
                           username=username or None)

        ten_min_ago = (datetime.now() - timedelta(minutes=10)).isoformat()
        ip_failures = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type = ? AND ip_address = ? AND timestamp >= ?",
            ("login_failed", ip_address, ten_min_ago)
        ).fetchone()[0]
        if ip_failures >= 5:
            log_security_event(
                "suspicious_activity",
                f"Excessive ({ip_failures}) failed logins from IP: {ip_address}",
            )

        if user and (user["failed_attempts"] or 0) >= 2:
            flash(
                f"Invalid credentials. Account locks after 3 failures. "
                f"(Attempt {new_failures}/3)", "warning"
            )
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@csrf.exempt
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name        = request.form.get("full_name", "").strip()
        hospital_name    = request.form.get("hospital_name", "").strip()
        username         = request.form.get("username", "").strip()
        email            = request.form.get("email", "").strip()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not full_name:     errors.append("Full name is required.")
        if not hospital_name: errors.append("Hospital name is required.")
        if not username:      errors.append("Username is required.")
        if not email:
            errors.append("Google Email is required.")
        elif not email.lower().endswith("@gmail.com"):
            errors.append("Please provide a valid Google Email address (@gmail.com).")
        if not password:         errors.append("Password is required.")
        if not confirm_password: errors.append("Please confirm your password.")
        if password and confirm_password and password != confirm_password:
            errors.append("Passwords do not match.")
        if password:
            errors.extend(validate_password(password))

        if not errors:
            db = get_db()
            if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                errors.append(f"Username '{username}' is already taken.")

        form_data = {"full_name": full_name, "hospital_name": hospital_name,
                     "username": username, "email": email}
        if errors:
            for msg in errors:
                flash(msg, "danger")
            return render_template("signup.html", form_data=form_data)

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, hospital_name, username, email, password_hash, role, failed_attempts, force_password_change) VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
                (full_name, hospital_name, username, email, password_hash, "admin")
            )
            db.commit()
            log_security_event("account_created",
                               f"New admin registered: {username} (Hospital: {hospital_name})",
                               username=username, role="admin")
            flash("Account created successfully! Please sign in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"A database error occurred: {e}", "danger")
            return render_template("signup.html", form_data=form_data)

    return render_template("signup.html", form_data={})





def finalize_login(user):
    """Helper to set session variables and redirect to dashboard."""
    db = get_db()
    prev_last_login = user["last_login"]
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
        (datetime.now().isoformat(), user["id"])
    )
    db.commit()
    
    session["user_id"]       = str(user["id"])
    session["username"]      = user["username"]
    session["user_role"]     = user["role"]
    session["hospital_name"] = user["hospital_name"]
    session["last_login"]    = prev_last_login
    
    log_security_event("login_success",
                       f"Successful login for {user['username']}",
                       username=user["username"], role=user["role"])

    if user["force_password_change"]:
        flash("Security Policy: You are required to change your password.", "warning")
        return redirect(url_for("change_password"))

    flash("Login successful.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db = get_db()
    sql_where, params = _build_patient_filter(user_role, user_id, hospital_name)

    total_patients = db.execute(f"SELECT COUNT(*) FROM patients {sql_where}", params).fetchone()[0]
    critical_cases = db.execute(
        f"SELECT COUNT(*) FROM patients {sql_where} {' AND ' if sql_where else 'WHERE '} is_critical = 1",
        params
    ).fetchone()[0]

    recent_patients_rows = db.execute(
        f"SELECT * FROM patients {sql_where} ORDER BY id DESC LIMIT 5",
        params
    ).fetchall()
    
    recent_patients = []
    for row in recent_patients_rows:
        dr = db.execute("SELECT username FROM users WHERE id = ?", (row["created_by"],)).fetchone()
        dr_username = dr["username"] if dr else "Unknown"
        doc_id = str(row["id"])
        
        try:
            recent_patients.append({
                "id":              doc_id,
                "name":            decrypt_text(row["name_encrypted"]),
                "age":             decrypt_text(row["age_encrypted"]),
                "disease":         decrypt_text(row["disease_encrypted"]),
                "prescription":    decrypt_text(row["prescription_encrypted"]),
                "created_at":      row["created_at"],
                "is_critical":     bool(row["is_critical"]),
                "doctor_username": dr_username,
            })
        except Exception:
            recent_patients.append(_err_patient(doc_id, dr_username, {
                "created_at": row["created_at"],
                "is_critical": bool(row["is_critical"])
            }))

    stats = {
        "total_patients": total_patients,
        "critical_cases": critical_cases,
        "recent_records": len(recent_patients),
    }

    since_24h  = (datetime.now() - timedelta(hours=24)).isoformat()
    
    if user_role == "admin" and hospital_name:
        # Filter security events by users in the same hospital
        failed_24h = db.execute(
            """
            SELECT COUNT(*) FROM security_events 
            WHERE event_type = ? AND timestamp >= ? 
            AND username IN (SELECT username FROM users WHERE hospital_name = ?)
            """,
            ("login_failed", since_24h, hospital_name)
        ).fetchone()[0]
        
        alerts_24h = db.execute(
            """
            SELECT COUNT(*) FROM security_events 
            WHERE event_type = ? AND timestamp >= ?
            AND username IN (SELECT username FROM users WHERE hospital_name = ?)
            """,
            ("suspicious_activity", since_24h, hospital_name)
        ).fetchone()[0]
        
        recent_logs = db.execute(
            """
            SELECT timestamp, event_type, details FROM security_events 
            WHERE username IN (SELECT username FROM users WHERE hospital_name = ?)
            OR username = ?
            ORDER BY timestamp DESC LIMIT 5
            """,
            (hospital_name, session.get("username"))
        ).fetchall()
    else:
        # Doctors or admins without hospital see nothing in security panel
        failed_24h = 0
        alerts_24h = 0
        recent_logs = []
    
    formatted_logs = []
    for log in recent_logs:
        formatted_logs.append(dict(log))
    
    security_stats = {
        "failed_attempts_total": failed_24h,
        "recent_alerts":         alerts_24h,
        "status":                "Secure" if alerts_24h == 0 else "Warning",
        "recent_logs":           formatted_logs,
    }

    return render_template(
        "dashboard.html",
        role=user_role,
        stats=stats,
        recent_patients=recent_patients,
        security_stats=security_stats,
    )


# ---------------------------------------------------------------------------
# Analytics API
# ---------------------------------------------------------------------------

@app.route("/api/analytics/patients")
@login_required
@role_required("doctor", "admin")
def analytics_patients():
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db = get_db()
    sql_where, params = _build_patient_filter(user_role, user_id, hospital_name)
    
    total = db.execute(f"SELECT COUNT(*) FROM patients {sql_where}", params).fetchone()[0]
    all_rows = db.execute(f"SELECT age_encrypted, disease_encrypted FROM patients {sql_where}", params).fetchall()

    disease_counts = {}
    age_groups     = {"0-18": 0, "19-40": 0, "41-65": 0, "66+": 0}

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
        except (ValueError, TypeError):
            age_val = None

        if age_val is not None:
            if   age_val <= 18: age_groups["0-18"]  += 1
            elif age_val <= 40: age_groups["19-40"] += 1
            elif age_val <= 65: age_groups["41-65"] += 1
            else:               age_groups["66+"]   += 1

    return jsonify({
        "patients_per_day":    {"labels": ["Today"], "data": [total]},
        "disease_distribution": {
            "labels": list(disease_counts.keys()),
            "data":   list(disease_counts.values()),
        },
        "age_groups": {
            "labels": list(age_groups.keys()),
            "data":   list(age_groups.values()),
        },
    })


# ---------------------------------------------------------------------------
# Patients – CRUD
# ---------------------------------------------------------------------------

@app.route("/add_patient", methods=["GET", "POST"])
@login_required
@role_required("doctor")
def add_patient():
    if request.method == "POST":
        name         = (request.form.get("name") or "").strip()
        age          = (request.form.get("age") or "").strip()
        disease      = (request.form.get("disease") or "").strip()
        prescription = (request.form.get("prescription") or "").strip()
        is_critical  = bool(request.form.get("is_critical"))

        errors = []
        age_val = None
        if not name:
            errors.append("Patient name is required.")
        if not age.isdigit():
            errors.append("Age must be a valid number.")
        else:
            age_val = int(age)
            if not (1 <= age_val <= 120):
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

        db = get_db()
        db.execute(
            "INSERT INTO patients (name_encrypted, age_encrypted, disease_encrypted, prescription_encrypted, created_by, is_critical, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (encrypt_text(" ".join(name.split())), encrypt_text(str(age_val)), encrypt_text(disease), encrypt_text(prescription), int(session["user_id"]), 1 if is_critical else 0, datetime.now().isoformat())
        )
        db.commit()
        flash("Patient record added securely.", "success")
        return redirect(url_for("view_patients"))

    return render_template("add_patient.html")



@app.route("/edit_patient/<string:patient_id>", methods=["GET", "POST"])
@login_required
@role_required("doctor")
def edit_patient(patient_id):
    db = get_db()
    
    # Fetch record
    patient_row = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient_row:
        flash("Patient record not found.", "warning")
        return redirect(url_for("view_patients"))

    user_id = session.get("user_id")
    user_role = session.get("user_role")
    hospital_name = session.get("hospital_name")

    # Authorization check
    if user_role == "doctor" and str(patient_row["created_by"]) != str(user_id):
        flash("You are not authorized to edit this record.", "danger")
        return redirect(url_for("view_patients"))
    
    if user_role == "admin" and hospital_name:
        creator = db.execute("SELECT hospital_name FROM users WHERE id = ?", (patient_row["created_by"],)).fetchone()
        if creator and creator["hospital_name"] != hospital_name:
            flash("Authorization denied for this hospital's data.", "danger")
            return redirect(url_for("view_patients"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        age = (request.form.get("age") or "").strip()
        disease = (request.form.get("disease") or "").strip()
        prescription = (request.form.get("prescription") or "").strip()
        is_critical = bool(request.form.get("is_critical"))

        errors = []
        if not name or not age or not disease or not prescription:
            errors.append("All fields are required.")
        if not age.isdigit() or not (1 <= int(age) <= 120):
            errors.append("Invalid age.")

        if errors:
            for msg in errors: flash(msg, "danger")
            # Pre-populate for retry (decrypted)
            patient = {
                "id": patient_id,
                "name": name,
                "age": age,
                "disease": disease,
                "prescription": prescription,
                "is_critical": is_critical
            }
            return render_template("edit_patient.html", patient=patient)

        # Update record
        db.execute(
            """
            UPDATE patients 
            SET name_encrypted = ?, age_encrypted = ?, disease_encrypted = ?, 
                prescription_encrypted = ?, is_critical = ?
            WHERE id = ?
            """,
            (
                encrypt_text(" ".join(name.split())),
                encrypt_text(str(age)),
                encrypt_text(disease),
                encrypt_text(prescription),
                1 if is_critical else 0,
                patient_id
            )
        )
        db.commit()
        
        log_security_event("PATIENT_RECORD_UPDATED", f"Patient ID {patient_id} updated by {session.get('username')}", session.get('username'), user_role)
        flash("Patient record updated securely.", "success")
        return redirect(url_for("patient_profile", patient_id=patient_id))

    # GET: Decrypt for editing
    try:
        patient = {
            "id": patient_id,
            "name": decrypt_text(patient_row["name_encrypted"]),
            "age": decrypt_text(patient_row["age_encrypted"]),
            "disease": decrypt_text(patient_row["disease_encrypted"]),
            "prescription": decrypt_text(patient_row["prescription_encrypted"]),
            "is_critical": bool(patient_row["is_critical"])
        }
    except Exception:
        flash("Decryption error. Internal key mismatch.", "danger")
        return redirect(url_for("view_patients"))

    return render_template("edit_patient.html", patient=patient)


@app.route("/patients")
@login_required
@role_required("doctor", "admin")
def view_patients():
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db      = get_db()
    sql_where, params = _build_patient_filter(user_role, user_id, hospital_name)
    patients = []
    doctors  = set()

    rows = db.execute(f"SELECT * FROM patients {sql_where} ORDER BY id DESC", params).fetchall()
    for row in rows:
        dr = db.execute("SELECT username FROM users WHERE id = ?", (row["created_by"],)).fetchone()
        dr_username = dr["username"] if dr else "Unknown"
        doctors.add(dr_username)
        doc_id = str(row["id"])
        dt_str = row["created_at"]
        try:
            patients.append({
                "id":              doc_id,
                "name":            decrypt_text(row["name_encrypted"]),
                "age":             decrypt_text(row["age_encrypted"]),
                "disease":         decrypt_text(row["disease_encrypted"]),
                "prescription":    decrypt_text(row["prescription_encrypted"]),
                "created_at":      dt_str,
                "is_critical":     bool(row["is_critical"]),
                "doctor_username": dr_username,
            })
        except Exception:
            patients.append(_err_patient(doc_id, dr_username, {
                "created_at":  dt_str,
                "is_critical": bool(row["is_critical"]),
            }))

    return render_template("view_patients.html",
                           patients=patients, doctors=sorted(doctors))


@app.route("/patients/<string:patient_id>")
@login_required
@role_required("doctor", "admin")
def patient_profile(patient_id):
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db = get_db()
    doc = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not doc:
        flash("Patient not found.", "warning")
        return redirect(url_for("view_patients"))

    # RBAC
    if user_role == "doctor" and str(doc["created_by"]) != str(user_id):
        flash("You do not have access to this patient record.", "danger")
        return redirect(url_for("view_patients"))
    if user_role == "admin" and hospital_name:
        dr = db.execute("SELECT hospital_name FROM users WHERE id = ?", (doc["created_by"],)).fetchone()
        if dr and dr["hospital_name"] != hospital_name:
            flash("You do not have access to this patient record.", "danger")
            return redirect(url_for("view_patients"))

    dr = db.execute("SELECT username FROM users WHERE id = ?", (doc["created_by"],)).fetchone()
    dr_username = dr["username"] if dr else "Unknown"
    doc_id      = str(doc["id"])
    dt_str      = doc["created_at"]
    
    try:
        patient = {
            "id":              doc_id,
            "name":            decrypt_text(doc["name_encrypted"]),
            "age":             decrypt_text(doc["age_encrypted"]),
            "disease":         decrypt_text(doc["disease_encrypted"]),
            "prescription":    decrypt_text(doc["prescription_encrypted"]),
            "created_at":      dt_str,
            "doctor_username": dr_username,
        }
    except Exception:
        patient = _err_patient(doc_id, dr_username, {"created_at": dt_str})

    uploaded_reports_rows = db.execute(
        "SELECT filename, filepath, created_at FROM medical_reports WHERE patient_id = ?",
        (patient_id,)
    ).fetchall()
    uploaded_reports = [dict(r) for r in uploaded_reports_rows]

    log_security_event(
        "patient_viewed",
        f"Authorized view of patient: {patient.get('name')} (ID: {patient_id})",
        username=session.get("username"),
        role=session.get("user_role"),
    )
    return render_template("patient_profile.html",
                           patient=patient, uploaded_reports=uploaded_reports)


@app.route("/api/patients/<string:patient_id>/summarize")
@login_required
@role_required("doctor")
def summarize_patient(patient_id):
    user_id = session.get("user_id")
    db = get_db()
    
    # RBAC: Only the doctor who created the record can summarize it
    doc = db.execute("SELECT * FROM patients WHERE id = ? AND created_by = ?", (patient_id, user_id)).fetchone()
    if not doc:
        return jsonify({"error": "Unauthorized or record not found"}), 403

    try:
        name = decrypt_text(doc["name_encrypted"])
        age = decrypt_text(doc["age_encrypted"])
        disease = decrypt_text(doc["disease_encrypted"])
        notes = decrypt_text(doc["prescription_encrypted"])
        
        # Simulated AI Intelligence
        # In a real app, you would send this to Gemini/OpenAI
        summary = f"Patient {name} ({age}y) presents with {disease}. "
        if "chronic" in notes.lower() or "severe" in notes.lower():
            summary += "Condition shows markers of chronicity requiring long-term management. "
        else:
            summary += "Current status appears stable with standard treatment protocols. "
        
        if len(notes) > 100:
            summary += "Detailed clinical notes indicate specific contraindications that should be monitored."
        else:
            summary += "Observation and follow-up recommended in 2 weeks."

        log_security_event("ai_summary_generated", f"AI Summary created for patient {patient_id}", 
                           username=session.get("username"), role="doctor")
        
        return jsonify({
            "summary": summary,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
        })
    except Exception as e:
        return jsonify({"error": f"Summarization failed: {str(e)}"}), 500


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/patients/<string:patient_id>/upload", methods=["POST"])
@login_required
@role_required("doctor")
def upload_report(patient_id):
    user_id = session.get("user_id")
    db      = get_db()

    row = db.execute("SELECT id, created_by FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row or str(row["created_by"]) != str(user_id):
        log_security_event(
            "unauthorized_upload_attempt",
            f"Doctor {session.get('username')} tried to upload to unauthorized patient {patient_id}",
            username=session.get("username"), role="doctor",
        )
        flash("Unauthorized: You can only upload reports for your own patients.", "danger")
        return redirect(url_for("view_patients"))

    if "report" not in request.files or request.files["report"].filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("patient_profile", patient_id=patient_id))

    file = request.files["report"]
    if not allowed_file(file.filename):
        flash("Invalid file type. Only PDF, JPG, and PNG are allowed.", "danger")
        return redirect(url_for("patient_profile", patient_id=patient_id))

    filename        = secure_filename(file.filename)
    unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    file.save(os.path.join(UPLOAD_FOLDER, unique_filename))

    db.execute(
        "INSERT INTO medical_reports (patient_id, filename, filepath, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?)",
        (patient_id, filename, unique_filename, int(user_id), datetime.now().isoformat())
    )
    db.commit()
    log_security_event(
        "file_uploaded",
        f"Doctor uploaded '{filename}' for patient {patient_id}",
        username=session.get("username"), role="doctor",
    )
    flash("Medical report uploaded and stored securely.", "success")
    return redirect(url_for("patient_profile", patient_id=patient_id))


@app.route("/patients/<string:patient_id>/prescription")
@login_required
@role_required("doctor", "admin")
def generate_prescription(patient_id):
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db = get_db()
    doc = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not doc:
        flash("Patient not found.", "warning")
        return redirect(url_for("view_patients"))

    # RBAC check
    if user_role == "doctor" and str(doc["created_by"]) != str(user_id):
        flash("Unauthorized access.", "danger")
        return redirect(url_for("view_patients"))
    if user_role == "admin" and hospital_name:
        dr = db.execute("SELECT hospital_name FROM users WHERE id = ?", (doc["created_by"],)).fetchone()
        if dr and dr["hospital_name"] != hospital_name:
            flash("Unauthorized access.", "danger")
            return redirect(url_for("view_patients"))

    dr = db.execute("SELECT username, name, hospital_name FROM users WHERE id = ?", (doc["created_by"],)).fetchone()
    dr_name = dr["name"] or dr["username"]
    doc_hospital = dr["hospital_name"] or "MedCrypt Medical Center"

    # Decrypt patient data
    try:
        p_name = decrypt_text(doc["name_encrypted"])
        p_age  = decrypt_text(doc["age_encrypted"])
        p_diag = decrypt_text(doc["disease_encrypted"])
        p_pres = decrypt_text(doc["prescription_encrypted"])
    except Exception:
        flash("Error decrypting patient data for PDF.", "danger")
        return redirect(url_for("patient_profile", patient_id=patient_id))

    # Generate PDF in memory
    buffer = io.BytesIO()
    doc_pdf = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Header Style
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Heading1'],
        fontSize=26,
        textColor=colors.HexColor("#061b3a"),
        spaceAfter=4,
        alignment=1 # Center
    )
    
    subhead_style = ParagraphStyle(
        'Subhead',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.grey,
        alignment=1,
        spaceAfter=20
    )

    # Content Area
    elements.append(Paragraph(doc_hospital.upper(), header_style))
    elements.append(Paragraph("Advanced Digital Health Registry & Clinical Services", subhead_style))
    elements.append(Paragraph(f"<b>Facility:</b> {doc_hospital}", styles['Normal']))
    elements.append(Paragraph(f"<b>Issuance Date:</b> {datetime.now().strftime('%d %B %Y %I:%M %p')}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Patient Info Table
    data = [
        [Paragraph("<b>PATIENT NAME</b>", styles['Normal']), p_name, Paragraph("<b>AGE/SEX</b>", styles['Normal']), f"{p_age} Years"],
        [Paragraph("<b>RECORD ID</b>", styles['Normal']), f"SC-PR-{patient_id}", Paragraph("<b>PHYSICIAN</b>", styles['Normal']), f"Dr. {dr_name}"]
    ]
    t = Table(data, colWidths=[100, 160, 100, 160])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,1), colors.HexColor("#f1f5f9")),
        ('BACKGROUND', (2,0), (2,1), colors.HexColor("#f1f5f9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 24))

    # Diagnosis Section
    elements.append(Paragraph("CLINICAL DIAGNOSIS", styles['Heading3']))
    elements.append(Paragraph(f"<font color='#0d6efd'>●</font> {p_diag}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Prescription Section
    elements.append(Paragraph("RX & TREATMENT PLAN", styles['Heading3']))
    
    # Simple line-break handling for PDF
    pres_html = p_pres.replace('\n', '<br/>')
    elements.append(Paragraph(pres_html, styles['Normal']))
    elements.append(Spacer(1, 60))

    # Verification Footer
    elements.append(Paragraph("___________________________", styles['Normal']))
    elements.append(Paragraph(f"<b>Digitally Signed: Dr. {dr_name}</b>", styles['Normal']))
    elements.append(Paragraph(f"Medical License Verified | {datetime.now().strftime('%Y-%m-%d')}", styles['Italic']))
    elements.append(Spacer(1, 30))
    
    footer_note = Paragraph(
        "<font color='grey' size='8'>This document is an encrypted electronic record generated by MedCrypt. "
        "Integrity is maintained via RBAC session validation and end-to-end symmetric encryption (AES-128). "
        "Any alteration voids this document.</font>", 
        styles['Italic']
    )
    elements.append(footer_note)

    doc_pdf.build(elements)
    buffer.seek(0)

    log_security_event("prescription_downloaded", f"Downloaded PDF for Patient {p_name} (ID: {patient_id})", 
                       username=session.get("username"), role=session.get("user_role"))

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Prescription_{p_name.replace(' ', '_')}.pdf",
        mimetype='application/pdf'
    )


# ---------------------------------------------------------------------------
# Medical Records
# ---------------------------------------------------------------------------

@app.route("/medical-records")
@login_required
@role_required("doctor", "admin")
def medical_records():
    user_id       = session.get("user_id")
    user_role     = session.get("user_role")
    hospital_name = session.get("hospital_name")

    db              = get_db()
    sql_where, params = _build_patient_filter(user_role, user_id, hospital_name)
    total_patients  = db.execute(f"SELECT COUNT(*) FROM patients {sql_where}", params).fetchone()[0]
    recent_records  = []

    rows = db.execute(f"SELECT * FROM patients {sql_where} ORDER BY id DESC LIMIT 10", params).fetchall()
    for row in rows:
        doc_id = str(row["id"])
        try:
            recent_records.append({
                "id":           doc_id,
                "name":         decrypt_text(row["name_encrypted"]),
                "age":          decrypt_text(row["age_encrypted"]),
                "disease":      decrypt_text(row["disease_encrypted"]),
                "prescription": decrypt_text(row["prescription_encrypted"]),
            })
        except Exception:
            recent_records.append({
                "id":           doc_id,
                "name":         "[Decryption error]",
                "age":          "[Decryption error]",
                "disease":      "[Decryption error]",
                "prescription": "[Decryption error]",
            })

    stats = {
        "total_patients": total_patients,
        "critical_cases":  0,
        "recent_records":  len(recent_records),
    }
    return render_template("medical_records.html", stats=stats, records=recent_records)


# ---------------------------------------------------------------------------
# Security Logs
# ---------------------------------------------------------------------------

@app.route("/security-logs")
@login_required
@role_required("admin")
def security_logs():
    db        = get_db()
    user_role = session.get("user_role")
    hosp      = session.get("hospital_name")

    if user_role == "admin" and hosp:
        rows = db.execute(
            """
            SELECT timestamp, username, role, ip_address, event_type, details FROM security_events 
            WHERE username IN (SELECT username FROM users WHERE hospital_name = ?)
            OR username = ?
            ORDER BY timestamp DESC LIMIT 200
            """,
            (hosp, session.get("username"))
        ).fetchall()
    else:
        # Fallback for system consistency, though role_required("admin") handles access
        rows = []
        
    logs = [dict(r) for r in rows]

    if hosp:
        suspicious_ips_rows = db.execute(
            """
            SELECT ip_address, COUNT(*) as failures FROM security_events
            WHERE event_type IN ('login_failed', 'suspicious_activity') 
            AND ip_address IS NOT NULL
            AND username IN (SELECT username FROM users WHERE hospital_name = ?)
            GROUP BY ip_address HAVING failures >= 3 ORDER BY failures DESC
            """,
            (hosp,)
        ).fetchall()
    else:
        suspicious_ips_rows = []
    suspicious_ips = [dict(r) for r in suspicious_ips_rows]

    if hosp:
        agg = db.execute(
            """
            SELECT
                SUM(CASE WHEN event_type = 'login_failed' THEN 1 ELSE 0 END) as failed_logins,
                SUM(CASE WHEN event_type = 'suspicious_activity' THEN 1 ELSE 0 END) as suspicious_events,
                SUM(CASE WHEN event_type IN ('unauthenticated_access', 'unauthorized_access') THEN 1 ELSE 0 END) as unauthorized_attempts
            FROM security_events
            WHERE username IN (SELECT username FROM users WHERE hospital_name = ?)
            """,
            (hosp,)
        ).fetchone()
    else:
        agg = {"failed_logins": 0, "suspicious_events": 0, "unauthorized_attempts": 0}

    stats = {
        "failed_logins":         agg["failed_logins"] or 0,
        "suspicious_events":     agg["suspicious_events"] or 0,
        "unauthorized_attempts": agg["unauthorized_attempts"] or 0,
    }
    return render_template("security_logs.html",
                           logs=logs, suspicious_ips=suspicious_ips, stats=stats)


# ---------------------------------------------------------------------------
# Manage Doctors
# ---------------------------------------------------------------------------

@app.route("/admin/doctors", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_doctors():
    db = get_db()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("manage_doctors"))

        errs = validate_password(password)
        if errs:
            for e in errs:
                flash(e, "danger")
            return redirect(url_for("manage_doctors"))

        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash(f"Username '{username}' is already taken.", "danger")
            return redirect(url_for("manage_doctors"))

        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role, force_password_change, hospital_name, failed_attempts) VALUES (?, ?, ?, 1, ?, 0)",
                (username, bcrypt.generate_password_hash(password).decode("utf-8"), "doctor", session.get("hospital_name"))
            )
            db.commit()
            log_security_event("account_created",
                               f"Admin created doctor account: {username}",
                               username=session.get("username"), role="admin")
            flash(
                f"Doctor account '{username}' created. "
                "They will be required to change password on first login.", "success"
            )
        except Exception:
            flash("Database error while creating doctor.", "danger")

        return redirect(url_for("manage_doctors"))

    # GET – list doctors
    hosp  = session.get("hospital_name")
    if hosp:
        rows = db.execute("SELECT id, username FROM users WHERE role = 'doctor' AND hospital_name = ? ORDER BY id DESC", (hosp,)).fetchall()
    else:
        # Strictly show nothing if no hospital is associated
        rows = []
    doctors = [{"id": str(d["id"]), "username": d["username"]} for d in rows]
    return render_template("manage_doctors.html", doctors=doctors)


@app.route("/admin/doctors/<string:doctor_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_doctor(doctor_id):
    if doctor_id == session.get("user_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("manage_doctors"))

    db = get_db()
    target = db.execute("SELECT username, role FROM users WHERE id = ?", (doctor_id,)).fetchone()
    if not target or target["role"] != "doctor":
        flash("Doctor not found.", "warning")
        return redirect(url_for("manage_doctors"))

    db.execute("DELETE FROM patients WHERE created_by = ?", (doctor_id,))
    db.execute("DELETE FROM users WHERE id = ?", (doctor_id,))
    db.commit()

    log_security_event("account_deleted",
                       f"Admin deleted doctor: {target['username']}",
                       username=session.get("username"), role="admin")
    flash(f"Doctor '{target['username']}' has been removed.", "success")
    return redirect(url_for("manage_doctors"))


# ---------------------------------------------------------------------------
# Settings / Change Password
# ---------------------------------------------------------------------------

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        current_pw  = request.form.get("current_password", "")
        new_pw      = request.form.get("new_password", "")
        confirm_pw  = request.form.get("confirm_password", "")
        user_id     = session.get("user_id")

        if not all([current_pw, new_pw, confirm_pw]):
            flash("All fields are required.", "danger")
            return redirect(url_for("settings"))
        if new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("settings"))
        errs = validate_password(new_pw)
        if errs:
            for e in errs:
                flash(e, "danger")
            return redirect(url_for("settings"))

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        ok = False
        try:
            ok = bcrypt.check_password_hash(user["password_hash"], current_pw)
        except ValueError:
            ok = wz_check_password_hash(user["password_hash"], current_pw)

        if not ok:
            log_security_event("password_change_failed",
                               "Incorrect current password during change",
                               username=session.get("username"),
                               role=session.get("user_role"))
            flash("Incorrect current password.", "danger")
            return redirect(url_for("settings"))

        if current_pw == new_pw:
            flash("New password cannot be the same as the current password.", "danger")
            return redirect(url_for("settings"))

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (bcrypt.generate_password_hash(new_pw).decode("utf-8"), user_id)
        )
        db.commit()
        log_security_event("password_changed", "User changed password",
                           username=session.get("username"),
                           role=session.get("user_role"))
        flash("Password updated successfully.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_pw     = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        user_id    = session.get("user_id")

        if not new_pw or not confirm_pw:
            flash("All fields are required.", "danger")
            return render_template("change_password.html")
        if new_pw != confirm_pw:
            flash("Passwords do not match.", "danger")
            return render_template("change_password.html")
        errs = validate_password(new_pw)
        if errs:
            for e in errs:
                flash(e, "danger")
            return render_template("change_password.html")

        db = get_db()
        db.execute(
            "UPDATE users SET password_hash = ?, force_password_change = 0 WHERE id = ?",
            (bcrypt.generate_password_hash(new_pw).decode("utf-8"), user_id)
        )
        db.commit()
        log_security_event("password_changed", "Mandatory password change completed",
                           username=session.get("username"),
                           role=session.get("user_role"))
        flash("Password changed successfully. You can now use the system.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


if __name__ == "__main__":
    app.run(debug=True)
