# 🏥 Secure Healthcare Data Sharing System

[![Security: AES-128](https://img.shields.io/badge/Security-AES--128-blue.svg)](https://cryptography.io/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Database: SQLite](https://img.shields.io/badge/Database-SQLite-003B57.svg)](https://www.sqlite.org/)

A production-ready, security-hardened healthcare platform designed to bridge the gap between medical efficiency and patient data privacy. Built with a "Security-First" philosophy, this system ensures that sensitive medical records are protected by industry-standard encryption and governed by strict access controls.

---

## 🌟 Key Highlights

- **End-to-End Privacy**: All sensitive patient data is encrypted locally before hitting the database.
- **Audit-Ready**: Every action leaves a digital footprint in the security console.
- **Modern UI**: A premium, responsive dashboard designed for clinical environments.
- **Resilient**: Protects against common web vulnerabilities (XSS, CSRF, Brute Force).

---

## 🔐 The "A to Z" Security Blueprint

### A. Authentication & Identity
- **Multi-Role Support**: Distinguishes between `Admin` (Security/Ops) and `Doctor` (Clinical) roles.
- **Secure Hashing**: Passwords never touch the database in plain text; we use `Bcrypt` with a unique salt for every user.
- **Account Protection**: Automatic 15-minute lockouts after 3 failed attempts to thwart automated brute-force attacks.

### B. Encryption at Rest
- **Fernet (AES-128)**: Utilizes symmetric encryption to wrap patient names, ages, and medical notes. 
- **Vault Management**: A system-generated `.secret.key` acts as the master key. Without it, the `healthcare.db` file is just a collection of gibberish.

### C. Role-Based Access Control (RBAC)
- **Clinical Isolation**: Doctors can only manage and view patients they are specifically assigned to.
- **Administrative Oversight**: Admins cannot see patient medical notes but have full visibility into system health and security logs.

### D. File Security
- **Sandboxed Uploads**: Patient reports are renamed with unique, non-guessable timestamps to prevent "Direct Object Reference" (IDOR) vulnerabilities.
- **Type Validation**: Only verified medical document types (`.pdf`, `.jpg`, `.png`) are accepted.

---

## 📊 Feature Walkthrough

### 👨‍⚕️ The Doctor's Experience
1. **Dashboard**: High-level view of patient volume and critical cases.
2. **Patient Registry**: A searchable, secondary-encrypted list of records.
3. **Clinical Entry**: Secure form to record diagnoses and prescriptions.
4. **Report Vault**: Upload PDFs or lab images directly to a patient's encrypted profile.

### 🛡️ The Administrator's Command Center
1. **Security Console**: Real-time ticker of system events (logins, unauthorized attempts, etc.).
2. **User Management**: Creating and managing Doctor accounts with "Force Password Change" on first login.
3. **Analytics**: Visual breakdown of hospital demographics and disease trends via Chart.js.

---

## 📁 Project Structure

```text
DSP PROJECT/
├── web/
│   └── secure_healthcare/
│       ├── app.py              # The "Brain": Handles routing, RBAC, and business logic.
│       ├── encryption.py       # The "Shield": Manages the AES encryption engine.
│       ├── healthcare.db       # The "Vault": Encrypted SQLite storage.
│       ├── init_db.py          # The "Architect": Sets up tables and admin accounts.
│       ├── seed_data_v2.py     # The "Generator": Populates demo data for training.
│       ├── static/             # Modern CSS and UI assets.
│       └── templates/          # Jinja2 HTML templates with security headers.
└── README.md                   # You are here!
```

---

## 🚀 Getting Started in 2 Minutes

1. **Initialize the Vault**:
   ```powershell
   python init_db.py
   ```
2. **(Optional) Load Training Data**:
   ```powershell
   python seed_data_v2.py
   ```
3. **Launch the Platform**:
   ```powershell
   python app.py
   ```
4. **Login**:
   - URL: `http://127.0.0.1:5000`
   - Default Admin: `admin` / `password123`
   - Test Doctor: `dr_sharma` / `Sharma@123`

---

## 📜 Compliance & Best Practices
- **Timezone Sync**: All system events are recorded in local time for accurate medical charting (Synced to IST).
- **Session Lifetimes**: Automatic session logout after 30 minutes of inactivity.
- **CSRF Protection**: Every form submission is validated with a unique cryptographic token.

---

> [!IMPORTANT]
> This system is designed for a secure local environment. For cloud deployment, ensure the `.secret.key` is stored in a managed Hardware Security Module (HSM).
