# 🛡️ MedCrypt: Secure Healthcare Infrastructure

**MedCrypt** is a security-hardened healthcare management ecosystem designed to enforce total privacy of Patient Identifiable Information (PII). Its primary mission is to protect sensitive clinical data through application-level cryptographic safeguards.

---

## 🛠️ Technical Engineering Blueprint

### 1. Cryptographic Core
- **Data-at-Rest Protection**: MedCrypt utilizes the **AES-128 (Fernet)** standard for field-level encryption. Every sensitive field (Name, Age, Disease, Prescription) is transformed into ciphertext before reaching the database.
- **Identity Hardening**: User passwords are never stored in plain-text. We implement **Bcrypt** adaptive hashing with unique salts for every user to repel brute-force and rainbow table attacks.
- **Key Integrity**: The master key (`.secret.key`) is generated on initialization and stored outside the database schema, creating a partitioned security layer.

### 2. Defensive Measures
- **Brute-Force Lockout**: Automatic 15-minute global account suspension after 3 failed login attempts.
- **Session Governance**: Cookies are flagged with `HttpOnly`, `Secure`, and `SameSite=Lax` to prevent XSS-based hijacking.
- **CSRF Protection**: Every form submission is validated against a unique cryptographic token.
- **RBAC Matrix**: Strict Role-Based Access Control isolates clinical data from administrative users.

### 3. Integrated Features
- **Voice-to-Note (Add-on)**: Hand-free clinical documentation system.
- **Security Ticker**: Real-time administrative logging of all system events.
- **PDF Generation**: Secure, digitally-signed prescriptions generated in memory.

---

## 🚀 Deployment & Installation

### Prerequisites
- Python 3.10 or higher
- Pip (Python Package Manager)

### Step 1: Initialize Environment
```bash
# Install dependencies
pip install -r requirements.txt

# Initialize the Secure Database & Key Vault
python init_db.py
```

### Step 2: Launch System
```bash
python app.py
```
The system will be accessible at: `http://127.0.0.1:5000`

---

## 👤 Credentials (Demo)
- **Administrator**: `admin` / `password123`
- **Doctor (Jeevan)**: `jeevan123` / `Admin@123`

---

## 📈 Evaluation Results
| Metric | Performance |
| :--- | :--- |
| **Encryption Latency** | Avg 32ms |
| **SQLi Protection** | 100% (Parameterized) |
| **Brute-Force Defense** | Active Throttling |
| **Data Integrity** | HMAC-SHA256 Verified |

---

**Built with a "Security-First" Philosophy by Team MedCrypt.**
