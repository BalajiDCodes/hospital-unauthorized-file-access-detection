# Hospital Unauthorized File Access Detection System

A lightweight, beginner-to-intermediate individual college mini project built with **Python Flask**, **HTML/CSS**, and **SQLite**.

This system implements **Role & Department-Based Access Control (RBAC)** to protect synthetic electronic medical records (EMRs). It permits medical staff to access only their assigned department's files while instantly intercepting, blocking, and logging any unauthorized cross-department file access attempts.

---

## 🏥 Features & The 4 Core Modules

1. **Module 1: Authentication & Demo Accounts**
   - Session-based authentication with cryptographically secure password hashing (`werkzeug.security`).
   - Three pre-configured demo evaluation accounts:
     - **Admin**: Full oversight across all hospital files and security audit logs.
     - **Cardiology Doctor**: Authorized to access cardiology reports (ECG, Echocardiogram).
     - **Radiology Doctor**: Authorized to access radiology scans (MRI, CT).
   - One-click autofill buttons on the login page for viva and presentation demos.

2. **Module 2: Real-Time Security Dashboard**
   - Displays 4 key metric cards:
     - **Total Users**: Registered clinical and administrative staff.
     - **Medical Files**: Available synthetic patient records.
     - **Authorized Attempts**: Compliant file queries (`GRANTED`).
     - **Denied Attempts**: Security violations intercepted (`DENIED`).
   - Summary of active user's department clearance and a live preview of recent security events.

3. **Module 3: Department-Based File Access Control**
   - Strict isolation of synthetic medical records stored in the dedicated `sample_data/` directory.
   - Users can only read and download records matching their designated department.
   - Cross-department access attempts (e.g. Cardiology doctor attempting to view Radiology MRI scans) are immediately blocked with a **HTTP 403 Security Alert** screen.
   - Built-in **Path Traversal Protection** (`..` sanitization) preventing unauthorized navigation outside the `sample_data/` folder.

4. **Module 4: Security Audit Logging**
   - Every file interaction (both authorized reads and unauthorized violation attempts) is automatically logged to the SQLite database.
   - Stored log attributes:
     - `id`: Unique record identifier
     - `timestamp`: Date and time of attempt
     - `username`: Identity of the querying user
     - `user_department`: Department of the user
     - `requested_file`: Target file requested
     - `required_department`: Department owner of the target file
     - `operation`: Requested operation (`READ` or `DOWNLOAD`)
     - `access_result`: `GRANTED` or `DENIED`
     - `reason`: Diagnostic explanation of the enforcement decision
   - Filterable UI to inspect **All Logs**, **Authorized Only**, or **Denied / Violations**.

---

## 🎨 Design & Technology Stack

- **Backend**: Python 3, Flask, SQLite3, Werkzeug
- **Frontend**: Clean Semantic HTML5 and Vanilla CSS (no internet CDN dependencies required)
- **Color Palette**: Professional Hospital Navy Blue (`#0f2744`), Teal Accent (`#00a896`), and Crisp Neutral White (`#f8fafc`)
- **Storage**: Dedicated `sample_data/` folder for synthetic records only

---

## 📁 Project Structure

```
hospital_access_system/
├── app.py                     # Flask web server, route definitions, and security logic
├── database.py                # SQLite schema setup, helper queries, and demo seed data
├── hospital_access.db         # SQLite database file (auto-generated)
├── requirements.txt           # Python dependencies (Flask, Werkzeug)
├── README.md                  # Project documentation & viva presentation guide
├── .gitignore                 # Standard Python/IDE ignore list
├── .vscode/
│   └── launch.json            # 1-Click debug/run configuration for VS Code
├── sample_data/               # Dedicated synthetic medical files
│   ├── cardio_patient_101_ecg.txt
│   ├── cardio_patient_102_echo.txt
│   ├── radio_scan_201_mri.txt
│   ├── radio_scan_202_ct.txt
│   └── general_policy_doc.txt
├── static/
│   └── css/
│       └── style.css          # Navy blue, teal & white responsive styling
├── templates/
│   ├── base.html              # Base layout with navbar, alerts, and footer
│   ├── login.html             # Login portal with one-click demo credentials
│   ├── dashboard.html         # 4-metric dashboard and activity preview
│   ├── files.html             # Medical records catalog with clearance badges
│   ├── file_view.html         # Secure record viewer for granted requests
│   ├── access_denied.html     # Security alert screen for unauthorized attempts
│   └── logs.html              # Comprehensive security audit trail with filters
└── tests/
    └── test_app.py            # Automated unit tests for all modules
```

---

## 🔑 Demo Evaluation Accounts

| Role / Designation | Username | Password | Department Clearance | Accessible Records |
| :--- | :--- | :--- | :--- | :--- |
| **System Admin** | `admin` | `admin123` | Administration | All files (Cardio, Radio, General) & Full Logs |
| **Cardiology Doctor** | `cardio_doc` | `cardio123` | Cardiology | Cardiology files (`cardio_*`) + General Policy |
| **Radiology Doctor** | `radio_doc` | `radio123` | Radiology | Radiology files (`radio_*`) + General Policy |

*(Note: Clicking on any demo account row on the login page will autofill the credentials automatically).*

---

## 🚀 How to Run the Application

### Option A: Running in VS Code (Recommended)
1. Open the project folder in **Visual Studio Code**.
2. Press **`F5`** or go to the **Run & Debug** panel (left sidebar) and select **"Python: Flask (Hospital Access System)"**.
3. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

### Option B: Running from Terminal / Command Prompt

1. **Open terminal** in the project directory:
   ```bash
   cd /path/to/project
   ```

2. **(Optional) Create and activate a virtual environment**:
   ```bash
   # On macOS / Linux:
   python3 -m venv venv
   source venv/bin/activate

   # On Windows:
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize database & seed demo accounts**:
   ```bash
   python database.py
   ```

5. **Start the Flask web server**:
   ```bash
   python app.py
   ```

6. Open your web browser and visit:
   ```
   http://127.0.0.1:5000
   ```

---

## 🧪 How to Demonstrate the Project in Viva / College Evaluation

Follow these 4 simple steps to demonstrate all modules to your examiner:

1. **Step 1: Successful Department Access**
   - Log in as `cardio_doc` (password: `cardio123`).
   - Go to **Medical Records**.
   - Click **"View Record"** on `cardio_patient_101_ecg.txt`.
   - **Result**: Access is **GRANTED**. The ECG report is displayed in the secure viewer.
   - Notice the **Authorized Attempts** counter increases on the Dashboard.

2. **Step 2: Unauthorized Access Detection (The Core Feature)**
   - While still logged in as `cardio_doc`, go to **Medical Records**.
   - Attempt to click **"View Record"** on `radio_scan_201_mri.txt` (a Radiology scan).
   - **Result**: The system blocks the request with a **HTTP 403 Security Alert Screen**:
     > *"⚠️ SECURITY ALERT: UNAUTHORIZED FILE ACCESS DETECTED"*
     > *"Cardiology personnel cannot view Radiology department records."*

3. **Step 3: Verify Security Audit Logs**
   - Click **"Check Security Logs"** or navigate to **Security Logs** in the navbar.
   - Point out the newly recorded entry:
     - User: `cardio_doc`
     - Requested File: `radio_scan_201_mri.txt`
     - Operation: `READ`
     - Result: `DENIED` (Red Badge)
     - Reason: Cross-department violation.

4. **Step 4: Administrator Clearance**
   - Click **Logout** and log in as `admin` (password: `admin123`).
   - Check the **Dashboard** metrics: Total Users (3), Files (5), Authorized Attempts, and Denied Attempts.
   - View any file (`radio_scan_201_mri.txt` or `cardio_patient_101_ecg.txt`).
   - **Result**: Admin is authorized across all departments.

---

## ⚙️ Running Automated Unit Tests

Automated test cases verify authentication, RBAC boundaries, directory traversal protection, and logging.

Run tests using:
```bash
python -m unittest tests/test_app.py
```
Expected output:
```
.........
----------------------------------------------------------------------
Ran 9 tests in 0.25s

OK
```

---

## 🎓 Frequently Asked Questions (Viva / Examination Prep)

**Q1: How does the system detect unauthorized access?**
> In `app.py`, the `evaluate_access()` function checks the logged-in user's department against the department metadata associated with the requested file in the SQLite database. If they do not match (and the user is not an Admin), access is denied and a `DENIED` record is logged to the `security_logs` table.

**Q2: How are passwords stored securely?**
> Passwords are never stored in plain text. They are hashed using `werkzeug.security.generate_password_hash` using standard PBKDF2/SHA-256 algorithm and validated via `check_password_hash`.

**Q3: How does the system prevent Directory / Path Traversal attacks?**
> The `is_safe_path()` function verifies that the requested filename does not contain parent path indicators (`..`) and uses `os.path.commonpath` to ensure the resolved file path strictly resides within the `sample_data/` directory.

**Q4: Why SQLite and Flask?**
> Flask is lightweight and Pythonic, allowing clean separation of routes and business logic. SQLite is a zero-configuration, serverless, file-based relational database ideal for mini projects and local college evaluations.
