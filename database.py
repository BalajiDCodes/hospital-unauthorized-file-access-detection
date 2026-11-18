import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, 'hospital_access.db')


def get_db_connection(db_path=None):
    """Returns a SQLite connection with dict-like row access."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    """Initializes tables and seeds default demo accounts and synthetic file entries."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # 1. Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            full_name TEXT NOT NULL
        )
    ''')

    # 2. Medical Files Metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            department TEXT NOT NULL,
            file_type TEXT NOT NULL,
            description TEXT
        )
    ''')

    # 3. Security Access Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            requested_file TEXT NOT NULL,
            user_department TEXT NOT NULL,
            required_department TEXT NOT NULL,
            operation TEXT NOT NULL,
            access_result TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')

    # Seed Demo Accounts (using pbkdf2:sha256 for universal compatibility)
    demo_users = [
        (
            'admin',
            generate_password_hash('admin123', method='pbkdf2:sha256'),
            'admin',
            'Administration',
            'System Security Administrator'
        ),
        (
            'cardio_doc',
            generate_password_hash('cardio123', method='pbkdf2:sha256'),
            'doctor',
            'Cardiology',
            'Dr. Suresh Rao (Cardiology)'
        ),
        (
            'radio_doc',
            generate_password_hash('radio123', method='pbkdf2:sha256'),
            'doctor',
            'Radiology',
            'Dr. Kavita Mehta (Radiology)'
        )
    ]

    for username, p_hash, role, dept, full_name in demo_users:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, role, department, full_name)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, p_hash, role, dept, full_name))

    # Seed Synthetic File Metadata
    demo_files = [
        (
            'cardio_patient_101_ecg.txt',
            'Patient 101 - 12-Lead ECG Report',
            'Cardiology',
            'ECG Diagnostic',
            'Sinus rhythm and electro-cardiac parameters'
        ),
        (
            'cardio_patient_102_echo.txt',
            'Patient 102 - Transthoracic Echo Report',
            'Cardiology',
            'Echocardiogram',
            'Left ventricular systolic function and valvular evaluation'
        ),
        (
            'radio_scan_201_mri.txt',
            'Patient 201 - Brain MRI Scan Report',
            'Radiology',
            'Brain MRI',
            'Axial/sagittal T1 and T2 multi-sequence examination'
        ),
        (
            'radio_scan_202_ct.txt',
            'Patient 202 - Chest High-Res CT Report',
            'Radiology',
            'Chest CT',
            'High-resolution non-contrast spiral thoracic imaging'
        ),
        (
            'general_policy_doc.txt',
            'Hospital EMR Data Governance Policy',
            'Administration',
            'Policy Document',
            'Guidelines for patient record isolation and security audits'
        )
    ]

    for filename, display_name, dept, ftype, desc in demo_files:
        cursor.execute('''
            INSERT OR IGNORE INTO files (filename, display_name, department, file_type, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, display_name, dept, ftype, desc))

    conn.commit()
    conn.close()


def get_user_by_username(username, db_path=None):
    """Retrieve user record by username."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_all_users(db_path=None):
    """Retrieve all registered users."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, department, full_name FROM users ORDER BY id ASC')
    users = cursor.fetchall()
    conn.close()
    return users


def get_all_files(db_path=None):
    """Retrieve all synthetic file records."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files ORDER BY department, id ASC')
    files = cursor.fetchall()
    conn.close()
    return files


def get_file_by_name(filename, db_path=None):
    """Retrieve a single file metadata by filename."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE filename = ?', (filename,))
    file_record = cursor.fetchone()
    conn.close()
    return file_record


def log_access_attempt(username, requested_file, user_department, required_department,
                       operation, access_result, reason, db_path=None):
    """Stores an access attempt in the security_logs table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''
        INSERT INTO security_logs (
            username, requested_file, user_department, required_department,
            operation, access_result, reason, timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        username,
        requested_file,
        user_department,
        required_department,
        operation,
        access_result,
        reason,
        timestamp
    ))

    conn.commit()
    conn.close()


def get_security_logs(limit=100, access_filter=None, db_path=None):
    """Fetch security logs with optional filter (GRANTED / DENIED) and row limit."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    if access_filter and access_filter in ('GRANTED', 'DENIED'):
        cursor.execute('''
            SELECT * FROM security_logs
            WHERE access_result = ?
            ORDER BY id DESC
            LIMIT ?
        ''', (access_filter, limit))
    else:
        cursor.execute('''
            SELECT * FROM security_logs
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
    logs = cursor.fetchall()
    conn.close()
    return logs


def get_dashboard_stats(db_path=None):
    """Calculate aggregate counts for dashboard metrics."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM files')
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE access_result = 'GRANTED'")
    authorized_attempts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE access_result = 'DENIED'")
    denied_attempts = cursor.fetchone()[0]

    conn.close()
    return {
        'total_users': total_users,
        'total_files': total_files,
        'authorized_attempts': authorized_attempts,
        'denied_attempts': denied_attempts
    }


if __name__ == '__main__':
    init_db()
    print("Database initialized successfully with demo accounts and files.")
