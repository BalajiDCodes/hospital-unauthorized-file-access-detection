import os
from functools import wraps
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_from_directory
)
from werkzeug.security import check_password_hash
from database import (
    init_db,
    get_user_by_username,
    get_all_files,
    get_file_by_name,
    log_access_attempt,
    get_security_logs,
    get_dashboard_stats
)

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'hospital-detection-secret-key-change-in-production'

# Base directory and restricted sample_data directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DATA_DIR = os.path.join(BASE_DIR, 'sample_data')


# ==============================================================================
# Helper Functions & Decorators
# ==============================================================================
def login_required(f):
    """Decorator to protect routes requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def is_safe_path(filename):
    """
    Prevents path traversal attacks (e.g. '../../etc/passwd').
    Ensures that the resolved file stays strictly within SAMPLE_DATA_DIR.
    """
    if not filename:
        return False
    # If raw filename has directory traversal components
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        return False
    target_path = os.path.abspath(os.path.join(SAMPLE_DATA_DIR, filename))
    common_prefix = os.path.commonpath([SAMPLE_DATA_DIR, target_path])
    return common_prefix == SAMPLE_DATA_DIR and os.path.isfile(target_path)


def evaluate_access(user_department, user_role, file_record):
    """
    Enforces Department-Level Access Control Rules:
    1. Admin has supervisory clearance across all hospital files.
    2. Administration files (e.g., policies) are accessible to all authenticated staff.
    3. Clinical staff (Cardiology, Radiology) can only access files of their own department.
    """
    if user_role == 'admin':
        return True, "Administrator clearance granted across all departments."

    file_dept = file_record['department']
    if file_dept == 'Administration':
        return True, "General hospital administration document accessible to all staff."

    if user_department == file_dept:
        return True, f"Department match verified ({user_department} staff accessing {file_dept} record)."

    return False, f"Unauthorized: {user_department} personnel cannot view {file_dept} department records."


# ==============================================================================
# Module 1: Authentication & Session Routes
# ==============================================================================
@app.route('/')
def index():
    """Root redirect."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route with demo account authentication and session establishment."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            # Session assignment
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['department'] = user['department']
            session['full_name'] = user['full_name']

            flash(f'Welcome back, {user["full_name"]} ({user["department"]})!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again or use the demo buttons.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logs out user and clears the current session."""
    username = session.get('username', 'User')
    session.clear()
    flash(f'{username} has been logged out successfully.', 'info')
    return redirect(url_for('login'))


# ==============================================================================
# Module 2: Dashboard Route
# ==============================================================================
@app.route('/dashboard')
@login_required
def dashboard():
    """Displays total users, files, authorized attempts, and denied attempts."""
    stats = get_dashboard_stats()
    recent_logs = get_security_logs(limit=5)
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs)


# ==============================================================================
# Module 3: File Access Control Routes
# ==============================================================================
@app.route('/files')
@login_required
def list_files():
    """Displays list of all synthetic hospital files and clearance status."""
    files = get_all_files()
    return render_template('files.html', files=files)


@app.route('/files/view/<path:filename>')
@login_required
def view_file(filename):
    """
    Attempts to read and view a file.
    Permits own department records and denies cross-department requests.
    All attempts (authorized or denied) are recorded in security logs.
    """
    user_department = session['department']
    user_role = session['role']
    username = session['username']

    # Security check 1: Path Traversal Prevention
    if not is_safe_path(filename):
        log_access_attempt(
            username=username,
            requested_file=filename,
            user_department=user_department,
            required_department='UNKNOWN',
            operation='READ',
            access_result='DENIED',
            reason='Security Alert: Path traversal or invalid file request detected.'
        )
        return render_template(
            'access_denied.html',
            filename=filename,
            target_dept='RESTRICTED',
            reason='Invalid path or unauthorized path traversal detected.',
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ), 403

    # Security check 2: File Metadata Lookup
    file_record = get_file_by_name(filename)
    if not file_record:
        abort(404, description="File record not found in system catalog.")

    # Security check 3: Department-Level Clearance Evaluation
    is_authorized, reason = evaluate_access(user_department, user_role, file_record)

    if is_authorized:
        # Log successful authorized access
        log_access_attempt(
            username=username,
            requested_file=filename,
            user_department=user_department,
            required_department=file_record['department'],
            operation='READ',
            access_result='GRANTED',
            reason=reason
        )

        # Read synthetic content safely
        file_path = os.path.join(SAMPLE_DATA_DIR, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return render_template('file_view.html', file_record=file_record, content=content)
    else:
        # Log unauthorized violation attempt
        log_access_attempt(
            username=username,
            requested_file=filename,
            user_department=user_department,
            required_department=file_record['department'],
            operation='READ',
            access_result='DENIED',
            reason=reason
        )

        return render_template(
            'access_denied.html',
            filename=filename,
            target_dept=file_record['department'],
            reason=reason,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ), 403


@app.route('/files/download/<path:filename>')
@login_required
def download_file(filename):
    """
    Allows downloading authorized files. Denies cross-department requests.
    """
    user_department = session['department']
    user_role = session['role']
    username = session['username']

    if not is_safe_path(filename):
        abort(400, description="Invalid filename.")

    file_record = get_file_by_name(filename)
    if not file_record:
        abort(404)

    is_authorized, reason = evaluate_access(user_department, user_role, file_record)

    if is_authorized:
        log_access_attempt(
            username=username,
            requested_file=filename,
            user_department=user_department,
            required_department=file_record['department'],
            operation='DOWNLOAD',
            access_result='GRANTED',
            reason=reason
        )
        return send_from_directory(SAMPLE_DATA_DIR, filename, as_attachment=True)
    else:
        log_access_attempt(
            username=username,
            requested_file=filename,
            user_department=user_department,
            required_department=file_record['department'],
            operation='DOWNLOAD',
            access_result='DENIED',
            reason=reason
        )
        return render_template(
            'access_denied.html',
            filename=filename,
            target_dept=file_record['department'],
            reason=reason,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ), 403


# ==============================================================================
# Module 4: Security Audit Logs Route
# ==============================================================================
@app.route('/logs')
@login_required
def security_logs():
    """Displays audit logs with optional filter for GRANTED or DENIED attempts."""
    access_filter = request.args.get('filter')
    logs = get_security_logs(limit=100, access_filter=access_filter)
    return render_template('logs.html', logs=logs, current_filter=access_filter)


# ==============================================================================
# Application Startup
# ==============================================================================
if __name__ == '__main__':
    # Initialize database if not already created
    init_db()
    print("Hospital Unauthorized File Access Detection System started.")
    print("Serving on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
