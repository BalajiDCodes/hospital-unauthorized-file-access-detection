import os
import sys
import unittest
import tempfile
import sqlite3

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import database
    import app as flask_app_module
except (ModuleNotFoundError, ImportError, PermissionError):
    import importlib.util
    db_file = os.path.join(PROJECT_ROOT, 'database.py')
    app_file = os.path.join(PROJECT_ROOT, 'app.py')

    db_spec = importlib.util.spec_from_file_location('database', db_file)
    database = importlib.util.module_from_spec(db_spec)
    sys.modules['database'] = database
    db_spec.loader.exec_module(database)

    app_spec = importlib.util.spec_from_file_location('app', app_file)
    flask_app_module = importlib.util.module_from_spec(app_spec)
    sys.modules['app'] = flask_app_module
    app_spec.loader.exec_module(flask_app_module)

from database import init_db, get_security_logs, get_dashboard_stats


class HospitalAccessSystemTests(unittest.TestCase):
    def setUp(self):
        """Create a fresh isolated temporary database for each test run."""
        self.db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        os.close(self.db_fd)

        # Patch database path
        flask_app_module.DEFAULT_DB_PATH = self.temp_db_path
        import database
        database.DEFAULT_DB_PATH = self.temp_db_path

        # Initialize schema and seed demo records
        init_db(self.temp_db_path)

        # Configure Flask test client
        flask_app_module.app.config['TESTING'] = True
        flask_app_module.app.config['WTF_CSRF_ENABLED'] = False
        self.client = flask_app_module.app.test_client()

    def tearDown(self):
        """Clean up temporary test database."""
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    # --------------------------------------------------------------------------
    # 1. Authentication Tests (Module 1)
    # --------------------------------------------------------------------------
    def test_unauthenticated_redirect(self):
        """Unauthenticated request to protected dashboard should redirect to login."""
        response = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers.get('Location', ''))

    def test_login_success_admin(self):
        """Admin login with correct credentials should succeed and set session."""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hospital Security Dashboard', response.data)
        self.assertIn(b'admin', response.data)

    def test_login_success_cardiology(self):
        """Cardiology doctor login should succeed and redirect to dashboard."""
        response = self.client.post('/login', data={
            'username': 'cardio_doc',
            'password': 'cardio123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Cardiology', response.data)

    def test_login_invalid_password(self):
        """Login with incorrect password should be rejected."""
        response = self.client.post('/login', data={
            'username': 'cardio_doc',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)

    # --------------------------------------------------------------------------
    # 2. File Access Control Tests (Module 3)
    # --------------------------------------------------------------------------
    def test_authorized_file_access_own_department(self):
        """Cardiology doctor accessing a Cardiology file must be GRANTED."""
        # Log in as cardio_doc
        self.client.post('/login', data={'username': 'cardio_doc', 'password': 'cardio123'})

        # Access Cardiology file
        response = self.client.get('/files/view/cardio_patient_101_ecg.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Access Granted', response.data)
        self.assertIn(b'Patient ID       : CARD-101', response.data)

        # Verify security log was recorded
        logs = get_security_logs(limit=1, db_path=self.temp_db_path)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['access_result'], 'GRANTED')
        self.assertEqual(logs[0]['requested_file'], 'cardio_patient_101_ecg.txt')

    def test_unauthorized_cross_department_access_denied(self):
        """Cardiology doctor accessing a Radiology file must be DENIED and logged."""
        # Log in as cardio_doc
        self.client.post('/login', data={'username': 'cardio_doc', 'password': 'cardio123'})

        # Attempt to access Radiology file
        response = self.client.get('/files/view/radio_scan_201_mri.txt')
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'UNAUTHORIZED FILE ACCESS DETECTED', response.data)

        # Verify security log records the violation
        logs = get_security_logs(limit=1, db_path=self.temp_db_path)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['access_result'], 'DENIED')
        self.assertEqual(logs[0]['username'], 'cardio_doc')
        self.assertEqual(logs[0]['requested_file'], 'radio_scan_201_mri.txt')

    def test_admin_can_access_any_department_file(self):
        """Admin has supervisor clearance to access files across all departments."""
        self.client.post('/login', data={'username': 'admin', 'password': 'admin123'})

        # Admin accesses Radiology file
        response = self.client.get('/files/view/radio_scan_201_mri.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Access Granted', response.data)

        # Admin accesses Cardiology file
        response = self.client.get('/files/view/cardio_patient_102_echo.txt')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Access Granted', response.data)

    def test_path_traversal_attack_blocked(self):
        """Attempts to traverse directory paths (e.g. ../../app.py) must be blocked."""
        self.client.post('/login', data={'username': 'cardio_doc', 'password': 'cardio123'})

        response = self.client.get('/files/view/..%2F..%2Fapp.py')
        self.assertEqual(response.status_code, 403)

        logs = get_security_logs(limit=1, db_path=self.temp_db_path)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['access_result'], 'DENIED')

    # --------------------------------------------------------------------------
    # 3. Dashboard Metrics & Security Logs Tests (Modules 2 & 4)
    # --------------------------------------------------------------------------
    def test_dashboard_stats_and_log_filtering(self):
        """Dashboard statistics accurately aggregate granted and denied access counts."""
        # 1. Cardio doctor makes 1 granted and 1 denied attempt
        self.client.post('/login', data={'username': 'cardio_doc', 'password': 'cardio123'})
        self.client.get('/files/view/cardio_patient_101_ecg.txt')  # GRANTED
        self.client.get('/files/view/radio_scan_202_ct.txt')       # DENIED

        stats = get_dashboard_stats(db_path=self.temp_db_path)
        self.assertEqual(stats['total_users'], 3)
        self.assertEqual(stats['total_files'], 5)
        self.assertEqual(stats['authorized_attempts'], 1)
        self.assertEqual(stats['denied_attempts'], 1)

        # Test log filtering
        granted_logs = get_security_logs(access_filter='GRANTED', db_path=self.temp_db_path)
        denied_logs = get_security_logs(access_filter='DENIED', db_path=self.temp_db_path)
        self.assertEqual(len(granted_logs), 1)
        self.assertEqual(len(denied_logs), 1)


if __name__ == '__main__':
    unittest.main()
