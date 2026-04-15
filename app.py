# Main Flask Application - Vulnerable Student Management System
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.utils import secure_filename
import os
import database
from config import Config
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
if not os.path.exists(database.DB_NAME):
    database.init_db()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# VULNERABILITY: No rate limiting on login attempts (Brute Force & Credential Stuffing)
LOGIN_ATTEMPTS = {}

def record_login_attempt(username):
    """No rate limiting implemented"""
    if username in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[username] += 1
    else:
        LOGIN_ATTEMPTS[username] = 1

def check_rate_limit(username):
    """Not enforced - allows unlimited brute force attempts"""
    return True  # Always returns True - NO PROTECTION


@app.route('/')
def index():
    """Home page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"<h1>Welcome to Vulnerable Student Management System</h1><a href='/logout'>Logout</a><br><a href='/dashboard'>Dashboard</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABILITY: Multiple Security Flaws
    1. SQL Injection in authentication
    2. NO rate limiting (Brute Force attack)
    3. Weak password handling
    4. No CSRF protection
    5. Sensitive error messages
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # No input validation
        
        # No rate limiting - allows unlimited login attempts
        record_login_attempt(username)
        
        # SQL Injection vulnerability here
        user = database.authenticate_user(username, password)
        
        if user:
            # VULNERABILITY: No session timeout enforcement
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[3]
            session['role'] = user[4]
            session.permanent = True
            
            # VULNERABILITY: Information Disclosure - Verbose logging
            database.log_action('LOGIN_SUCCESS', username, f"User logged in successfully")
            
            return redirect(url_for('dashboard'))
        else:
            # VULNERABILITY: Information Disclosure
            error = "Invalid username or password"
            database.log_action('LOGIN_FAILED', username, f"Failed login attempt with password: {password}")
            return render_template('login.html', error=error)
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """
    VULNERABILITY: No proper access control
    Anyone with a session can access
    Shows role-based dashboard
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    username = session.get('username')
    
    if role == 'admin':
        # Admin dashboard - full access to all functions
        return f'''
        <h1>Admin Dashboard</h1>
        <p>Welcome, <b>Admin: {username}</b></p>
        <h3>Student Management</h3>
        <ul>
            <li><a href="/students">View All Students</a></li>
            <li><a href="/add_student">Add New Student</a></li>
            <li><a href="/search">Search Students</a></li>
        </ul>
        <h3>File Management</h3>
        <ul>
            <li><a href="/upload">Upload File</a></li>
        </ul>
        <h3>System</h3>
        <ul>
            <li><a href="/view_logs">View System Logs</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
        '''
    
    elif role == 'student':
        # Student dashboard - limited access
        return f'''
        <h1>Student Dashboard</h1>
        <p>Welcome, <b>Student: {username}</b></p>
        <h3>My Academic Information</h3>
        <ul>
            <li><a href="/student/grades">View My Grades & GPA</a></li>
            <li><a href="/student/profile">View My Profile</a></li>
        </ul>
        <h3>Account</h3>
        <ul>
            <li><a href="/logout">Logout</a></li>
        </ul>
        '''
    
    else:
        # Regular user dashboard
        return f'''
        <h1>User Dashboard</h1>
        <p>Welcome, <b>User: {username}</b></p>
        <ul>
            <li><a href="/students">View Students</a></li>
            <li><a href="/add_student">Add Student</a></li>
            <li><a href="/search">Search Students</a></li>
            <li><a href="/upload">Upload File</a></li>
            <li><a href="/logout">Logout</a></li>
        </ul>
        '''

@app.route('/students')
def view_students():
    """
    VULNERABILITY: No access control - any authenticated user can see all data
    Exposes sensitive information (SSN, passwords)
    FIXED: Restrict to admin and user roles only (not students)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view all student records", 403
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, roll_no, name, email, phone, ssn FROM students')
    students = cursor.fetchall()
    conn.close()
    
    html = '<h1>Student List</h1><table border="1"><tr><th>ID</th><th>Roll No</th><th>Name</th><th>Email</th><th>Phone</th><th>SSN</th><th>Action</th></tr>'
    
    for student in students:
        html += f'<tr><td>{student[0]}</td><td>{student[1]}</td><td>{student[2]}</td><td>{student[3]}</td><td>{student[4]}</td><td>{student[5]}</td><td><a href="/student/{student[0]}">View</a></td></tr>'
    
    html += '</table><br><a href="/dashboard">Back</a>'
    return html

@app.route('/student/<student_id>')
def view_student(student_id):
    """
    VULNERABILITY: SQL Injection in student ID parameter
    Sensitive Data Exposure of SSN and password
    FIXED: Prevent students from viewing other student records
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view other student records", 403
    
    # VULNERABLE: Direct parameter use - SQL Injection
    student = database.get_student_details(student_id)
    
    if not student:
        return "Student not found", 404
    
    # VULNERABILITY: Sensitive data exposure
    return f'''
    <h1>Student Details</h1>
    <p><b>Roll No:</b> {student[1]}</p>
    <p><b>Name:</b> {student[2]}</p>
    <p><b>Email:</b> {student[3]}</p>
    <p><b>Phone:</b> {student[4]}</p>
    <p><b>Address:</b> {student[5]}</p>
    <p><b>SSN:</b> {student[6]}</p>  <!-- VULNERABLE: Exposing SSN -->
    <p><b>GPA:</b> {student[7]}</p>
    <p><b>Password:</b> {student[8]}</p>  <!-- VULNERABLE: Exposing password! -->
    <br><a href="/students">Back</a>
    '''

@app.route('/student/profile')
def student_profile():
    """
    Student can view only their own profile
    Restricts access based on email matching between user and student record
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        return "Access Denied: Only students can view their profile", 403
    
    user_email = session.get('email')  # Requires email to be stored in session
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    # Use parameterized query here (matching email)
    cursor.execute('SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        return "Your student record not found", 404
    
    return f'''
    <h1>My Profile</h1>
    <p><b>Roll Number:</b> {student[1]}</p>
    <p><b>Name:</b> {student[2]}</p>
    <p><b>Email:</b> {student[3]}</p>
    <p><b>Phone:</b> {student[4]}</p>
    <p><b>Address:</b> {student[5]}</p>
    <p><b>CGPA:</b> {student[6]}</p>
    <br><a href="/dashboard">Back to Dashboard</a>
    '''

@app.route('/student/grades')
def student_grades():
    """
    Student can view only their own grades and GPA
    Restricts access to student role only
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        return "Access Denied: Only students can view their grades", 403
    
    user_email = session.get('email')
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT roll_no, name, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        return "Your student record not found", 404
    
    # VULNERABILITY: Password shown here too (information disclosure)
    return f'''
    <h1>My Academic Performance</h1>
    <h2>Student Information</h2>
    <p><b>Roll Number:</b> {student[0]}</p>
    <p><b>Name:</b> {student[1]}</p>
    
    <h2>Academic Performance</h2>
    <p><b>CGPA (Cumulative Grade Point Average):</b> {student[2]}</p>
    <p><b>Status:</b> {'Good Standing' if float(student[2]) >= 3.0 else 'Probation'}</p>
    
    <h3>Performance Analysis</h3>
    <table border="1">
        <tr>
            <th>GPA Range</th>
            <th>Performance</th>
        </tr>
        <tr>
            <td>3.8 - 4.0</td>
            <td>Excellent</td>
        </tr>
        <tr>
            <td>3.5 - 3.7</td>
            <td>Very Good</td>
        </tr>
        <tr>
            <td>3.0 - 3.4</td>
            <td>Good</td>
        </tr>
        <tr>
            <td>< 3.0</td>
            <td>Needs Improvement</td>
        </tr>
    </table>
    
    <br><a href="/dashboard">Back to Dashboard</a>
    '''

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    """
    VULNERABILITY: No input validation, SQL Injection
    No privilege check (any user can add students)
    FIXED: Now restricts to admin only
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can add students", 403
    
    if request.method == 'POST':
        # No input validation or sanitization
        roll_no = request.form.get('roll_no', '')
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        ssn = request.form.get('ssn', '')
        gpa = request.form.get('gpa', '0')
        
        # VULNERABLE: No validation, SQL injection possible
        if database.add_student(roll_no, name, email, phone, address, ssn, gpa):
            return "Student added successfully! <a href='/dashboard'>Back</a>"
        else:
            return "Error adding student <a href='/dashboard'>Back</a>"
    
    return '''
    <h1>Add Student</h1>
    <form method="POST">
        Roll No: <input type="text" name="roll_no"><br>
        Name: <input type="text" name="name"><br>
        Email: <input type="email" name="email"><br>
        Phone: <input type="text" name="phone"><br>
        Address: <input type="text" name="address"><br>
        SSN: <input type="text" name="ssn"><br>
        GPA: <input type="float" name="gpa"><br>
        <input type="submit" value="Add Student">
    </form>
    <a href="/dashboard">Back</a>
    '''

@app.route('/search', methods=['GET', 'POST'])
def search_students():
    """
    VULNERABILITY: SQL Injection in search
    No access control - FIXED to prevent students
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot search student records", 403
    
    results = []
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        
        # VULNERABLE: SQL Injection
        results = database.search_students(search_term)
        
        # VULNERABILITY: Information Disclosure - Shows query
        print(f"[*] Search performed for: {search_term}")
    
    html = '''
    <h1>Search Students</h1>
    <form method="POST">
        Search: <input type="text" name="search">
        <input type="submit" value="Search">
    </form>
    '''
    
    if results:
        html += '<h3>Results:</h3><table border="1">'
        html += '<tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Roll No</th></tr>'
        for result in results:
            html += f'<tr><td>{result[0]}</td><td>{result[1]}</td><td>{result[2]}</td><td>{result[3]}</td><td>{result[4]}</td></tr>'
        html += '</table>'
    
    html += '<a href="/dashboard">Back</a>'
    return html

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    VULNERABILITY: Multiple File Upload Issues
    1. No file type validation (allows executables)
    2. Path Traversal vulnerability
    3. No file size limit enforcement
    4. Predictable filenames
    FIXED: Prevent students from uploading
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Only admin and users can upload files", 403
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file selected'
        
        file = request.files['file']
        
        if file.filename == '':
            return 'No file selected'
        
        # VULNERABILITY: No proper file validation
        # Allow dangerous file extensions
        filename = file.filename  # VULNERABLE: No sanitization
        

        # VULNERABILITY: Path Traversal - No path validation
        # Attacker can use "../" to upload outside intended directory
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # VULNERABILITY: No file type check
        # Allows executable files (.exe, .sh, .bat)
        file.save(filepath)
        
        # VULNERABILITY: Information Disclosure - Log file path
        database.log_action('FILE_UPLOAD', session.get('username'), f"Uploaded file: {filepath}")
        
        return f"File uploaded successfully! <a href='/dashboard'>Back</a><br>File path: {filepath}"
    
    return '''
    <h1>Upload File</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <a href="/dashboard">Back</a>
    '''

@app.route('/download/<filename>')
def download_file(filename):
    """
    VULNERABILITY: Path Traversal
    No validation of filename parameter
    Allows download of any file using ../ notation
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABLE: Path Traversal - No sanitization
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(filepath):
        return send_file(filepath)
    else:
        return "File not found", 404

@app.route('/file/<path:filepath>')
def access_file(filepath):
    """
    VULNERABILITY: Unrestricted File Path Access
    CWE-434: Unrestricted Upload of File with Dangerous Type
    CWE-22: Path Traversal vulnerability
    
    Allows direct access to ANY file on the system using path parameter
    No validation - attackers can use this to:
    - Download config.py (steal SECRET_KEY)
    - Download vulnerable_app.db (steal all user/student data)
    - Download app.py (get source code)
    - Download database.py (leak database queries)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # CRITICAL VULNERABILITY: No path validation whatsoever
    # Directly trusts user input for file access
    try:
        if os.path.exists(filepath) and os.path.isfile(filepath):
            database.log_action('FILE_ACCESS', session.get('username'), f"Accessed file: {filepath}")
            return send_file(filepath)
        else:
            return "File not found or not a file", 404
    except Exception as e:
        # VULNERABILITY: Information Disclosure - reveals errors
        return f"Error accessing file: {str(e)}", 500

@app.route('/logs')
def view_logs():
    """
    VULNERABILITY: Information Disclosure + Sensitive Data Exposure
    No access control - any user can see logs with passwords
    FIXED: Restrict to admin only
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can view logs", 403
    
    # VULNERABILITY: No role-based access control
    # Should be admin-only
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY created_at DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    
    html = '<h1>System Logs</h1><table border="1"><tr><th>ID</th><th>Action</th><th>Username</th><th>Details</th><th>Timestamp</th></tr>'
    
    for log in logs:
        # VULNERABLE: Displays sensitive information including passwords
        html += f'<tr><td>{log[0]}</td><td>{log[1]}</td><td>{log[2]}</td><td>{log[3]}</td><td>{log[4]}</td></tr>'
    
    html += '</table><br><a href="/dashboard">Back</a>'
    return html

@app.route('/logout')
def logout():
    """VULNERABILITY: No CSRF token on logout"""
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    # VULNERABILITY: Information Disclosure - Detailed error
    return f"404 Error: {error}", 404

@app.errorhandler(500)
def internal_error(error):
    # VULNERABILITY: Information Disclosure - Stack trace exposed
    return f"500 Internal Server Error: {error}", 500

if __name__ == '__main__':
    # VULNERABILITY: Running in debug mode (not for production)
    # Debug mode exposes detailed error pages and allows code execution
    app.run(debug=True, host='0.0.0.0', port=5000)
