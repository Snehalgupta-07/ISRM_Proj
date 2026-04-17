# Database Module - Contains SQL Injection Vulnerabilities
import sqlite3
import os
from datetime import datetime

DB_NAME = 'vulnerable_app.db'

def init_db():
    """Initialize the database with vulnerable schema"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    
    # Create students table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            ssn TEXT NOT NULL,
            gpa REAL,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create logs table - VULNERABLE: Logs sensitive data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            username TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default admin user with weak credentials
    cursor.execute('DELETE FROM users')  # Clean slate
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin123', 'admin@university.edu', 'admin'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('user', 'password', 'user@university.edu', 'user'))
    
    # NEW: Add student accounts for student login
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('john_student', 'student123', 'john.student@university.edu', 'student'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('sarah_student', 'student456', 'sarah.student@university.edu', 'student'))
    
    # Add student records that correspond to student logins
    cursor.execute('DELETE FROM students')  # Clean slate
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10001', 'John Smith', 'john.student@university.edu', '9876543210', '123 Main St', '123-45-6789', 3.85, 'student123'))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10002', 'Sarah Johnson', 'sarah.student@university.edu', '9876543211', '456 Oak Ave', '987-65-4321', 3.92, 'student456'))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10003', 'Michael Brown', 'michael@university.edu', '9876543212', '789 Pine Rd', '456-78-9012', 3.45, 'pass123'))
    
    conn.commit()
    conn.close()
    print("[*] Database initialized successfully")

def authenticate_user(username, password):
    """
    FIXED: SQL Injection
    Now uses parameterized queries with ? placeholders
    Prevents SQL injection attacks by separating query structure from data
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE (COMMENTED): SQL Injection - String concatenation
    # query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # VULNERABLE (COMMENTED): Information Disclosure
    # print(f"[DEBUG] Executing query: {query}")
    
    user = None
    try:
        # FIXED: Use parameterized queries with ? placeholders
        # Data is passed separately and automatically escaped by SQLite driver
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
    except Exception as e:
        # FIXED: Generic error message - no information disclosure
        print(f"[INFO] Authentication check completed")
    finally:
        conn.close()  # Close connection BEFORE logging
    
    # FIXED: Sanitized logging - don't log passwords
    if user:
        log_action('AUTH_ATTEMPT', username, "Result: Success")
    else:
        log_action('AUTH_ATTEMPT', username, "Result: Failed")
    
    return user

def search_students(search_term):
    """
    FIXED: SQL Injection
    Now uses parameterized queries with LIKE operator safely
    Prevents attackers from injecting SQL through search term
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE (COMMENTED): SQL Injection - Direct string interpolation
    # query = f"SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE '%{search_term}%' OR roll_no LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    # VULNERABLE (COMMENTED): Information Disclosure
    # print(f"[DEBUG] Search query: {query}")
    
    try:
        # FIXED: Use parameterized query with ? placeholders
        # LIKE pattern constructed safely with data escaped
        search_pattern = f"%{search_term}%"
        cursor.execute(
            "SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE ? OR roll_no LIKE ? OR email LIKE ?",
            (search_pattern, search_pattern, search_pattern)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        # FIXED: Generic error message - no information disclosure
        print(f"[INFO] Search operation completed")
        return []

def get_student_details(student_id):
    """
    FIXED: SQL Injection + Sensitive Data Exposure
    Now uses parameterized queries
    Only returns non-sensitive fields (excludes SSN and password)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE (COMMENTED): SQL Injection
    # query = f"SELECT * FROM students WHERE id = {student_id}"
    # VULNERABLE (COMMENTED): Information Disclosure
    # print(f"[DEBUG] Student query: {query}")
    
    try:
        # FIXED: Validate input type and use parameterized query
        try:
            student_id = int(student_id)  # Validate that ID is an integer
        except ValueError:
            return None
        
        # FIXED: Use parameterized query with ? placeholder
        # Only select non-sensitive fields (exclude SSN and password)
        cursor.execute(
            "SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE id = ?",
            (student_id,)
        )
        student = cursor.fetchone()
        conn.close()
        return student  # FIXED: No longer returns sensitive data like SSN or password
    except Exception as e:
        # FIXED: Generic error message
        print(f"[INFO] Student lookup completed")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa):
    """
    FIXED: SQL Injection + Input Validation
    Now uses parameterized queries and validates all inputs
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # VULNERABLE (COMMENTED): No input validation, string concatenation
        # query = f'''
        #     INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        #     VALUES ('{roll_no}', '{name}', '{email}', '{phone}', '{address}', '{ssn}', {gpa}, '{roll_no}')
        # '''
        # VULNERABLE (COMMENTED): Information Disclosure
        # print(f"[DEBUG] Insert query: {query}")
        
        # FIXED: Input validation before using data
        if not all([roll_no, name, email, phone, address, ssn]):
            return False
        
        # FIXED: Validate email format (basic check)
        if '@' not in email:
            return False
        
        # FIXED: Validate GPA is numeric and in valid range
        try:
            gpa_float = float(gpa)
            if gpa_float < 0 or gpa_float > 4.0:
                return False
        except ValueError:
            return False
        
        # FIXED: Use parameterized query with ? placeholders
        cursor.execute(
            '''INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (roll_no, name, email, phone, address, ssn, gpa_float, roll_no)
        )
        conn.commit()
        conn.close()
        print(f"[INFO] Student record created successfully")
        return True
    except Exception as e:
        # FIXED: Generic error message
        print(f"[INFO] Student creation operation completed")
        return False

def log_action(action, username, details):
    """
    FIXED: Information Disclosure
    Now sanitizes details to prevent logging sensitive data like passwords
    Redacts sensitive information before logging
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5.0)  # Wait up to 5 seconds for lock
        cursor = conn.cursor()
        
        # VULNERABLE (COMMENTED): Logs sensitive details including passwords
        # cursor.execute('''INSERT INTO logs (action, username, details) VALUES (?, ?, ?)''', (action, username, details))
        
        # FIXED: Sanitize details - remove sensitive information
        sanitized_details = details
        # Remove any password mentions
        if 'password' in sanitized_details.lower() or 'Password' in sanitized_details:
            sanitized_details = sanitized_details.split(',')[0]  # Only keep first part before sensitive data
        
        # FIXED: Log sanitized information only
        cursor.execute(
            '''INSERT INTO logs (action, username, details) 
               VALUES (?, ?, ?)''',
            (action, username, sanitized_details)
        )
        
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        # If database is locked, just print warning and continue
        # FIXED: Don't expose internal error details
        print(f"[INFO] Logging operation attempted")
        pass
