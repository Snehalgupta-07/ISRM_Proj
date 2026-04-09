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
    
    conn.commit()
    conn.close()
    print("[*] Database initialized successfully")

def authenticate_user(username, password):
    """
    VULNERABILITY: SQL Injection
    Description: Uses string concatenation instead of parameterized queries
    Impact: Attacker can bypass authentication with SQL injection
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection - String concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    print(f"[DEBUG] Executing query: {query}")  # VULNERABLE: Information Disclosure
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        # Log the authentication attempt - VULNERABLE: Logs passwords
        log_action('AUTH_ATTEMPT', username, f"Password: {password}, Result: {user is not None}")
        
        conn.close()
        return user
    except Exception as e:
        # VULNERABLE: Information Disclosure - Detailed error messages
        print(f"[ERROR] Authentication failed: {str(e)}")
        return None

def search_students(search_term):
    """
    VULNERABILITY: SQL Injection
    Description: Allows SQL injection in student search
    Impact: Data breach, unauthorized access
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection - Direct string interpolation
    query = f"SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE '%{search_term}%' OR roll_no LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    
    print(f"[DEBUG] Search query: {query}")  # Information Disclosure
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Search failed: {str(e)}")
        return []

def get_student_details(student_id):
    """
    VULNERABILITY: SQL Injection + Sensitive Data Exposure
    Description: No input validation, exposes SSN and passwords
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # VULNERABLE: SQL Injection
    query = f"SELECT * FROM students WHERE id = {student_id}"
    
    print(f"[DEBUG] Student query: {query}")
    
    try:
        cursor.execute(query)
        student = cursor.fetchone()
        conn.close()
        # VULNERABLE: Returns sensitive data including SSN and password
        return student
    except Exception as e:
        print(f"[ERROR] Query failed: {str(e)}")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa):
    """
    VULNERABILITY: No input validation, no parameterized queries
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # VULNERABLE: No input validation
        query = f'''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES ('{roll_no}', '{name}', '{email}', '{phone}', '{address}', '{ssn}', {gpa}, '{roll_no}')
        '''
        
        print(f"[DEBUG] Insert query: {query}")  # Information Disclosure
        
        cursor.execute(query)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to add student: {str(e)}")
        return False

def log_action(action, username, details):
    """
    VULNERABILITY: Information Disclosure
    Logs sensitive details including passwords and personal info
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO logs (action, username, details) 
        VALUES (?, ?, ?)
    ''', (action, username, details))
    
    conn.commit()
    conn.close()
