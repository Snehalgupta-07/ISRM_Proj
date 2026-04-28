pipeline {
    agent any
    
    environment {
        PYTHON_PATH = "C:\\Users\\Snehal\\AppData\\Local\\Programs\\Python\\Python39\\python.exe"
        REPORT_DIR = 'reports'
    }
    
    triggers {
        githubPush()
    }
    
    stages {
        
        stage('0. Checkout') {
            steps {
                echo "========== CHECKOUT STAGE =========="
                cleanWs()
                checkout scm
                bat 'dir'
            }
        }
        
        stage('1. Build') {
            steps {
                echo "========== BUILD STAGE =========="
                
                bat """
                    ${PYTHON_PATH} --version
                    
                    if not exist venv (
                        ${PYTHON_PATH} -m venv venv
                    )
                    
                    call venv\\Scripts\\activate.bat
                    
                    venv\\Scripts\\pip install --upgrade pip
                    venv\\Scripts\\pip install -r requirements.txt
                    venv\\Scripts\\pip install bandit
                """
            }
        }
        
        stage('2. Security Scan') {
            steps {
                echo "========== SECURITY SCANNING =========="
                
                bat """
                    if not exist reports mkdir reports
                    
                    chcp 65001
                    
                    call venv\\Scripts\\activate.bat
                    
                    echo [*] Running Bandit scan...
                    
                    venv\\Scripts\\bandit -r . -f json -o reports\\bandit_report.json
                    venv\\Scripts\\bandit -r . -f html -o reports\\bandit_report.html
                """
            }
        }
        
        stage('3. Report Generation') {
            steps {
                echo "========== REPORT GENERATION =========="
                
                bat """
                    call venv\\Scripts\\activate.bat
                    ${PYTHON_PATH} generate_vulnerability_report.py
                """
                
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            }
        }

        stage('4. Enforce Security Gate (CVSS > 5)') {
            steps {
                echo "========== SECURITY GATE =========="
                
                // Write the python script to a file, because Windows BAT does not support <<EOF heredocs
                writeFile file: 'check_security_gate.py', text: '''
import json
import sys
import os

try:
    with open('reports/bandit_report.json') as f:
        data = json.load(f)
except FileNotFoundError:
    print("❌ Bandit report not found!")
    sys.exit(1)

mapping = {
    'B608': 9.0,
    'B105': 8.0,
    'B607': 8.5,
    'B610': 7.5,
    'B201': 6.5,
    'B104': 6.5,
    'B101': 5.0,
    'B110': 5.0,
    'B102': 5.0
}

fail = False

for v in data.get('results', []):
    test_id = v.get('test_id')
    filename = v.get('filename', '')
    
    # Filter to only check project files like the report generator does
    if not any(f in filename for f in ['app.py', 'database.py', 'config.py']):
        continue
        
    cvss = mapping.get(test_id, 5.0)
    
    if cvss > 5:
        print(f"[!] High risk vulnerability: {test_id} (CVSS {cvss}) in {os.path.basename(filename)}")
        fail = True

if fail:
    print("❌ Build FAILED due to CVSS > 5 vulnerabilities")
    sys.exit(1)
else:
    print("✅ Build PASSED (No CVSS > 5 vulnerabilities found)")
'''
                bat """
                    call venv\\Scripts\\activate.bat
                    echo Checking for vulnerabilities with CVSS > 5...
                    ${PYTHON_PATH} check_security_gate.py
                """
            }
        }
    }
    
    post {
        always {
            echo "========== PIPELINE COMPLETE =========="
        }
        success {
            echo "[SUCCESS] No high-risk vulnerabilities"
        }
        failure {
            echo "[FAILURE] High-risk vulnerabilities detected"
        }
    }
}