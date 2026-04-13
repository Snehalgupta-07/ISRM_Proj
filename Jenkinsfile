pipeline {
    agent any
    
    environment {
        PYTHON_ENV = 'venv'
        PROJECT_NAME = 'ISRM_Vulnerable_App'
        REPORT_DIR = 'reports'
    }
    
    stages {
        stage('0. Checkout') {
            steps {
                echo "========== CLONING REPOSITORY =========="
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/main']],
                    userRemoteConfigs: [[url: 'https://github.com/Snehalgupta-07/ISRM_Proj.git']]
                ])
                bat '''
                    @echo off
                    dir
                '''
                echo "[+] Repository cloned successfully"
            }
        }
        
        stage('1. Build') {
            steps {
                echo "========== BUILD STAGE =========="
                echo "Setting up Python environment..."
                bat '''
                    python --version
                    if not exist venv (python -m venv venv)
                    call venv\Scripts\activate.bat
                    pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install bandit
                '''
                echo "[+] Build completed"
            }
        }
        
        stage('2. Security Scan') {
            steps {
                echo "========== SECURITY SCANNING STAGE =========="
                bat '''
                    if not exist reports mkdir reports
                    call venv\Scripts\activate.bat
                    
                    echo [*] Running Bandit JSON report...
                    bandit -r app.py database.py config.py -f json -o reports\bandit_report.json
                    
                    echo [*] Running Bandit HTML report...
                    bandit -r app.py database.py config.py -f html -o reports\bandit_report.html
                    
                    echo [*] Running Bandit console output...
                    bandit -r app.py database.py config.py -ll
                    
                    exit /b 0
                '''
            }
        }
        
        stage('3. Report Generation') {
            steps {
                echo "========== REPORT GENERATION STAGE =========="
                bat '''
                    call venv\Scripts\activate.bat
                    
                    echo [*] Generating vulnerability assessment report...
                    python generate_vulnerability_report.py
                    
                    exit /b 0
                '''
                
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
                echo "[+] Reports generated and archived"
            }
        }
    }
    
    post {
        always {
            echo "========== PIPELINE COMPLETE =========="
        }
        success {
            echo "[SUCCESS] Pipeline executed successfully"
        }
        failure {
            echo "[FAILURE] Pipeline failed - check logs above"
        }
    }
}