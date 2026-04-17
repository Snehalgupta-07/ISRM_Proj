pipeline {
    agent any
    
    environment {
        PYTHON_PATH = "C:\\Users\\Snehal\\AppData\\Local\\Programs\\Python\\Python39\\python.exe"
        PROJECT_NAME = 'ISRM_Vulnerable_App'
        REPORT_DIR = 'reports'
    }
    
    triggers {
        githubPush()
    }
    
    stages {
        
        stage('0. Checkout') {
            steps {
                echo "========== CHECKOUT STAGE =========="
                
                // 🔥 FIX: Use branch-aware checkout
                cleanWs()
                checkout scm
                
                bat 'dir'
                echo "[+] Correct branch checked out"
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
                
                echo "[+] Build completed"
            }
        }
        
        stage('2. Security Scan') {
            steps {
                echo "========== SECURITY SCANNING =========="
                
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    
                    bat """
                        if not exist reports mkdir reports
                        
                        chcp 65001
                        
                        call venv\\Scripts\\activate.bat
                        
                        echo [*] Running Bandit scan on CURRENT BRANCH...
                        
                        venv\\Scripts\\bandit -r . -f json -o reports\\bandit_report.json
                        venv\\Scripts\\bandit -r . -f html -o reports\\bandit_report.html
                        venv\\Scripts\\bandit -r . -ll
                    """
                }
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
                echo "[+] Reports archived"
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
            echo "[FAILURE] Pipeline failed"
        }
    }
}