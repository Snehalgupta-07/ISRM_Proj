pipeline {
    agent any
    
    environment {
        PYTHON_ENV = 'venv'
        PROJECT_NAME = 'ISRM_Vulnerable_App'
        REPORT_DIR = 'reports'
    }
    
    stages {
        stage('1. Build') {
            steps {
                echo "========== BUILD STAGE =========="
                echo "Setting up Python environment..."
                sh '''
                    python --version
                    python -m venv venv || true
                    . venv/bin/activate || source venv/Scripts/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install bandit pytest coverage
                '''
                echo "[+] Build completed"
            }
        }
        
        stage('2. Unit Tests') {
            steps {
                echo "========== TESTING STAGE =========="
                sh '''
                    . venv/bin/activate || source venv/Scripts/activate
                    python test_vulnerabilities.py || true
                '''
            }
        }
        
        stage('3. Security Scan') {
            steps {
                echo "========== SECURITY SCANNING STAGE =========="
                sh '''
                    mkdir -p reports
                    . venv/bin/activate || source venv/Scripts/activate
                    
                    echo "[*] Running Bandit JSON scan..."
                    bandit -r app.py database.py config.py -f json -o reports/bandit_report.json || true
                    
                    echo "[*] Running Bandit HTML scan..."
                    bandit -r app.py database.py config.py -f html -o reports/bandit_report.html || true
                    
                    echo "[*] Running Bandit CSV scan..."
                    bandit -r app.py database.py config.py -f csv -o reports/bandit_report.csv || true
                    
                    echo "[*] Console output..."
                    bandit -r app.py database.py config.py -ll || true
                '''
            }
        }
        
        stage('4. Report Generation') {
            steps {
                echo "========== REPORT GENERATION STAGE =========="
                sh '''
                    . venv/bin/activate || source venv/Scripts/activate
                    
                    echo "[*] Generating vulnerability assessment report..."
                    python generate_vulnerability_report.py
                    
                    echo "[*] Copying reports..."
                    cp -f VULNERABILITY_ASSESSMENT_REPORT.md reports/ || true
                    cp -f vulnerability_assessment.csv reports/ || true
                    cp -f vulnerability_assessment.html reports/ || true
                '''
                
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
                echo "[+] Reports generated and archived"
            }
        }
    }
    
    post {
        always {
            echo "========== POST BUILD =========="
            cleanWs()
        }
        success {
            echo "[SUCCESS] Pipeline executed successfully"
        }
        failure {
            echo "[FAILURE] Pipeline failed - check logs"
        }
    }
}