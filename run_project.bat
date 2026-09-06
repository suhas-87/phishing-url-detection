@echo off
title PhishGuard - Phishing URL Detection System
color 0B

echo ================================================================
echo          PHISHGUARD - PHISHING URL DETECTION SYSTEM
echo            AI-Powered Cybersecurity Defense Project
echo              BCA 3rd-Year Academic Project Launcher
echo ================================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python is not installed or not added to your PATH!
    echo Please install Python 3.9+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo [*] Python detected:
python --version
echo.

:: 2. Check and generate dataset if missing
if not exist "dataset\urls.csv" (
    echo [*] Dataset missing. Generating balanced 3,200 URL dataset...
    cd dataset
    python generate_dataset.py
    cd ..
    echo [OK] Dataset generated successfully!
    echo.
) else (
    echo [OK] Dataset found: dataset\urls.csv
)

:: 3. Check and train ML model if missing
if not exist "model\phishing_model.pkl" (
    echo [*] Trained ML model not found. Starting training pipeline...
    cd backend
    python train_model.py
    cd ..
    echo [OK] ML model trained and saved to model\phishing_model.pkl!
    echo.
) else (
    echo [OK] Trained ML model found: model\phishing_model.pkl
)

:: 4. Check and evaluate model / generate confusion matrix if missing
if not exist "screenshots\confusion_matrix.png" (
    echo [*] Generating confusion matrix evaluation plot...
    cd backend
    python evaluate_model.py
    cd ..
    echo [OK] Confusion matrix saved to screenshots\confusion_matrix.png!
    echo.
) else (
    echo [OK] Evaluation plot found: screenshots\confusion_matrix.png
)

:: 5. Launch web browser after small delay in background
echo [*] Launching web browser at http://127.0.0.1:5000 ...
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:5000"

:: 6. Start Flask server
echo [*] Starting Flask REST API server on http://127.0.0.1:5000 ...
echo [*] Press Ctrl+C in this terminal window to stop the server.
echo.
cd backend
python app.py

pause
