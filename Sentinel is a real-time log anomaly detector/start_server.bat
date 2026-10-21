@echo off
title Sentinel - Real-Time Anomaly Detector ^& Web Dashboard
cd /d "%~dp0"

echo =================================================================
echo       SENTINEL REAL-TIME ANOMALY DETECTOR ^& WEB DASHBOARD
echo =================================================================
echo.
echo [*] Checking Python virtual environment...

if not exist ".venv\Scripts\python.exe" (
    echo [!] Error: Virtual environment not found at .venv\Scripts\python.exe
    echo [*] Please run setup first:
    echo        python -m venv .venv
    echo        .\.venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo [*] Starting Sentinel Server, ML Detector, and opening Web Browser...
echo.

REM Run start_server.py which initializes the server, ML daemon, and launches Chrome/browser
".venv\Scripts\python.exe" scripts\start_server.py

pause
