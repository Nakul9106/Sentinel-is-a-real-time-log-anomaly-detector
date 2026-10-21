# Starts the Sentinel Webhook & Live Dashboard Server with automatic Chrome/browser launch (Windows PowerShell)

$ErrorActionPreference = "Stop"

$VenvPython = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Virtual environment not found at $VenvPython. Run: python -m venv .venv" -ForegroundColor Red
    exit 1
}

& $VenvPython scripts\start_server.py
