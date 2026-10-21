# Sentinel End-to-End Real-Time Demonstration Script (Windows PowerShell)

$ErrorActionPreference = "Stop"

$VenvPython = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[!] Virtual environment not found at $VenvPython. Run: python -m venv .venv" -ForegroundColor Red
    exit 1
}

# Run the complete demonstration orchestrator
& $VenvPython scripts\run_demo.py
