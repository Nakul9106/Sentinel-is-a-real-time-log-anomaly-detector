# Sentinel High-Throughput Performance Benchmark Script (Windows PowerShell)

param(
    [int]$Count = 10000,
    [int]$BatchSize = 50
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   SENTINEL: PERFORMANCE & THROUGHPUT BENCHMARK" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$VenvPython = ".\.venv\Scripts\python.exe"
$ModelPath = "models\sentinel_model.joblib"

# 1. Ensure Model exists
if (-not (Test-Path $ModelPath)) {
    Write-Host "[*] Training baseline model first..." -ForegroundColor Yellow
    & $VenvPython -m sentinel.train --input data/normal.log --output $ModelPath
}

# 2. Run benchmark script
& $VenvPython scripts\benchmark.py --count $Count --batch-size $BatchSize

Write-Host "[+] Benchmark execution finished." -ForegroundColor Green
