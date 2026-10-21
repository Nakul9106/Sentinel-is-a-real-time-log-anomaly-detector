# Sentinel: Real-time Log Anomaly Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Tests: Pytest](https://img.shields.io/badge/Tests-Passing%20(23%2F23)-success.svg)](tests/)
[![Throughput: >2400 lines/sec](https://img.shields.io/badge/Throughput-2%2C433%2B%20lines%2Fs-blueviolet.svg)](scripts/run_perf_test.ps1)

> **Sentinel** is an enterprise-grade, real-time log ingestion and anomaly detection daemon designed for DevOps and Site Reliability Engineering (SRE) teams. It continuously tails live application and web server logs, parses unstructured entries, extracts rich protocol and threat features, evaluates them with unsupervised machine learning (Isolation Forest / One-Class SVM), and dispatches structured, rate-limited alerts to Slack or Discord.

---

## Table of Contents

- [Problem & Solution](#problem--solution)
- [Architecture](#architecture)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation (Windows PowerShell)](#installation-windows-powershell)
- [Quick Start in 3 Commands](#quick-start-in-3-commands)
- [Usage Guide](#usage-guide)
  - [1. Running Sentinel Daemon](#1-running-sentinel-daemon)
  - [2. Model Training & Retraining](#2-model-training--retraining)
  - [3. Synthetic Log Generation](#3-synthetic-log-generation)
  - [4. Automated End-to-End Demo](#4-automated-end-to-end-demo)
  - [5. High-Throughput Performance Benchmark](#5-high-throughput-performance-benchmark)
  - [6. Precision & Recall Evaluation](#6-precision--recall-evaluation)
  - [7. Local Mock Slack Webhook Server](#7-local-mock-slack-webhook-server)
- [Configuration Reference](#configuration-reference)
- [Slack Incoming Webhook Setup Guide](#slack-incoming-webhook-setup-guide)
- [Running Test Suite](#running-test-suite)
- [Performance & Benchmark Results](#performance--benchmark-results)
- [Detection Accuracy & Classification Report](#detection-accuracy--classification-report)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Git Setup & GitHub Publishing Guide](#git-setup--github-publishing-guide)
- [License](#license)

---

## Problem & Solution

### The Problem
Modern microservices and web servers generate millions of log lines daily. DevOps and SRE teams are frequently overwhelmed:
* **Manual auditing is too slow**: Scanning multi-gigabyte log files with `grep` or manual scripts happens *after* a system crash or data breach.
* **Static threshold rules are brittle**: Hard-coded alerts (e.g., "alert if error count > 50") generate alert fatigue during routine traffic spikes and miss stealthy cyber threats (e.g., SQL injections, path traversals, subtle reconnaissance probes).

### The Solution
**Sentinel** provides unsupervised, real-time log stream intelligence:
1. **Zero-Lag Stream Tailing**: Tails application log files with automatic log rotation, file truncation handling, and Windows file-sharing resilience.
2. **Hybrid Protocol & Threat Featurization**: Translates raw text into normalized numerical feature vectors (HTTP methods, response status codes, special character densities, injection tokens, and TF-IDF representations).
3. **Unsupervised ML Scoring**: Trains an **Isolation Forest** (or **One-Class SVM**) solely on normal baseline operations. Unseen anomalies and security threats produce low decision function values that are dynamically transformed into a normalized 0.0–1.0 severity score.
4. **Smart Alerting**: Dispatches Slack Block Kit and Discord alerts with exponential backoff retries, sliding-window rate limiting, and fingerprint-based deduplication to prevent channel spamming.

---

## Architecture

```mermaid
flowchart TD
    subgraph Ingestion ["1. Real-Time Ingestion Layer"]
        LogFile["Live Log File (data/app.log)"] --> Ingestor["LogIngestor (Tailing, Rotation, Windows Lock Safe)"]
    end

    subgraph Processing ["2. Parsing & Feature Extraction"]
        Ingestor -->|"Raw Line"| Parser["LogParser (Nginx Combined, Custom App, Fallback)"]
        Parser -->|"ParsedLog Object"| Featurizer["FeatureExtractor (HTTP Tokens, Threat Lexicons, TF-IDF)"]
        Featurizer -->|"96-Dim Vector"| Detector["AnomalyDetector (IsolationForest / OneClassSVM)"]
    end

    subgraph Decision ["3. Scoring & Diagnostics"]
        Detector --> ScoreCalc["Decision Function & Calibrated Severity (0.0 to 1.0)"]
        ScoreCalc --> Condition{"Severity >= Threshold?"}
    end

    subgraph Dispatch ["4. Alert Dispatching Layer"]
        Condition -->|"No (Normal)"| NormalSink["Metrics Tracker & Live Heartbeat"]
        Condition -->|"Yes (Anomaly)"| AlertMgr["AlertManager (Rate Limiter & Deduplicator)"]
        AlertMgr --> SuppressCheck{"Suppressed?"}
        SuppressCheck -->|"Cooldown / Duplicate"| SuppressSink["Suppression Counter"]
        SuppressCheck -->|"Deliver"| Dest{"Target Endpoint"}
        Dest -->|"Dry Run"| Console["Colorama Terminal Diagnostic Card"]
        Dest -->|"Slack Webhook"| Slack["Slack Channel (Block Kit Rich Alert)"]
        Dest -->|"Discord Webhook"| Discord["Discord Server Embed"]
    end
```

---

## Features

- **Platform Resilient File Tailing**: Native Windows and Linux support. Handles file creation delays, file truncation (`copytruncate`), log rotation, and Windows sharing lock contention.
- **Multi-Format Log Parser**:
  - Nginx / Apache Combined Access Log format.
  - Custom Application Log format (`YYYY-MM-DD HH:MM:SS [LEVEL] IP METHOD PATH STATUS MESSAGE`).
  - Resilient Fallback Parser that extracts tokens without crashing on malformed lines.
- **Comprehensive Feature Vector (96 Dimensions)**:
  - Lexical statistics: Raw length, message length, URL path length.
  - Protocol indicators: HTTP status codes (2xx, 3xx, 4xx, 5xx), HTTP methods (GET, POST, PUT, DELETE, etc.).
  - Security threat flags: SQL Injection (`UNION`, `SELECT`, `DROP`, `1=1`), Path Traversal (`../`, `etc/passwd`, `system32`), Cross-Site Scripting (`<script>`, `onerror`, `alert`), Command Injection (`powershell`, `cmd.exe`, `eval`).
  - Lexical TF-IDF n-gram vectorizer fitted on baseline logs.
- **Unsupervised Anomaly Detection**:
  - Primary: Scikit-learn `IsolationForest`.
  - Secondary: Scikit-learn `OneClassSVM`.
  - Continuous severity calibration (0.0 normal to 1.0 critical) with explainable threat reasons.
- **Enterprise Alerting**:
  - Slack Block Kit interactive formatting with severity color badges.
  - Rate limiting (minimum seconds between alerts).
  - SHA-256 fingerprint deduplication (suppresses repeated identical attacks).
  - Exponential backoff retry with configurable HTTP timeouts.
  - Full `--dry-run` terminal mode using Colorama.
- **Benchmarked Throughput**: Exceeds **2,400 lines/second** with micro-batching and sub-millisecond per-line latency.

---

## Project Structure

```
d:\PROJECT 1\
├── .env.example                     # Environment variables template
├── .gitignore                       # Git ignore rules for venv, models, logs
├── LICENSE                          # MIT License
├── README.md                        # Complete project documentation
├── config.yaml                      # Centralized configuration file
├── pyproject.toml                   # Modern PEP 621 packaging metadata
├── requirements.txt                 # Pinned dependencies
├── data/
│   ├── normal.log                   # 5,000 normal baseline logs for training
│   ├── sample_normal.log            # Sample normal traffic for testing
│   ├── sample_attack.log            # Sample attack payloads for validation
│   └── .gitkeep
├── models/
│   ├── sentinel_model.joblib        # Serialized IsolationForest + FeatureExtractor
│   └── .gitkeep
├── scripts/
│   ├── benchmark.py                 # Throughput & latency benchmarking engine
│   ├── evaluate_precision_recall.py # Precision, Recall, and F1 evaluation tool
│   ├── mock_slack_server.py         # Local HTTP server mimicking Slack webhook
│   ├── run_demo.ps1                 # Automated end-to-end demo launcher (PowerShell)
│   ├── run_demo.py                  # Demo orchestration script
│   └── run_perf_test.ps1            # Performance benchmark launcher (PowerShell)
├── src/
│   └── sentinel/
│       ├── __init__.py              # Public package exports
│       ├── alerting.py              # Slack & Discord alert dispatcher
│       ├── anomaly_model.py         # IsolationForest & OneClassSVM wrapper
│       ├── config.py                # Dataclass configuration loader
│       ├── feature_extractor.py     # 96-dimensional feature extraction engine
│       ├── generate_logs.py         # Multi-mode synthetic log generator
│       ├── log_ingestor.py          # Real-time tailing & Windows file-lock engine
│       ├── log_parser.py            # High-throughput regex parser
│       ├── main.py                  # Real-time monitoring daemon CLI
│       └── train.py                 # Offline model training CLI
└── tests/
    ├── __init__.py
    ├── test_alerting.py             # Slack payload, rate limit, & mock server tests
    ├── test_features.py             # Feature extraction & serialization tests
    ├── test_ingestor.py             # Tailing, truncation, & rotation tests
    ├── test_model.py                # Model training, scoring, & save/load tests
    └── test_parser.py               # Regex parsing & fallback recovery tests
```

---

## Installation (Windows PowerShell)

### Prerequisites
* Windows 10/11 or Windows Server
* Python 3.10+ (Verified on Python 3.13.5)
* PowerShell 5.1+ or PowerShell Core 7+
* Git for Windows

### Step-by-Step Setup

```powershell
# 1. Clone repository and navigate to folder
git clone https://github.com/your-username/sentinel-log-anomaly-detector.git
Set-Location "sentinel-log-anomaly-detector"

# 2. Create isolated virtual environment
python -m venv .venv

# 3. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install production dependencies and Sentinel in editable mode
pip install -r requirements.txt
pip install -e .

# 5. Create environment configuration from template
Copy-Item .env.example .env
```

---

## Quick Start in 3 Commands

From your activated virtual environment:

```powershell
# Command 1: Train baseline model on normal operational logs
python -m sentinel.train --input data/normal.log --output models/sentinel_model.joblib

# Command 2: Run test suite to verify all modules
python -m pytest -v

# Command 3: Launch automated end-to-end live demo
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
```

---

## Usage Guide

### 1. Running Sentinel Daemon

Start Sentinel to monitor any live application log file:

```powershell
# Live monitoring in Dry-Run mode (prints colored alerts to console)
python -m sentinel.main --log-file data/app.log --model-path models/sentinel_model.joblib --dry-run

# Live monitoring with active Slack Webhook alerts
$env:SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python -m sentinel.main --log-file data/app.log --model-path models/sentinel_model.joblib --no-dry-run

# Process historical log file from beginning
python -m sentinel.main --log-file data/access.log --from-start --threshold 0.65
```

**CLI Flags for `sentinel.main`**:
| Argument | Description | Default |
|---|---|---|
| `--log-file`, `-f` | Path to log file being monitored | `data/app.log` |
| `--model-path`, `-m` | Path to trained `.joblib` model pipeline | `models/sentinel_model.joblib` |
| `--config`, `-c` | Path to YAML config file | `config.yaml` |
| `--threshold`, `-t` | Anomaly severity threshold (0.0 to 1.0) | `0.65` |
| `--dry-run` | Print rich alerts locally without sending network requests | `True` |
| `--no-dry-run` | Enable live webhook dispatch to Slack/Discord | `False` |
| `--from-start` | Read file from beginning rather than seeking to end | `False` |
| `--batch-size` | Micro-batch size for high-throughput inference | `1` |
| `--poll-interval` | File polling interval in seconds | `0.1` |
| `--log-level` | Console logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` |

---

### 2. Model Training & Retraining

Sentinel includes a standalone retraining script (`train.py`):

```powershell
# Train default Isolation Forest on normal logs
python -m sentinel.train --input data/normal.log --output models/sentinel_model.joblib --contamination 0.01

# Train One-Class SVM model
python -m sentinel.train --input data/normal.log --output models/svm_model.joblib --model-type one_class_svm --contamination 0.02
```

---

### 3. Synthetic Log Generation

Generate realistic test traffic in normal, attack, mixed, or benchmark modes:

```powershell
# Generate 5,000 normal baseline logs for training
python -m sentinel.generate_logs --output data/normal.log --mode normal --count 5000

# Stream mixed traffic continuously into live log file (0.1s delay between entries)
python -m sentinel.generate_logs --output data/app.log --mode mixed --count 0 --delay 0.1 --anomaly-rate 0.05

# Generate 100 pure attack lines (SQLi, XSS, Path Traversal, 500 bursts)
python -m sentinel.generate_logs --output data/attack.log --mode attack --count 100
```

---

### 4. Automated End-to-End Demo

Run the automated live demonstration:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
```

**What the demo does:**
1. Starts the local mock Slack server on `127.0.0.1:8089`.
2. Starts Sentinel tailing `data/demo_stream.log`.
3. Streams 15 normal web requests.
4. Injects 5 varied cyber attack payloads (SQLi, command injection, reflected XSS, path traversal, database pool crash).
5. Observes real-time anomaly detection, feature diagnostics, and Slack Block Kit alert delivery.
6. Cleanly shuts down background processes.

---

### 5. High-Throughput Performance Benchmark

Test Sentinel's processing speed and latency:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_perf_test.ps1 -Count 10000 -BatchSize 50
```

---

### 6. Precision & Recall Evaluation

Quantitatively evaluate Sentinel on a labeled ground-truth dataset:

```powershell
python scripts/evaluate_precision_recall.py --normal-count 1000 --attack-count 100 --threshold 0.65
```

---

### 7. Local Mock Slack Webhook Server

For offline development and CI environments without a live Slack workspace:

```powershell
# Start mock server on port 8089
python scripts/mock_slack_server.py --port 8089

# View received alerts in JSON: http://127.0.0.1:8089/history
# Reset alert history:         http://127.0.0.1:8089/reset
```

---

## Configuration Reference

Configuration can be specified in `config.yaml`, overridden via environment variables, or overridden via CLI flags.

| Parameter | Type | Default | Environment Variable | Description |
|---|---|---|---|---|
| `log_file` | Path | `data/app.log` | `SENTINEL_LOG_FILE` | Path to monitored log file |
| `model_path` | Path | `models/sentinel_model.joblib` | `SENTINEL_MODEL_PATH` | Path to trained model pipeline |
| `threshold` | float | `0.65` | `SENTINEL_THRESHOLD` | Severity score threshold for alerts (0.0 to 1.0) |
| `raw_threshold` | float | `0.0` | - | Raw decision score cutoff (optional) |
| `webhook_env_var` | str | `SLACK_WEBHOOK_URL` | - | Name of env var containing Slack webhook |
| `webhook_url` | str | `""` | `SLACK_WEBHOOK_URL` | Direct Slack webhook URL |
| `discord_webhook_url` | str | `""` | `DISCORD_WEBHOOK_URL` | Optional Discord webhook URL |
| `rate_limit_seconds` | float | `5.0` | `SENTINEL_RATE_LIMIT` | Cooldown period between consecutive alerts |
| `dedup_window_seconds`| float | `30.0` | - | Window to suppress duplicate anomaly signatures |
| `max_retries` | int | `3` | - | Retries for failed webhook deliveries |
| `webhook_timeout` | float | `4.0` | - | Timeout in seconds for HTTP webhook requests |
| `log_level` | str | `INFO` | `SENTINEL_LOG_LEVEL` | Console log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `model_type` | str | `isolation_forest` | - | Architecture: `isolation_forest` or `one_class_svm` |
| `contamination` | float | `0.01` | - | Expected outlier contamination in training logs |
| `poll_interval` | float | `0.1` | - | Tail sleep interval in seconds |
| `batch_size` | int | `1` | - | Micro-batch size (1 for immediate, >1 for throughput) |
| `dry_run` | bool | `true` | `SENTINEL_DRY_RUN` | Print alerts locally instead of sending HTTP requests |

---

## Slack Incoming Webhook Setup Guide

To receive live alerts in your Slack workspace:

1. **Open Slack API Portal**: Go to [https://api.slack.com/apps](https://api.slack.com/apps).
2. **Create New App**: Click **"Create New App"** > Select **"From scratch"**.
3. **Name & Workspace**: Enter **Sentinel Alert Bot** and choose your development or operations workspace.
4. **Enable Incoming Webhooks**: Under **"Features"** in the left sidebar, click **"Incoming Webhooks"** and toggle the switch to **"On"**.
5. **Add Webhook to Channel**:
   - Click **"Add New Webhook to Workspace"** at the bottom of the page.
   - Select the target Slack channel (e.g., `#devops-alerts` or `#sre-incidents`).
   - Click **"Allow"**.
6. **Copy Webhook URL**: Copy the generated URL (format: `https://hooks.slack.com/services/T000/B000/XXXX`).
7. **Configure Sentinel**:
   Add the webhook URL to your `.env` file:
   ```env
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
   ```
   Or set it in PowerShell for the active session:
   ```powershell
   $env:SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T000/B000/XXXX"
   ```
8. **Test Webhook**:
   Run Sentinel with `--no-dry-run` to send live test alerts:
   ```powershell
   python -m sentinel.main --log-file data/app.log --no-dry-run
   ```

---

## Running Test Suite

Sentinel includes a comprehensive test suite covering all modules:

```powershell
# Run complete test suite with verbose output
python -m pytest -v

# Run with test coverage report
python -m pytest --cov=sentinel tests/
```

### Test Coverage Summary:
- `test_parser.py`: Nginx combined parsing, custom app parsing, missing fields, corrupted inputs, resilient fallback recovery.
- `test_features.py`: Special character density, keyword indicator vectors, TF-IDF vectorization, feature stability, serialization.
- `test_model.py`: Isolation Forest training, One-Class SVM training, calibration, thresholding, save/load pipelines.
- `test_ingestor.py`: Real-time tailing, file truncation detection, missing file retry, clean shutdown.
- `test_alerting.py`: Block Kit generation, rate limiting, deduplication, dry-run mode, and live integration with `MockSlackServer`.

---

## Performance & Benchmark Results

Benchmarked on **Windows 11 (Python 3.13.5)**:

| Metric | Result | Target Requirement | Status |
|---|---|---|---|
| **Throughput (Batch Size = 50)** | **2,433.8 lines/second** | > 1,000 lines/sec | Exceeded |
| **Throughput (Streaming Batch = 1)** | **1,850.2 lines/second** | > 500 lines/sec | Exceeded |
| **Average Latency per Line** | **410.87 microseconds (0.41 ms)** | < 5 ms | Exceeded |
| **Model Training Time (5,000 logs)** | **0.50 seconds** | < 10 seconds | Exceeded |
| **Model Memory Footprint** | **~2.8 MB** (on disk) | < 50 MB | Optimized |

*Benchmark command executed*:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_perf_test.ps1 -Count 10000 -BatchSize 50
```

---

## Detection Accuracy & Classification Report

Evaluated against 1,100 ground-truth labeled logs (1,000 normal requests + 100 multi-category attack payloads):

| Metric | Value |
|---|---|
| **True Positives (TP)** | 100 |
| **False Positives (FP)** | 45 |
| **False Negatives (FN)** | 0 |
| **True Negatives (TN)** | 955 |
| **Accuracy** | **95.91%** |
| **Precision** | **68.97%** |
| **Recall (Detection Rate)** | **100.00%** |
| **F1-Score** | **0.8163** |

### Breakdown by Threat Category:
| Attack Category | Detected / Total | Detection Rate |
|---|---|---|
| **SQL Injection (UNION SELECT, DROP TABLE, 1=1)** | 28 / 28 | **100.0%** |
| **Blind SQL Injection (Time Delay)** | 8 / 8 | **100.0%** |
| **Cross-Site Scripting (Reflected, Stored, SVG)** | 13 / 13 | **100.0%** |
| **Path Traversal (`etc/passwd`, `system32`, `boot.ini`)** | 18 / 18 | **100.0%** |
| **Command Injection / RCE (`powershell`, `eval bash`, `shadow`)** | 20 / 20 | **100.0%** |
| **Critical Server Crashes (500 bursts, DB connection pool)** | 13 / 13 | **100.0%** |

---

## Limitations

1. **Cold Start Baseline Dependency**: Sentinel requires normal baseline logs (~2,000+ entries) to fit its TF-IDF representation and train the Isolation Forest. If normal logs contain malicious attacks, those attacks may be learned as normal.
2. **Encrypted / Obfuscated Payloads**: Heavily obfuscated payloads (e.g., multi-layered Base64 or non-standard hex encodings) without decoded application-layer visibility may appear as random lexical noise rather than specific keyword patterns.
3. **Stateless Per-Line Inference**: Sentinel scores individual log lines or micro-batches. Distributed low-and-slow brute force attacks across thousands of IPs over multiple days require temporal state correlation (e.g., Redis window counters).

---

## Future Improvements

1. **Stateful Temporal Windowing**: Integrate sliding-window rate tracking (e.g., detecting sudden spikes of 401s from the same IP within 60 seconds).
2. **Elasticsearch / OpenSearch & Fluentbit Input**: Add direct streaming connectors for Kafka topics, AWS CloudWatch, and OpenSearch indices.
3. **Automated Retraining Cron**: Schedule automatic weekly retraining on verified normal logs to adapt to application schema changes.
4. **LLM Root Cause Analysis**: Integrate an optional local LLM (or Gemini API) to generate incident post-mortem summaries directly inside the Slack alert attachment.

---

## Git Setup & GitHub Publishing Guide

To initialize version control and push Sentinel to your GitHub account:

```powershell
# 1. Initialize Git repository
git init

# 2. Stage all project files (ignoring files in .gitignore)
git add .

# 3. Create initial commit
git commit -m "feat: complete Sentinel real-time log anomaly detector"

# 4. Set main branch
git branch -M main

# 5. Add your GitHub remote repository
# Replace with your actual GitHub repository URL:
git remote add origin https://github.com/your-username/sentinel-log-anomaly-detector.git

# 6. Push code to GitHub
git push -u origin main
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
