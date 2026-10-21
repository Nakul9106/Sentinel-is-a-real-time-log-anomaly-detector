"""Sentinel 1-Click Server & Web Dashboard Launcher.

Spins up:
1. The Sentinel Web Dashboard & Alert Webhook Server (http://localhost:8089)
2. The Sentinel Real-time ML Anomaly Detection Daemon (monitoring data/app.log)
3. Seeds initial logs so live output appears immediately
4. Automatically opens Google Chrome or the default web browser to the live dashboard
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from mock_slack_server import MockSlackServer, set_sentinel_process
from sentinel.generate_logs import generate_attack_log, generate_normal_log


def find_chrome() -> str | None:
    """Finds Google Chrome executable on Windows if available."""
    candidates = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    which_chrome = shutil.which("chrome")
    if which_chrome:
        return which_chrome
    return None


def open_browser(url: str = "http://localhost:8089") -> None:
    """Opens Google Chrome or default browser to the given URL."""
    chrome_path = find_chrome()
    if chrome_path:
        try:
            subprocess.Popen([chrome_path, url])
            print(f"[*] Opened live dashboard in Google Chrome: {url}")
            return
        except Exception:
            pass

    # Fallback to system default browser
    try:
        webbrowser.open(url)
        print(f"[*] Opened live dashboard in default web browser: {url}")
    except Exception as e:
        print(f"[!] Could not open browser automatically: {e}")
        print(f"[*] Please open your browser and go to: {url}")


def main() -> None:
    print("\n" + "=" * 68)
    print("      SENTINEL REAL-TIME ANOMALY DETECTOR & WEB DASHBOARD")
    print("=" * 68)

    # 1. Ensure model exists
    model_path = PROJECT_ROOT / "models" / "sentinel_model.joblib"
    if not model_path.is_file():
        print("[*] Baseline model not found. Training model now (takes ~3s)...")
        subprocess.run(
            [sys.executable, "-m", "sentinel.train", "--input", "data/normal.log", "--output", str(model_path)],
            check=True,
            cwd=str(PROJECT_ROOT),
        )
        print("[+] Model trained and saved successfully.")

    # 2. Ensure log file directory and file exists
    app_log = PROJECT_ROOT / "data" / "app.log"
    app_log.parent.mkdir(parents=True, exist_ok=True)
    if not app_log.exists():
        app_log.write_text("", encoding="utf-8")

    # 3. Start Mock Slack Server & Live Dashboard on port 8089
    port = 8089
    server = MockSlackServer(host="127.0.0.1", port=port)
    server.start()
    dashboard_url = f"http://localhost:{port}"
    webhook_url = f"http://127.0.0.1:{port}/webhook"

    print(f"[+] Web Dashboard running at:  {dashboard_url}")
    print(f"[+] Alert Webhook listening at: {webhook_url}")

    # 4. Launch Sentinel Daemon in background
    env = os.environ.copy()
    env["SLACK_WEBHOOK_URL"] = webhook_url
    env["SENTINEL_RATE_LIMIT"] = "1.0"
    env["PYTHONUNBUFFERED"] = "1"

    sentinel_proc = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "sentinel.main",
            "--log-file",
            str(app_log),
            "--model-path",
            str(model_path),
            "--threshold",
            "0.65",
            "--no-dry-run",
            "--poll-interval",
            "0.1",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    set_sentinel_process(sentinel_proc)
    print("[+] Sentinel ML daemon started (monitoring data/app.log)")

    # 5. Allow daemon to initialize, then seed initial traffic
    time.sleep(1.5)
    print("[*] Generating sample baseline & anomaly traffic for initial display...")
    with open(app_log, "a", encoding="utf-8") as f:
        # 3 normal logs
        for _ in range(3):
            f.write(generate_normal_log() + "\n")
        # 1 attack log to trigger instant anomaly card
        attack_line, attack_type = generate_attack_log()
        f.write(attack_line + "\n")
        f.flush()

    time.sleep(0.5)

    # 6. Launch Chrome or default browser
    open_browser(dashboard_url)

    print("\n" + "-" * 68)
    print("  LIVE SERVER READY!")
    print(f"  * Web Dashboard:  {dashboard_url}")
    print(f"  * Monitored Log:  {app_log}")
    print("  * In Chrome, click 'Start Project' to launch live telemetry streaming!")
    print("  * Press Ctrl+C in this terminal window to stop the server.")
    print("-" * 68 + "\n")

    def shutdown(sig=None, frame=None):
        print("\n[!] Shutting down Sentinel daemon and web server...")
        try:
            sentinel_proc.terminate()
            sentinel_proc.wait(timeout=2)
        except Exception:
            sentinel_proc.kill()
        server.stop()
        print("[+] All services stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive and print sentinel output if desired
    try:
        while True:
            line = sentinel_proc.stdout.readline() if sentinel_proc.stdout else ""
            if line:
                # Optionally filter or print sentinel logs
                line_str = line.strip()
                if "[ANOMALY]" in line_str or "[ALERT]" in line_str or "Dispatched" in line_str:
                    print(f"  {line_str}")
            elif sentinel_proc.poll() is not None:
                print("[!] Sentinel daemon process terminated unexpectedly.")
                break
            time.sleep(0.05)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
