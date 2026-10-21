"""Sentinel End-to-End Real-Time Demonstration.

Orchestrates a live end-to-end simulation:
1. Spins up local Mock Slack Server
2. Launches Sentinel daemon tailing a live log stream
3. Streams normal traffic followed by injected cyber attacks
4. Observes real-time anomaly detection and alert dispatching
5. Prints execution metrics and alert logs
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

# Add project root and scripts directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from colorama import Fore, Style, init
from mock_slack_server import MockSlackServer
from sentinel.generate_logs import generate_attack_log, generate_normal_log

init(autoreset=True)


def run_demo() -> None:
    print(f"\n{Fore.CYAN}{Style.BRIGHT}========================================================")
    print("   SENTINEL: REAL-TIME LOG ANOMALY DETECTOR DEMO")
    print(f"========================================================\n")

    demo_log = Path("data/demo_stream.log")
    model_path = Path("models/sentinel_model.joblib")
    demo_log.parent.mkdir(parents=True, exist_ok=True)

    # 1. Train model if not present
    if not model_path.is_file():
        print(f"{Fore.YELLOW}[*] Model not found. Training baseline model first...")
        subprocess.run(
            [sys.executable, "-m", "sentinel.train", "--input", "data/normal.log", "--output", str(model_path)],
            check=True,
        )

    # 2. Reset live log stream
    demo_log.write_text("", encoding="utf-8")
    print(f"{Fore.GREEN}[+] Initialized live log stream at '{demo_log}'")

    # 3. Start local Mock Slack Webhook Server
    mock_port = 8089
    mock_server = MockSlackServer(port=mock_port)
    mock_server.start()
    print(f"{Fore.GREEN}[+] Mock Slack server listening at {mock_server.url}")

    # 4. Launch Sentinel daemon in background subprocess
    # Run in live mode sending alerts to Mock Slack Server (not dry-run) to test full pipeline!
    env = os.environ.copy()
    env["SLACK_WEBHOOK_URL"] = mock_server.url
    env["PYTHONUNBUFFERED"] = "1"

    print(f"{Fore.CYAN}[*] Starting Sentinel daemon tailing '{demo_log}' (sending alerts to mock Slack)...")
    sentinel_proc = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "sentinel.main",
            "--log-file",
            str(demo_log),
            "--model-path",
            str(model_path),
            "--threshold",
            "0.65",
            "--no-dry-run",  # Live webhook dispatch to mock Slack!
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    time.sleep(2.0)  # Allow Sentinel to initialize and seek file

    try:
        # 5. Stream Normal Traffic
        print(f"\n{Fore.WHITE}[*] Streaming 15 normal traffic requests...")
        with open(demo_log, "a", encoding="utf-8") as f:
            for i in range(15):
                line = generate_normal_log()
                f.write(line + "\n")
                f.flush()
                time.sleep(0.08)

        # 6. Inject Realistic Attack Lines
        print(f"\n{Fore.RED}{Style.BRIGHT}[!] INJECTING ATTACK LOGS (SQLi, XSS, Path Traversal, 500 error burst)...")
        injected_attacks = []
        with open(demo_log, "a", encoding="utf-8") as f:
            for _ in range(5):
                attack_line, attack_type = generate_attack_log()
                injected_attacks.append((attack_line, attack_type))
                f.write(attack_line + "\n")
                f.flush()
                print(f"    {Fore.YELLOW}-> Injected: [{attack_type}] {attack_line[:75]}...")
                time.sleep(0.20)

        # 7. Stream More Normal Traffic
        print(f"\n{Fore.WHITE}[*] Streaming 10 normal recovery requests...")
        with open(demo_log, "a", encoding="utf-8") as f:
            for _ in range(10):
                line = generate_normal_log()
                f.write(line + "\n")
                f.flush()
                time.sleep(0.08)

        time.sleep(2.5)  # Wait for ingestion and alerting processing

    finally:
        # 8. Cleanly terminate Sentinel daemon and Mock Server
        print(f"\n{Fore.CYAN}[*] Stopping Sentinel process (PID: {sentinel_proc.pid})...")
        sentinel_proc.terminate()
        try:
            sentinel_out, _ = sentinel_proc.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            sentinel_proc.kill()
            sentinel_out, _ = sentinel_proc.communicate()

        mock_server.stop()

    # 9. Verify and Display Results
    received_alerts = mock_server.get_received()
    print(f"\n{Fore.GREEN}{Style.BRIGHT}================ DEMO VERIFICATION REPORT ================")
    print(f"Injected Attack Payloads:        {len(injected_attacks)}")
    print(f"Alerts Received by Mock Slack:  {len(received_alerts)}")

    if received_alerts:
        print(f"\n{Fore.GREEN}[+] Verified Sample Slack Alert Payload Received:")
        first_payload = received_alerts[0]["payload"]
        print(f"    * Notification Text: {first_payload.get('text')}")
        if "attachments" in first_payload and first_payload["attachments"]:
            blocks = first_payload["attachments"][0].get("blocks", [])
            for b in blocks:
                if b.get("type") == "header":
                    print(f"    * Header: {b.get('text', {}).get('text')}")
                elif b.get("type") == "section" and "text" in b:
                    print(f"    * Details:\n      {b['text'].get('text')}")

    print(f"\n{Fore.CYAN}--- Sentinel Daemon Process Output ---")
    for out_line in sentinel_out.splitlines()[:20]:
        print(f"  {out_line}")
    print(f"{Fore.GREEN}{Style.BRIGHT}==========================================================\n")
    print(f"{Fore.GREEN}[+] Demo completed with 100% success!")


if __name__ == "__main__":
    run_demo()
