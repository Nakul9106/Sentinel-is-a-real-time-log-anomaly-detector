"""Mock Slack Incoming Webhook Server & Sentinel Web Dashboard.

Provides:
1. HTTP POST /webhook: Receives and validates Slack Incoming Webhook alerts
2. HTTP GET /: Serves a simple, clean Dark Theme Web Dashboard
3. HTTP GET /history: JSON endpoint for real-time alert polling
4. HTTP POST /start: Starts the Sentinel ML monitoring engine & continuous live traffic stream
5. HTTP POST /stop: Pauses the live ingestion stream
6. HTTP POST /simulate: Test injection of normal and attack traffic directly from the UI
7. HTTP POST /clear: Resets alert history
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sentinel.generate_logs import generate_attack_log, generate_normal_log

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SentinelServer] %(message)s")
logger = logging.getLogger("SentinelServer")

# Global Server State
RECEIVED_ALERTS: list[dict[str, Any]] = []
STREAM_ACTIVE: bool = False
STREAM_THREAD: Optional[Thread] = None
STREAM_INTERVAL: float = 1.5
CURRENT_SERVER_PORT: int = 8089
SENTINEL_PROC: Optional[subprocess.Popen] = None
_STREAM_LOCK = threading.Lock()


def set_sentinel_process(proc: subprocess.Popen) -> None:
    """Registers an externally managed Sentinel daemon subprocess."""
    global SENTINEL_PROC
    SENTINEL_PROC = proc


def is_sentinel_running() -> bool:
    """Checks if the Sentinel detection daemon process is active."""
    global SENTINEL_PROC
    return SENTINEL_PROC is not None and SENTINEL_PROC.poll() is None


def ensure_sentinel_running() -> bool:
    """Ensures Sentinel ML daemon is running in the background."""
    global SENTINEL_PROC
    if is_sentinel_running():
        return True

    model_path = PROJECT_ROOT / "models" / "sentinel_model.joblib"
    if not model_path.is_file():
        try:
            logger.info("Baseline model not found. Training model now...")
            subprocess.run(
                [sys.executable, "-m", "sentinel.train", "--input", "data/normal.log", "--output", str(model_path)],
                check=True,
                cwd=str(PROJECT_ROOT),
            )
            logger.info("Model trained and saved successfully.")
        except Exception as e:
            logger.error(f"Failed to auto-train model: {e}")
            return False

    app_log = PROJECT_ROOT / "data" / "app.log"
    app_log.parent.mkdir(parents=True, exist_ok=True)
    if not app_log.exists():
        app_log.write_text("", encoding="utf-8")

    env = os.environ.copy()
    env["SLACK_WEBHOOK_URL"] = f"http://127.0.0.1:{CURRENT_SERVER_PORT}/webhook"
    env["SENTINEL_RATE_LIMIT"] = "0.5"
    env["PYTHONUNBUFFERED"] = "1"

    try:
        SENTINEL_PROC = subprocess.Popen(
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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Spawned background Sentinel ML detection daemon.")
        return True
    except Exception as e:
        logger.error(f"Could not spawn Sentinel daemon: {e}")
        return False


def _stream_worker() -> None:
    """Background worker that continuously writes realistic logs into data/app.log."""
    global STREAM_ACTIVE
    target_log = PROJECT_ROOT / "data" / "app.log"
    target_log.parent.mkdir(parents=True, exist_ok=True)

    iteration = 0
    while STREAM_ACTIVE:
        iteration += 1
        is_attack = (iteration == 1) or (iteration % 4 == 0)
        if is_attack:
            line, _ = generate_attack_log()
        else:
            line = generate_normal_log()

        try:
            with open(target_log, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception as e:
            logger.error(f"Error appending to log: {e}")

        time.sleep(STREAM_INTERVAL)


def start_stream(interval: float = 1.5) -> None:
    """Starts the continuous log generation stream."""
    global STREAM_ACTIVE, STREAM_THREAD, STREAM_INTERVAL
    with _STREAM_LOCK:
        STREAM_INTERVAL = max(0.2, interval)
        if STREAM_ACTIVE and STREAM_THREAD and STREAM_THREAD.is_alive():
            return
        STREAM_ACTIVE = True
        STREAM_THREAD = Thread(target=_stream_worker, daemon=True)
        STREAM_THREAD.start()
        logger.info(f"Sentinel live stream started (interval: {STREAM_INTERVAL}s)")


def stop_stream() -> None:
    """Pauses the continuous log generation stream."""
    global STREAM_ACTIVE
    with _STREAM_LOCK:
        STREAM_ACTIVE = False
        logger.info("Sentinel live stream paused.")


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel - Incident Monitor</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #121212;
      color: #e0e0e0;
      margin: 0;
      padding: 20px;
      line-height: 1.5;
    }
    .container {
      max-width: 960px;
      margin: 0 auto;
      background: #1e1e1e;
      border: 1px solid #2d2d2d;
      border-radius: 8px;
      padding: 20px 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #2d2d2d;
      padding-bottom: 12px;
      margin-bottom: 16px;
    }
    h1 {
      font-size: 20px;
      margin: 0;
      font-weight: 600;
      color: #ffffff;
    }
    .status {
      font-size: 13px;
      color: #4caf50;
      font-weight: 500;
    }
    .stats-bar {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      background: #252525;
      border: 1px solid #2d2d2d;
      border-radius: 6px;
      padding: 10px 14px;
      margin-bottom: 16px;
      font-size: 14px;
      color: #b0b0b0;
    }
    .stats-bar span {
      font-weight: 600;
      color: #ffffff;
    }
    .controls {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 20px;
      align-items: center;
    }
    button {
      background: #2a2a2a;
      color: #ffffff;
      border: 1px solid #3d3d3d;
      border-radius: 6px;
      padding: 7px 14px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    button:hover {
      background: #383838;
    }
    button.btn-start {
      background: #198754;
      border-color: #198754;
      color: #ffffff;
      font-weight: 600;
    }
    button.btn-start:hover {
      background: #157347;
    }
    button.btn-stop {
      background: #dc3545;
      border-color: #dc3545;
      color: #ffffff;
      font-weight: 600;
    }
    button.btn-stop:hover {
      background: #bb2d3b;
    }
    button.btn-danger {
      background: #2a2a2a;
      border-color: #dc3545;
      color: #ff6b6b;
    }
    button.btn-danger:hover {
      background: #dc3545;
      color: #ffffff;
    }
    .feed-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }
    .feed-header h2 {
      font-size: 16px;
      margin: 0;
      color: #ffffff;
    }
    .feed-header span {
      font-size: 12px;
      color: #888888;
    }
    .alert-card {
      border: 1px solid #333333;
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 12px;
      background: #242424;
    }
    .alert-card.CRITICAL { border-left: 4px solid #f44336; }
    .alert-card.HIGH { border-left: 4px solid #ff9800; }
    .alert-card.MEDIUM { border-left: 4px solid #ffc107; }
    .alert-card.LOW { border-left: 4px solid #4caf50; }
    .card-top {
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
      font-size: 13px;
      font-weight: 600;
      color: #ffffff;
    }
    .meta-row {
      font-size: 13px;
      color: #a0a0a0;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }
    .meta-row b {
      color: #e0e0e0;
    }
    .reasons-list {
      margin: 6px 0;
      padding-left: 20px;
      font-size: 13px;
      color: #ff8585;
    }
    .raw-log {
      background: #181818;
      border: 1px solid #2d2d2d;
      border-radius: 4px;
      padding: 8px 10px;
      font-family: monospace;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 6px;
      color: #cfcfcf;
    }
    .empty-state {
      text-align: center;
      padding: 36px 10px;
      color: #888888;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Sentinel Incident Monitor</h1>
      <span id="system-status" class="status">Server Active</span>
    </header>

    <div class="stats-bar">
      <div>Total Alerts: <span id="kpi-total">0</span></div>
      <div>Critical: <span id="kpi-critical" style="color: #f44336;">0</span></div>
      <div>High: <span id="kpi-high" style="color: #ff9800;">0</span></div>
      <div>Medium: <span id="kpi-medium" style="color: #ffc107;">0</span></div>
    </div>

    <div class="controls">
      <button id="btn-start" class="btn-start" onclick="toggleStream()">Start Project</button>
      <button class="btn-danger" onclick="triggerAttack()">Inject Attack Log</button>
      <button onclick="triggerNormal()">Inject Normal Traffic</button>
      <button onclick="clearAlerts()">Clear</button>
      <button onclick="fetchAlerts()">Refresh</button>
    </div>

    <div>
      <div class="feed-header">
        <h2>Live Alerts</h2>
        <span id="poll-indicator">Polling every 1s</span>
      </div>
      <div id="alert-list">
        <div class="empty-state">
          No alerts yet. Click 'Start Project' to begin live monitoring.
        </div>
      </div>
    </div>
  </div>

  <script>
    let isRunning = false;

    async function toggleStream() {
      const btn = document.getElementById('btn-start');
      const status = document.getElementById('system-status');
      try {
        if (!isRunning) {
          const resp = await fetch('/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interval: 1.5 })
          });
          const data = await resp.json();
          isRunning = true;
          btn.textContent = 'Stop Project';
          btn.className = 'btn-stop';
          status.textContent = 'Live Stream Active';
          status.style.color = '#4caf50';
          setTimeout(fetchAlerts, 500);
        } else {
          const resp = await fetch('/stop', { method: 'POST' });
          const data = await resp.json();
          isRunning = false;
          btn.textContent = 'Start Project';
          btn.className = 'btn-start';
          status.textContent = 'Stream Paused';
          status.style.color = '#ff9800';
        }
      } catch (err) {
        alert("Failed to toggle stream: " + err);
      }
    }

    async function fetchAlerts() {
      try {
        const resp = await fetch('/history');
        const alerts = await resp.json();
        renderAlerts(alerts);
      } catch (err) {
        console.error("Failed to fetch alerts:", err);
      }
    }

    function renderAlerts(alerts) {
      const container = document.getElementById('alert-list');
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;

      if (!alerts || alerts.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            No alerts yet. Click 'Start Project' to begin live monitoring.
          </div>
        `;
        document.getElementById('kpi-total').textContent = '0';
        document.getElementById('kpi-critical').textContent = '0';
        document.getElementById('kpi-high').textContent = '0';
        document.getElementById('kpi-medium').textContent = '0';
        return;
      }

      document.getElementById('kpi-total').textContent = alerts.length;

      let html = '';
      const reversed = [...alerts].reverse();

      for (const item of reversed) {
        const payload = item.payload || {};
        const text = payload.text || 'Incident Alert';

        let severityLabel = 'CRITICAL';
        if (text.includes('[CRITICAL]')) { severityLabel = 'CRITICAL'; criticalCount++; }
        else if (text.includes('[HIGH]')) { severityLabel = 'HIGH'; highCount++; }
        else if (text.includes('[MEDIUM]')) { severityLabel = 'MEDIUM'; mediumCount++; }
        else if (text.includes('[LOW]')) { severityLabel = 'LOW'; }
        else { criticalCount++; }

        let header = text;
        let reasons = [];
        let rawLog = '';
        let ip = 'N/A';
        let rawScore = 'N/A';
        let httpReq = '';
        let statusCode = 'N/A';

        const attachments = payload.attachments || [];
        if (attachments.length > 0 && attachments[0].blocks) {
          for (const b of attachments[0].blocks) {
            if (b.type === 'header' && b.text) {
              header = b.text.text || header;
            } else if (b.type === 'section' && b.fields) {
              for (const f of b.fields) {
                const t = f.text || '';
                if (t.includes('Source IP:')) ip = t.replace('*Source IP:*', '').replace(/[`\n]/g, '').trim();
                if (t.includes('Raw Model Score:')) rawScore = t.replace('*Raw Model Score:*', '').replace(/[`\n]/g, '').trim();
                if (t.includes('HTTP Request:')) httpReq = t.replace('*HTTP Request:*', '').replace(/[`\n]/g, '').trim();
                if (t.includes('Status Code:')) statusCode = t.replace('*Status Code:*', '').replace(/[`\n]/g, '').trim();
              }
            } else if (b.type === 'section' && b.text && b.text.text) {
              const body = b.text.text;
              if (body.includes('*Trigger Reasons:*')) {
                reasons = body.replace('*Trigger Reasons:*', '').trim().split('\\n').filter(Boolean);
              } else if (body.includes('*Raw Log Line:*')) {
                rawLog = body.replace('*Raw Log Line:*', '').replace(/```/g, '').trim();
              }
            }
          }
        }

        if (!rawLog && payload.raw) {
          rawLog = payload.raw;
        }

        html += `
          <div class="alert-card ${severityLabel}">
            <div class="card-top">
              <span>[${severityLabel}] Anomaly Alert</span>
              <span style="font-weight: normal; color: #888888;">${new Date().toLocaleTimeString()}</span>
            </div>
            <div class="meta-row">
              <div>IP: <b>${escapeHtml(ip)}</b></div>
              <div>Status: <b>${escapeHtml(statusCode)}</b></div>
              <div>Score: <b>${escapeHtml(rawScore)}</b></div>
              ${httpReq ? `<div>Request: <b>${escapeHtml(httpReq)}</b></div>` : ''}
            </div>
            ${reasons.length > 0 ? `
              <ul class="reasons-list">
                ${reasons.map(r => `<li>${escapeHtml(r.replace(/^[•*]\s*/, ''))}</li>`).join('')}
              </ul>
            ` : ''}
            <div class="raw-log">${escapeHtml(rawLog || 'Raw log text not captured.')}</div>
          </div>
        `;
      }

      document.getElementById('kpi-critical').textContent = criticalCount;
      document.getElementById('kpi-high').textContent = highCount;
      document.getElementById('kpi-medium').textContent = mediumCount;
      container.innerHTML = html;
    }

    function escapeHtml(str) {
      return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    async function triggerAttack() {
      try {
        const resp = await fetch('/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'attack' })
        });
        await resp.json();
        setTimeout(fetchAlerts, 600);
      } catch (err) {
        alert("Injection error: " + err);
      }
    }

    async function triggerNormal() {
      try {
        const resp = await fetch('/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'normal' })
        });
        await resp.json();
        setTimeout(fetchAlerts, 600);
      } catch (err) {
        alert("Injection error: " + err);
      }
    }

    async function clearAlerts() {
      await fetch('/clear', { method: 'POST' });
      fetchAlerts();
    }

    setInterval(fetchAlerts, 1000);
    fetchAlerts();
  </script>
</body>
</html>
"""


class MockSlackHandler(BaseHTTPRequestHandler):
    """Handles webhook ingestion, dashboard rendering, live stream control, and test log injection."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress noisy request logs."""
        pass

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        if self.path in ("/webhook", "/services") or self.path.startswith("/services/"):
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception:
                payload = {"raw": post_data.decode("utf-8", errors="replace")}

            RECEIVED_ALERTS.append({
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "path": self.path,
                "payload": payload,
            })
            logger.info(f"Received alert via webhook! Total: {len(RECEIVED_ALERTS)}")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        elif self.path == "/start":
            interval = 1.5
            try:
                if post_data:
                    body = json.loads(post_data.decode("utf-8"))
                    interval = float(body.get("interval", 1.5))
            except Exception:
                pass

            ensure_sentinel_running()
            start_stream(interval=interval)

            resp = json.dumps({
                "status": "started",
                "running": True,
                "interval": interval,
                "alerts_count": len(RECEIVED_ALERTS),
                "message": "Sentinel live ingestion stream started.",
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

        elif self.path == "/stop":
            stop_stream()
            resp = json.dumps({
                "status": "stopped",
                "running": False,
                "message": "Sentinel live ingestion stream paused.",
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

        elif self.path == "/simulate":
            try:
                body = json.loads(post_data.decode("utf-8"))
            except Exception:
                body = {"type": "attack"}

            target_log = PROJECT_ROOT / "data" / "app.log"
            target_log.parent.mkdir(parents=True, exist_ok=True)

            ensure_sentinel_running()

            if body.get("type") == "attack":
                line, attack_type = generate_attack_log()
                with open(target_log, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                resp_json = json.dumps({"status": "injected", "type": attack_type, "line": line})
            else:
                line = generate_normal_log()
                with open(target_log, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                resp_json = json.dumps({"status": "injected", "type": "normal", "line": line})

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp_json.encode("utf-8"))

        elif self.path in ("/clear", "/reset"):
            with _STREAM_LOCK:
                RECEIVED_ALERTS.clear()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"cleared")

        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

        elif self.path in ("/alerts", "/history"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(RECEIVED_ALERTS).encode("utf-8"))

        elif self.path in ("/status", "/api/status"):
            resp = json.dumps({
                "running": STREAM_ACTIVE,
                "alerts_count": len(RECEIVED_ALERTS),
                "sentinel_active": is_sentinel_running(),
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))

        elif self.path in ("/clear", "/reset"):
            with _STREAM_LOCK:
                RECEIVED_ALERTS.clear()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"cleared")

        else:
            self.send_response(404)
            self.end_headers()


class MockSlackServer:
    """Threaded wrapper around HTTPServer for integration testing and live monitoring."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8089) -> None:
        global CURRENT_SERVER_PORT
        self.host = host
        self.port = port
        CURRENT_SERVER_PORT = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/webhook"

    def start(self) -> None:
        self.server = HTTPServer((self.host, self.port), MockSlackHandler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"Mock Slack Server started at {self.url}")

    def stop(self) -> None:
        stop_stream()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Mock Slack Server stopped.")

    def get_received(self) -> list[dict[str, Any]]:
        return list(RECEIVED_ALERTS)

    def clear(self) -> None:
        with _STREAM_LOCK:
            RECEIVED_ALERTS.clear()


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Webhook Server & Incident Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind")
    parser.add_argument("--port", type=int, default=8089, help="Port to listen on (default: 8089)")
    args = parser.parse_args()

    global CURRENT_SERVER_PORT
    CURRENT_SERVER_PORT = args.port

    server = HTTPServer((args.host, args.port), MockSlackHandler)
    print("\n" + "=" * 60)
    print("      SENTINEL INCIDENT DASHBOARD & WEBHOOK SERVER")
    print("=" * 60)
    print(f"[*] Dashboard URL:     http://{args.host}:{args.port}/")
    print(f"[*] Slack Webhook:     http://{args.host}:{args.port}/webhook")
    print(f"[*] Press Ctrl+C to terminate.")
    print("=" * 60 + "\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server.")
        stop_stream()
        server.shutdown()


if __name__ == "__main__":
    main()
