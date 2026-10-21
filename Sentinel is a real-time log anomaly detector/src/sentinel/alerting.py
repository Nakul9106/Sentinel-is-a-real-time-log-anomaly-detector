"""Alert dispatch engine for Sentinel.

Sends formatted incident alerts to Slack (via Incoming Webhook Block Kit)
and Discord, featuring retry logic, rate limiting, and de-duplication.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import requests
from colorama import Fore, Style, init

from sentinel.config import SentinelConfig
from sentinel.log_parser import ParsedLog

init(autoreset=True)
logger = logging.getLogger("sentinel.alerting")


@dataclass
class AlertPayload:
    """Encapsulates an anomaly incident to alert on."""

    timestamp: str
    raw_log: str
    severity: float
    severity_label: str  # LOW, MEDIUM, HIGH, CRITICAL
    raw_score: float
    reasons: list[str]
    ip: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None

    def fingerprint(self) -> str:
        """Computes a unique signature for deduplication.

        Combines IP and normalized reasons/URL to identify repeats.
        """
        key = f"{self.ip or 'noip'}:{self.method or ''}:{self.url or ''}:{','.join(self.reasons[:2])}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class AlertManager:
    """Manages rate-limited, deduplicated alert dispatch to Slack and Discord."""

    COLOR_MAP = {
        "CRITICAL": "#E01E5A",  # Dark Red
        "HIGH": "#E8912D",      # Orange
        "MEDIUM": "#ECB22E",    # Yellow/Gold
        "LOW": "#2EB886",       # Green
    }

    CONSOLE_COLOR = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.LIGHTRED_EX,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
    }

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self.last_sent_time: float = 0.0
        self.recent_fingerprints: dict[str, float] = {}  # fingerprint -> timestamp
        self.alerts_sent_count: int = 0
        self.alerts_suppressed_count: int = 0
        self.alerts_failed_count: int = 0

    def _should_suppress(self, payload: AlertPayload) -> tuple[bool, str]:
        """Checks rate limiting and deduplication conditions."""
        now = time.time()

        # 1. Clean up stale fingerprints
        dedup_window = self.config.dedup_window_seconds
        stale_keys = [k for k, ts in self.recent_fingerprints.items() if now - ts > dedup_window]
        for k in stale_keys:
            del self.recent_fingerprints[k]

        # 2. Check Deduplication
        fp = payload.fingerprint()
        if fp in self.recent_fingerprints:
            elapsed = now - self.recent_fingerprints[fp]
            if elapsed < dedup_window:
                return True, f"Deduplication: identical pattern alerted {elapsed:.1f}s ago (window: {dedup_window}s)"

        # 3. Check Global Rate Limit
        if (now - self.last_sent_time) < self.config.rate_limit_seconds:
            elapsed = now - self.last_sent_time
            return True, f"Rate limited: alerted {elapsed:.1f}s ago (cooldown: {self.config.rate_limit_seconds}s)"

        return False, ""

    def build_slack_payload(self, alert: AlertPayload) -> dict[str, Any]:
        """Constructs a rich Slack Block Kit message."""
        color = self.COLOR_MAP.get(alert.severity_label, "#E01E5A")
        reasons_text = "\n".join(f"• {r}" for r in alert.reasons) if alert.reasons else "• Statistical anomaly"

        header_text = f":rotating_light: Sentinel Alert: [{alert.severity_label}] Log Anomaly Detected"

        fields = [
            {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity_label} ({alert.severity:.2f})"},
            {"type": "mrkdwn", "text": f"*Raw Model Score:*\n`{alert.raw_score:+.4f}`"},
            {"type": "mrkdwn", "text": f"*Timestamp:*\n{alert.timestamp}"},
            {"type": "mrkdwn", "text": f"*Source IP:*\n`{alert.ip or 'Unknown'}`"},
        ]

        if alert.method and alert.url:
            fields.append({"type": "mrkdwn", "text": f"*HTTP Request:*\n`{alert.method} {alert.url}`"})
        if alert.status_code is not None:
            fields.append({"type": "mrkdwn", "text": f"*Status Code:*\n`{alert.status_code}`"})

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True},
            },
            {
                "type": "section",
                "fields": fields,
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Trigger Reasons:*\n{reasons_text}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Raw Log Line:*\n```{alert.raw_log}```",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Sentinel v0.1.0 | Monitored by IsolationForest | Deduplication ID: `{alert.fingerprint()}`",
                    }
                ],
            },
        ]

        return {
            "text": f"[{alert.severity_label}] Sentinel Log Anomaly Alert ({alert.timestamp})",
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ],
        }

    def print_dry_run_alert(self, alert: AlertPayload) -> None:
        """Displays rich alert diagnostics in the terminal for dry-run mode."""
        col = self.CONSOLE_COLOR.get(alert.severity_label, Fore.RED)
        sep = col + "=" * 70

        print(sep)
        print(f"{col}{Style.BRIGHT}[SENTINEL ALERT] [{alert.severity_label}] Severity: {alert.severity:.3f} | Score: {alert.raw_score:+.4f}")
        print(f"{Fore.WHITE}Time: {alert.timestamp} | IP: {alert.ip or 'N/A'} | Status: {alert.status_code or 'N/A'}")
        if alert.method and alert.url:
            print(f"{Fore.WHITE}Request: {alert.method} {alert.url}")
        print(f"{col}Reasons:")
        for r in alert.reasons:
            print(f"  {col}* {r}", flush=True)
        print(f"{Fore.LIGHTBLACK_EX}Raw: {alert.raw_log}", flush=True)
        print(sep, flush=True)

    def send_alert(self, alert: AlertPayload) -> bool:
        """Sends alert to configured webhook endpoint with retry and suppression checks."""
        should_suppress, reason = self._should_suppress(alert)
        if should_suppress:
            self.alerts_suppressed_count += 1
            logger.debug(f"Alert suppressed: {reason}")
            return False

        # If dry-run is enabled, print formatted alert and record state without sending HTTP request
        if self.config.dry_run:
            self.print_dry_run_alert(alert)
            now = time.time()
            self.last_sent_time = now
            self.recent_fingerprints[alert.fingerprint()] = now
            self.alerts_sent_count += 1
            return True

        # Resolve webhook URL
        webhook_url = self.config.resolve_webhook_url()
        if not webhook_url:
            logger.warning("No Slack webhook URL configured (set SLACK_WEBHOOK_URL). Alert logged locally.")
            self.print_dry_run_alert(alert)
            return False

        payload_json = self.build_slack_payload(alert)
        headers = {"Content-Type": "application/json"}

        # Retry loop
        for attempt in range(1, self.config.max_retries + 1):
            try:
                resp = requests.post(
                    webhook_url,
                    json=payload_json,
                    headers=headers,
                    timeout=self.config.webhook_timeout,
                )
                if resp.status_code in (200, 204):
                    now = time.time()
                    self.last_sent_time = now
                    self.recent_fingerprints[alert.fingerprint()] = now
                    self.alerts_sent_count += 1
                    logger.info(f"Alert successfully sent to Slack (HTTP {resp.status_code}).")
                    return True
                else:
                    logger.warning(
                        f"Slack webhook attempt {attempt}/{self.config.max_retries} returned HTTP {resp.status_code}: {resp.text}"
                    )
            except requests.RequestException as err:
                logger.warning(
                    f"Slack webhook attempt {attempt}/{self.config.max_retries} failed: {err}"
                )

            if attempt < self.config.max_retries:
                time.sleep(1.0 * attempt)

        self.alerts_failed_count += 1
        logger.error(f"Failed to deliver alert after {self.config.max_retries} retries.")
        return False
