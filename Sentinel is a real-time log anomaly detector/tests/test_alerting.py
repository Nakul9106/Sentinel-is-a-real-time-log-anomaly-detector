"""Unit and integration tests for AlertManager."""

import time
import pytest
from sentinel.alerting import AlertManager, AlertPayload
from sentinel.config import SentinelConfig
from scripts.mock_slack_server import MockSlackServer


@pytest.fixture
def sample_alert():
    return AlertPayload(
        timestamp="2026-10-20 14:00:00",
        raw_log='198.51.100.42 - - [20/Oct/2026:14:00:00 +0000] "GET /login?user=admin\'%20OR%201=1;-- HTTP/1.1" 500 120 "-" "sqlmap"',
        severity=0.92,
        severity_label="CRITICAL",
        raw_score=-0.2450,
        reasons=["Suspicious patterns detected: select, 1=1, --", "Server error: HTTP 500"],
        ip="198.51.100.42",
        method="GET",
        url="/login?user=admin' OR 1=1;--",
        status_code=500,
    )


def test_build_slack_payload(sample_alert):
    config = SentinelConfig(dry_run=True)
    manager = AlertManager(config)
    payload = manager.build_slack_payload(sample_alert)

    assert "text" in payload
    assert "[CRITICAL]" in payload["text"]
    assert "attachments" in payload
    assert len(payload["attachments"]) == 1

    blocks = payload["attachments"][0]["blocks"]
    assert any(b.get("type") == "header" for b in blocks)
    assert any("198.51.100.42" in str(b) for b in blocks)
    assert any("Suspicious patterns detected" in str(b) for b in blocks)


def test_dry_run_mode(sample_alert):
    config = SentinelConfig(dry_run=True)
    manager = AlertManager(config)

    success = manager.send_alert(sample_alert)
    assert success is True
    assert manager.alerts_sent_count == 1


def test_rate_limiting_and_deduplication(sample_alert):
    config = SentinelConfig(dry_run=True, rate_limit_seconds=2.0, dedup_window_seconds=5.0)
    manager = AlertManager(config)

    # First alert sent
    sent1 = manager.send_alert(sample_alert)
    assert sent1 is True

    # Immediate second alert with same fingerprint is deduplicated
    sent2 = manager.send_alert(sample_alert)
    assert sent2 is False
    assert manager.alerts_suppressed_count >= 1

    # Immediate alert with different fingerprint is rate-limited
    diff_alert = AlertPayload(
        timestamp="2026-10-20 14:00:01",
        raw_log="other attack line",
        severity=0.88,
        severity_label="HIGH",
        raw_score=-0.18,
        reasons=["Different reason"],
        ip="10.0.0.99",
    )
    sent3 = manager.send_alert(diff_alert)
    assert sent3 is False
    assert manager.alerts_suppressed_count >= 2


def test_mock_slack_server_integration(sample_alert):
    # Start mock server on dedicated test port
    mock_server = MockSlackServer(port=8099)
    mock_server.start()

    try:
        config = SentinelConfig(
            dry_run=False,
            webhook_url=mock_server.url,
            rate_limit_seconds=0.01,
            dedup_window_seconds=0.01,
        )
        manager = AlertManager(config)

        # Dispatch real HTTP alert to local mock server
        success = manager.send_alert(sample_alert)
        assert success is True

        # Verify mock server received the payload
        received = mock_server.get_received()
        assert len(received) >= 1

        first = received[0]["payload"]
        assert "attachments" in first
        assert "[CRITICAL]" in first["text"]

    finally:
        mock_server.stop()
