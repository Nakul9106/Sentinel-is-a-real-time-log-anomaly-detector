"""Unit tests for LogIngestor."""

import time
from threading import Thread
import pytest
from sentinel.log_ingestor import LogIngestor


def test_tail_from_start(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("line 1\nline 2\n", encoding="utf-8")

    ingestor = LogIngestor(log_file, poll_interval=0.01, from_start=True)
    lines = []

    def consume():
        for line in ingestor.tail():
            lines.append(line.strip())
            if len(lines) == 3:
                ingestor.stop()

    t = Thread(target=consume, daemon=True)
    t.start()

    time.sleep(0.05)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("line 3\n")

    t.join(timeout=2.0)
    assert lines == ["line 1", "line 2", "line 3"]


def test_tail_truncation_detection(tmp_path):
    log_file = tmp_path / "test_trunc.log"
    log_file.write_text("initial large content line 1\ninitial large content line 2\n", encoding="utf-8")

    ingestor = LogIngestor(log_file, poll_interval=0.02, from_start=True)
    collected = []

    def consume():
        for line in ingestor.tail():
            collected.append(line.strip())
            if len(collected) >= 3:
                ingestor.stop()

    t = Thread(target=consume, daemon=True)
    t.start()

    # Wait for initial lines to be consumed
    time.sleep(0.1)

    # Now truncate and write a new line
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("truncated new line\n")

    t.join(timeout=2.0)
    assert ingestor.truncations_detected >= 1
    assert "truncated new line" in collected


def test_tail_missing_file_waits(tmp_path):
    missing_file = tmp_path / "future.log"
    ingestor = LogIngestor(missing_file, poll_interval=0.02, from_start=True)
    collected = []

    def consume():
        for line in ingestor.tail():
            collected.append(line.strip())
            if len(collected) >= 1:
                ingestor.stop()

    t = Thread(target=consume, daemon=True)
    t.start()

    time.sleep(0.08)
    missing_file.write_text("delayed line\n", encoding="utf-8")

    t.join(timeout=2.0)
    assert collected == ["delayed line"]
