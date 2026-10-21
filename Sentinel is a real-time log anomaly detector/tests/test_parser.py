"""Unit tests for LogParser."""

import pytest
from sentinel.log_parser import LogParser, ParsedLog


@pytest.fixture
def parser():
    return LogParser()


def test_parse_nginx_combined_standard(parser):
    line = (
        '192.168.1.100 - - [20/Oct/2026:14:32:10 +0000] '
        '"GET /api/v1/products HTTP/1.1" 200 1024 '
        '"https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    parsed = parser.parse_line(line)

    assert parsed.format == "nginx_combined"
    assert parsed.ip == "192.168.1.100"
    assert parsed.method == "GET"
    assert parsed.url == "/api/v1/products"
    assert parsed.status_code == 200
    assert parsed.bytes_sent == 1024
    assert parsed.level == "INFO"
    assert not parsed.is_error_status
    assert parsed.extra.get("referer") == "https://example.com"


def test_parse_nginx_combined_error(parser):
    line = (
        '10.0.0.5 - - [20/Oct/2026:14:35:00 +0000] '
        '"POST /checkout HTTP/1.1" 500 452 "-" "curl/8.4.0"'
    )
    parsed = parser.parse_line(line)

    assert parsed.format == "nginx_combined"
    assert parsed.status_code == 500
    assert parsed.level == "ERROR"
    assert parsed.is_error_status


def test_parse_custom_app_standard(parser):
    line = "2026-10-20 14:32:11 ERROR 192.168.1.5 Database connection failed"
    parsed = parser.parse_line(line)

    assert parsed.format == "custom_app"
    assert parsed.level == "ERROR"
    assert parsed.ip == "192.168.1.5"
    assert "Database connection failed" in parsed.message
    assert parsed.is_error_status


def test_parse_custom_app_with_http(parser):
    line = "2026-10-20 14:32:11 [INFO] 10.0.0.12 GET /api/v1/users 200 Fetch user profile"
    parsed = parser.parse_line(line)

    assert parsed.format == "custom_app"
    assert parsed.level == "INFO"
    assert parsed.ip == "10.0.0.12"
    assert parsed.method == "GET"
    assert parsed.url == "/api/v1/users"
    assert parsed.status_code == 200
    assert not parsed.is_error_status


def test_parse_empty_line(parser):
    parsed = parser.parse_line("   ")
    assert parsed.format == "unparsed"
    assert parser.failed_count == 1


def test_parse_fallback_unstructured(parser):
    line = "Corrupted raw log line with ip 172.16.0.4 and status 404 something bad happened"
    parsed = parser.parse_line(line)

    assert parsed.format == "fallback"
    assert parsed.ip == "172.16.0.4"
    assert parsed.status_code == 404
    assert parser.fallback_count >= 1


def test_parser_never_crashes(parser):
    corrupted_lines = [
        "!!!@@@###$$$%%%^^^&&&***()",
        "\x00\x01\x02\x03\x04 binary junk",
        "2026-99-99 99:99:99 WRONG FORMAT",
        "127.0.0.1 - [broken",
    ]
    for line in corrupted_lines:
        parsed = parser.parse_line(line)
        assert isinstance(parsed, ParsedLog)
        assert parsed.raw == line
