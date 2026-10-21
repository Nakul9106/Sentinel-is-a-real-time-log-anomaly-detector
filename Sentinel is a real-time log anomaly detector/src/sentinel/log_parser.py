"""Log parsing engine for Sentinel.

Parses unstructured log lines into typed ParsedLog objects.
Supports Nginx/Apache Combined format, standard application logs, and a resilient
fallback parser that never crashes on malformed input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ParsedLog:
    """Structured representation of a parsed log entry."""

    raw: str
    format: str  # 'nginx_combined', 'custom_app', 'fallback', 'unparsed'
    timestamp: Optional[str] = None
    level: str = "INFO"
    ip: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    message: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error_status(self) -> bool:
        """Returns True if HTTP status is 4xx or 5xx, or level is ERROR/CRITICAL."""
        if self.status_code is not None and self.status_code >= 400:
            return True
        return self.level in ("ERROR", "CRITICAL", "WARN", "WARNING")

    def to_dict(self) -> dict[str, Any]:
        """Convert parsed log to serializable dictionary."""
        return {
            "format": self.format,
            "timestamp": self.timestamp,
            "level": self.level,
            "ip": self.ip,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "bytes_sent": self.bytes_sent,
            "message": self.message,
            "raw": self.raw,
        }

    def summary(self) -> str:
        """Brief one-line summary for logging and alerts."""
        parts = []
        if self.ip:
            parts.append(self.ip)
        if self.method and self.url:
            parts.append(f"{self.method} {self.url}")
        if self.status_code is not None:
            parts.append(f"HTTP {self.status_code}")
        if self.level:
            parts.append(f"[{self.level}]")
        if self.message:
            short_msg = self.message[:80] + ("..." if len(self.message) > 80 else "")
            parts.append(f"- {short_msg}")
        return " | ".join(parts) if parts else self.raw[:100]


class LogParser:
    """High-throughput regex-based log parser with fallback recovery."""

    # 1. Nginx / Apache Combined Format:
    # 192.168.1.1 - - [20/Oct/2026:14:32:10 +0000] "GET /api/v1/products HTTP/1.1" 200 1024 "http://..." "Mozilla/5.0..."
    NGINX_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/[0-9.]+)?(?: [^"]*)?"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # 2. Custom App Log Format:
    # e.g.: "2026-10-20 14:32:11 ERROR 192.168.1.5 Database connection failed"
    # or:   "2026-10-20 14:32:11 [ERROR] 192.168.1.5 GET /api/users 500 Connection timeout"
    APP_PATTERN_WITH_HTTP = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?:\[?(?P<level>[A-Z]{4,8})\]?)\s+'
        r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+'
        r'(?:(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<status>\d{3})\s+)?'
        r'(?P<message>.*)$'
    )

    # Simple App Log Format:
    # "2026-10-20 14:32:11 ERROR 192.168.1.5 Database connection failed"
    APP_PATTERN_SIMPLE = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?:\[?(?P<level>[A-Z]{4,8})\]?)\s+'
        r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\s+'
        r'(?P<message>.*)$'
    )

    # Fallback extraction patterns
    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    STATUS_REGEX = re.compile(r'\b([1-5]\d{2})\b')
    METHOD_REGEX = re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')
    LEVEL_REGEX = re.compile(r'\b(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL)\b')

    def __init__(self) -> None:
        self.total_lines: int = 0
        self.parsed_count: int = 0
        self.fallback_count: int = 0
        self.failed_count: int = 0

    def parse_line(self, line: str) -> ParsedLog:
        """Parse a single raw log line into a structured ParsedLog.

        Never raises an uncaught exception; falls back gracefully.
        """
        self.total_lines += 1
        clean_line = line.strip()

        if not clean_line:
            self.failed_count += 1
            return ParsedLog(raw=line, format="unparsed", message="<empty line>")

        try:
            # 1. Attempt Nginx/Apache Combined match
            nginx_match = self.NGINX_PATTERN.match(clean_line)
            if nginx_match:
                groups = nginx_match.groupdict()
                bytes_sent = int(groups["bytes"]) if groups.get("bytes") and groups["bytes"] != "-" else 0
                status_code = int(groups["status"])
                level = "ERROR" if status_code >= 500 else ("WARN" if status_code >= 400 else "INFO")

                extra = {}
                if groups.get("referer"):
                    extra["referer"] = groups["referer"]
                if groups.get("user_agent"):
                    extra["user_agent"] = groups["user_agent"]

                self.parsed_count += 1
                return ParsedLog(
                    raw=clean_line,
                    format="nginx_combined",
                    timestamp=groups.get("timestamp"),
                    level=level,
                    ip=groups.get("ip"),
                    method=groups.get("method"),
                    url=groups.get("url"),
                    status_code=status_code,
                    bytes_sent=bytes_sent,
                    message=f"{groups.get('method')} {groups.get('url')} HTTP {status_code}",
                    extra=extra,
                )

            # 2. Attempt App pattern with HTTP details
            app_match = self.APP_PATTERN_WITH_HTTP.match(clean_line)
            if app_match:
                groups = app_match.groupdict()
                status = int(groups["status"]) if groups.get("status") else None
                level = groups.get("level") or "INFO"
                if level == "WARNING":
                    level = "WARN"

                self.parsed_count += 1
                return ParsedLog(
                    raw=clean_line,
                    format="custom_app",
                    timestamp=groups.get("timestamp"),
                    level=level,
                    ip=groups.get("ip"),
                    method=groups.get("method"),
                    url=groups.get("url"),
                    status_code=status,
                    message=groups.get("message", "").strip(),
                )

            # 3. Attempt Simple App pattern
            simple_match = self.APP_PATTERN_SIMPLE.match(clean_line)
            if simple_match:
                groups = simple_match.groupdict()
                level = groups.get("level") or "INFO"
                if level == "WARNING":
                    level = "WARN"

                msg = groups.get("message", "").strip()
                # Check if message contains method/url/status
                method_m = self.METHOD_REGEX.search(msg)
                status_m = self.STATUS_REGEX.search(msg)

                self.parsed_count += 1
                return ParsedLog(
                    raw=clean_line,
                    format="custom_app",
                    timestamp=groups.get("timestamp"),
                    level=level,
                    ip=groups.get("ip"),
                    method=method_m.group(1) if method_m else None,
                    url=None,
                    status_code=int(status_m.group(1)) if status_m else None,
                    message=msg,
                )

            # 4. Fallback parser: Extract whatever components exist
            return self._parse_fallback(clean_line)

        except Exception as err:
            # Absolute safety net: never let an unexpected exception escape
            self.failed_count += 1
            return ParsedLog(
                raw=clean_line,
                format="unparsed",
                message=f"Parser recovery: {err}",
            )

    def _parse_fallback(self, line: str) -> ParsedLog:
        """Extract best-effort fields from an unstructured or non-standard log line."""
        self.fallback_count += 1

        ip_m = self.IP_REGEX.search(line)
        # Strip IP address before extracting status code to avoid matching octets (e.g. 172.16.0.4)
        line_no_ip = self.IP_REGEX.sub(" ", line)
        status_m = self.STATUS_REGEX.search(line_no_ip)
        method_m = self.METHOD_REGEX.search(line)
        level_m = self.LEVEL_REGEX.search(line)

        status_code = int(status_m.group(1)) if status_m else None
        level = level_m.group(1) if level_m else ("ERROR" if status_code and status_code >= 500 else "INFO")
        if level == "WARNING":
            level = "WARN"

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        return ParsedLog(
            raw=line,
            format="fallback",
            timestamp=now_utc,
            level=level,
            ip=ip_m.group(0) if ip_m else None,
            method=method_m.group(1) if method_m else None,
            url=None,
            status_code=status_code,
            message=line,
        )

    def get_stats(self) -> dict[str, int]:
        """Returns parser operational metrics."""
        return {
            "total_lines": self.total_lines,
            "parsed_count": self.parsed_count,
            "fallback_count": self.fallback_count,
            "failed_count": self.failed_count,
        }
