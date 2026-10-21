"""Sentinel: Real-time Log Anomaly Detector.

Continuous monitoring daemon that tails log streams, parses entries,
extracts features, scores anomalies via unsupervised ML, and dispatches
real-time alerts to Slack or Discord.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init

from sentinel.alerting import AlertManager, AlertPayload
from sentinel.anomaly_model import AnomalyDetector
from sentinel.config import SentinelConfig, load_config
from sentinel.log_ingestor import LogIngestor
from sentinel.log_parser import LogParser, ParsedLog

init(autoreset=True)


class SentinelRunner:
    """Orchestrates the tail -> parse -> featurize -> predict -> alert loop."""

    def __init__(self, config: SentinelConfig) -> None:
        self.config = config
        self._setup_logging()
        self.logger = logging.getLogger("sentinel.runner")

        self.parser = LogParser()
        self.alert_manager = AlertManager(config)
        self.detector: Optional[AnomalyDetector] = None

        self.total_processed: int = 0
        self.anomalies_detected: int = 0
        self.normal_detected: int = 0
        self.start_time: float = 0.0
        self.is_running: bool = False

    def _setup_logging(self) -> None:
        level_name = (self.config.log_level or "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def load_model(self) -> None:
        """Loads the pre-trained AnomalyDetector model."""
        model_path = self.config.model_path
        if not model_path.is_file():
            print(
                f"{Fore.RED}[!] Model file not found at: {model_path.resolve()}\n"
                f"{Fore.YELLOW}[*] Please train the model first by running:\n"
                f"    python -m sentinel.train --input data/normal.log --output {model_path}\n"
                f"    or: sentinel-train --input data/normal.log\n",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            self.detector = AnomalyDetector.load(model_path)
            # Apply configured threshold overrides
            self.detector.threshold = self.config.threshold
            self.detector.raw_threshold = self.config.raw_threshold
            self.logger.info(f"Loaded {self.detector.model_type.upper()} model from '{model_path}'")
        except Exception as err:
            self.logger.error(f"Failed to load model from '{model_path}': {err}")
            sys.exit(1)

    def run(self) -> None:
        """Runs the main ingestion and anomaly detection loop."""
        self.load_model()
        assert self.detector is not None

        self.is_running = True
        self.start_time = time.time()

        print(f"\n{Fore.CYAN}{Style.BRIGHT}================ SENTINEL ACTIVE ================")
        print(f"Monitoring Log:      {self.config.log_file.resolve()}")
        print(f"Model Path:          {self.config.model_path.resolve()} ({self.detector.model_type})")
        print(f"Severity Threshold:  {self.config.threshold} (0.0=normal, 1.0=critical)")
        print(f"Alert Destination:   {'Dry Run (Console)' if self.config.dry_run else (self.config.resolve_webhook_url() or 'None')}")
        print(f"Rate Limit Cooldown: {self.config.rate_limit_seconds}s")
        print(f"Log Level:           {self.config.log_level}")
        print(f"Press Ctrl+C to terminate cleanly.")
        print(f"{Fore.CYAN}{Style.BRIGHT}==================================================\n")

        ingestor = LogIngestor(
            file_path=self.config.log_file,
            poll_interval=self.config.poll_interval,
            from_start=self.config.from_start,
        )

        # Micro-batching buffer
        batch: list[ParsedLog] = []
        batch_size = max(1, self.config.batch_size)

        try:
            for line in ingestor.tail():
                if not self.is_running:
                    break

                clean_line = line.strip()
                if not clean_line:
                    continue

                parsed = self.parser.parse_line(clean_line)

                if batch_size > 1:
                    batch.append(parsed)
                    if len(batch) >= batch_size:
                        self._process_batch(batch)
                        batch.clear()
                else:
                    self._process_single(parsed)

            # Flush any remaining items in buffer
            if batch:
                self._process_batch(batch)
                batch.clear()

        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def _process_single(self, parsed: ParsedLog) -> None:
        """Process a single parsed log line."""
        assert self.detector is not None
        result = self.detector.predict_one(parsed)
        self.total_processed += 1

        if result["is_anomaly"]:
            self.anomalies_detected += 1
            self._handle_anomaly(result, parsed)
        else:
            self.normal_detected += 1
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"[NORMAL] (score: {result['raw_score']:+.4f}) {parsed.summary()}")
            elif self.total_processed % 250 == 0:
                # Occasional heartbeat indicator in high throughput
                sys.stdout.write(f"\r{Fore.GREEN}[*] Sentinel active: {self.total_processed:,} logs processed ({self.anomalies_detected} anomalies)")
                sys.stdout.flush()

    def _process_batch(self, batch: list[ParsedLog]) -> None:
        """Process a batch of parsed log lines efficiently."""
        assert self.detector is not None
        results = self.detector.predict_batch(batch)
        self.total_processed += len(batch)

        for result, parsed in zip(results, batch):
            if result["is_anomaly"]:
                self.anomalies_detected += 1
                self._handle_anomaly(result, parsed)
            else:
                self.normal_detected += 1

    def _handle_anomaly(self, result: dict, parsed: ParsedLog) -> None:
        """Dispatches alert for an anomaly."""
        alert = AlertPayload(
            timestamp=parsed.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            raw_log=parsed.raw,
            severity=result["severity"],
            severity_label=result["severity_label"],
            raw_score=result["raw_score"],
            reasons=result["reasons"],
            ip=parsed.ip,
            method=parsed.method,
            url=parsed.url,
            status_code=parsed.status_code,
        )
        self.alert_manager.send_alert(alert)

    def shutdown(self) -> None:
        """Prints final execution metrics upon exit."""
        self.is_running = False
        elapsed = time.time() - self.start_time if self.start_time > 0 else 0.0
        rate = (self.total_processed / elapsed) if elapsed > 0 else 0.0

        p_stats = self.parser.get_stats()
        print(f"\n\n{Fore.CYAN}{Style.BRIGHT}================ SENTINEL SHUTDOWN SUMMARY ================")
        print(f"Total Runtime:           {elapsed:.2f}s")
        print(f"Total Logs Processed:    {self.total_processed:,}")
        print(f"Throughput:              {rate:,.1f} logs/second")
        print(f"Normal Logs:             {self.normal_detected:,}")
        print(f"Anomalies Flagged:       {self.anomalies_detected:,}")
        print(f"Alerts Dispatched:       {self.alert_manager.alerts_sent_count:,}")
        print(f"Alerts Suppressed:       {self.alert_manager.alerts_suppressed_count:,} (rate-limit / dedup)")
        print(f"Parsing Breakdown:       {p_stats['parsed_count']:,} structured | {p_stats['fallback_count']:,} fallback | {p_stats['failed_count']} failed")
        print(f"{Fore.CYAN}{Style.BRIGHT}===========================================================\n")


def main() -> None:
    """CLI entrypoint for running Sentinel."""
    parser = argparse.ArgumentParser(description="Sentinel: Real-time Log Anomaly Detector")
    parser.add_argument("--log-file", "-f", default=None, help="Path to monitored log file")
    parser.add_argument("--model-path", "-m", default=None, help="Path to trained model (.joblib)")
    parser.add_argument("--config", "-c", default=None, help="Path to YAML configuration file")
    parser.add_argument("--threshold", "-t", type=float, default=None, help="Anomaly severity threshold (0.0 to 1.0)")
    parser.add_argument("--dry-run", action="store_true", default=None, help="Print alerts locally without sending network requests")
    parser.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="Send live webhook alerts to Slack")
    parser.add_argument("--from-start", action="store_true", default=None, help="Read log file from beginning instead of seeking to end")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size for inference (default: 1)")
    parser.add_argument("--poll-interval", type=float, default=None, help="Poll interval in seconds (default: 0.1)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default=None, help="Console logging verbosity")

    args = parser.parse_args()

    cli_overrides = {
        "log_file": Path(args.log_file) if args.log_file else None,
        "model_path": Path(args.model_path) if args.model_path else None,
        "threshold": args.threshold,
        "dry_run": args.dry_run,
        "from_start": args.from_start,
        "batch_size": args.batch_size,
        "poll_interval": args.poll_interval,
        "log_level": args.log_level,
    }

    config = load_config(config_file=args.config, cli_overrides=cli_overrides)
    runner = SentinelRunner(config)

    # Clean signal handling for Windows & Unix
    def handle_signal(sig, frame):
        runner.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_signal)

    runner.run()


if __name__ == "__main__":
    main()
