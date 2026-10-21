"""Offline model training and retraining pipeline for Sentinel.

Reads normal baseline logs, extracts features, trains an unsupervised anomaly
detector, and serializes the complete pipeline for real-time inference.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
import numpy as np
from colorama import Fore, Style, init

from sentinel.anomaly_model import AnomalyDetector
from sentinel.config import load_config
from sentinel.log_parser import LogParser, ParsedLog

init(autoreset=True)


def train_model(
    input_path: Path | str,
    output_path: Path | str,
    model_type: str = "isolation_forest",
    contamination: float = 0.01,
    threshold: float = 0.65,
) -> AnomalyDetector:
    """Trains and serializes the AnomalyDetector on normal log lines."""
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"Training log file not found at: '{input_file}'")

    print(f"{Fore.CYAN}[*] Reading baseline logs from: {input_file}")
    t0 = time.time()

    parser = LogParser()
    parsed_logs: list[ParsedLog] = []

    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            clean = line.strip()
            if clean:
                parsed = parser.parse_line(clean)
                parsed_logs.append(parsed)

    read_elapsed = time.time() - t0
    stats = parser.get_stats()
    print(
        f"{Fore.GREEN}[+] Loaded {len(parsed_logs):,} lines in {read_elapsed:.2f}s "
        f"(Parsed: {stats['parsed_count']:,}, Fallback: {stats['fallback_count']:,}, Failed: {stats['failed_count']})"
    )

    if not parsed_logs:
        raise ValueError(f"No valid log entries found in '{input_file}' to train on.")

    # Instantiate and fit AnomalyDetector
    print(f"{Fore.CYAN}[*] Training {model_type.upper()} (contamination={contamination:.4f})...")
    t1 = time.time()

    detector = AnomalyDetector(
        model_type=model_type,
        contamination=contamination,
        threshold=threshold,
    )
    detector.fit(parsed_logs)
    train_elapsed = time.time() - t1

    # Extract score metrics on training set
    X_train = detector.feature_extractor.transform(parsed_logs)
    train_scores = detector.raw_score(X_train)
    p1 = float(np.percentile(train_scores, 1))
    p5 = float(np.percentile(train_scores, 5))
    mean_sc = float(np.mean(train_scores))
    std_sc = float(np.std(train_scores))

    # Save to disk
    output_file.parent.mkdir(parents=True, exist_ok=True)
    detector.save(output_file)

    # Print summary report
    print(f"\n{Fore.GREEN}{Style.BRIGHT}================ TRAINING SUMMARY ================")
    print(f"Model Type:            {model_type.upper()}")
    print(f"Training Samples:      {len(parsed_logs):,}")
    print(f"Feature Dimensions:    {X_train.shape[1]} features")
    print(f"Training Duration:     {train_elapsed:.2f}s")
    print(f"Raw Score Distribution on Baseline:")
    print(f"  * Mean Score:        {mean_sc:+.4f} (std: {std_sc:.4f})")
    print(f"  * Min Score:         {float(np.min(train_scores)):+.4f}")
    print(f"  * Max Score:         {float(np.max(train_scores)):+.4f}")
    print(f"  * 1st Percentile:    {p1:+.4f}")
    print(f"  * 5th Percentile:    {p5:+.4f}")
    print(f"Configured Threshold:  {threshold} (Severity)")
    print(f"Model Serialized To:   {output_file.resolve()}")
    print(f"{Fore.GREEN}{Style.BRIGHT}==================================================\n")

    return detector


def main() -> None:
    """CLI entrypoint for training Sentinel models."""
    parser = argparse.ArgumentParser(description="Train Sentinel Anomaly Detection Model")
    parser.add_argument("--input", "-i", default=None, help="Path to input normal log file (default from config)")
    parser.add_argument("--output", "-o", default=None, help="Path to save trained model (default from config)")
    parser.add_argument("--contamination", "-c", type=float, default=None, help="Expected outlier rate (e.g. 0.01)")
    parser.add_argument("--model-type", "-m", choices=["isolation_forest", "one_class_svm"], default=None, help="Model algorithm")
    parser.add_argument("--threshold", "-t", type=float, default=None, help="Anomaly severity threshold (0.0 to 1.0)")
    parser.add_argument("--config", help="Path to YAML config file")

    args = parser.parse_args()

    # Load defaults from config
    cfg = load_config(
        config_file=args.config,
        cli_overrides={
            "log_file": Path(args.input) if args.input else None,
            "model_path": Path(args.output) if args.output else None,
            "contamination": args.contamination,
            "model_type": args.model_type,
            "threshold": args.threshold,
        },
    )

    # If --input not specified and default config is data/app.log, prefer data/normal.log if exists
    input_path = cfg.log_file
    if args.input is None and Path("data/normal.log").is_file():
        input_path = Path("data/normal.log")

    try:
        train_model(
            input_path=input_path,
            output_path=cfg.model_path,
            model_type=cfg.model_type,
            contamination=cfg.contamination,
            threshold=cfg.threshold,
        )
    except Exception as err:
        print(f"{Fore.RED}[!] Training failed: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
