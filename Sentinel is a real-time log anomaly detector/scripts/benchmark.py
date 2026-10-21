"""Sentinel high-throughput performance benchmark.

Measures parser throughput, feature extraction latency, and inference speed
under high-volume traffic.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from sentinel.anomaly_model import AnomalyDetector
from sentinel.config import SentinelConfig
from sentinel.generate_logs import generate_to_file
from sentinel.log_parser import LogParser


def run_benchmark(count: int = 10000, batch_size: int = 50, log_path: str = "data/perf_benchmark.log") -> None:
    path = Path(log_path)
    model_path = Path("models/sentinel_model.joblib")

    if not model_path.is_file():
        print("[!] Model file not found. Please train models/sentinel_model.joblib first.")
        return

    # Generate benchmark logs
    if path.is_file():
        path.unlink()
    print(f"[*] Generating {count:,} mixed benchmark logs at '{path}'...")
    t_gen0 = time.perf_counter()
    generate_to_file(path, count=count, mode="mixed", delay=0.0, anomaly_rate=0.02)
    t_gen = time.perf_counter() - t_gen0
    print(f"[+] Data generated in {t_gen:.2f}s ({count / t_gen:,.0f} lines/sec)\n")

    # Load model and parser
    print(f"[*] Loading Sentinel AnomalyDetector from '{model_path}'...")
    detector = AnomalyDetector.load(model_path)
    parser = LogParser()

    print(f"[*] Starting high-throughput evaluation (Batch Size: {batch_size})...")
    t0 = time.perf_counter()
    parsed_batch = []
    total_parsed = 0
    total_anomalies = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            clean = line.strip()
            if not clean:
                continue
            p = parser.parse_line(clean)
            parsed_batch.append(p)
            total_parsed += 1

            if len(parsed_batch) >= batch_size:
                results = detector.predict_batch(parsed_batch)
                total_anomalies += sum(1 for r in results if r["is_anomaly"])
                parsed_batch.clear()

        if parsed_batch:
            results = detector.predict_batch(parsed_batch)
            total_anomalies += sum(1 for r in results if r["is_anomaly"])
            parsed_batch.clear()

    t1 = time.perf_counter()
    total_time = t1 - t0
    rate = total_parsed / total_time
    latency_us = (total_time / total_parsed) * 1_000_000

    print("\n================ BENCHMARK RESULTS ================")
    print(f"Total Logs Evaluated:   {total_parsed:,}")
    print(f"Batch Size:             {batch_size}")
    print(f"Elapsed Time:           {total_time:.3f} seconds")
    print(f"Throughput:             {rate:,.1f} lines/second")
    print(f"Average Latency:        {latency_us:.2f} microseconds / line ({latency_us / 1000:.3f} ms)")
    print(f"Anomalies Detected:     {total_anomalies:,} ({(total_anomalies / total_parsed) * 100:.2f}%)")
    print("===================================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Performance Benchmark")
    parser.add_argument("--count", "-c", type=int, default=10000, help="Number of benchmark logs")
    parser.add_argument("--batch-size", "-b", type=int, default=50, help="Micro-batch size")
    parser.add_argument("--log-path", default="data/perf_benchmark.log", help="Path to write benchmark log")
    args = parser.parse_args()

    run_benchmark(count=args.count, batch_size=args.batch_size, log_path=args.log_path)


if __name__ == "__main__":
    main()
