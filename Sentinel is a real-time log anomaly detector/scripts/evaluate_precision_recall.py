"""Evaluates precision, recall, and F1-score of Sentinel on a labeled test set.

Generates ground-truth labeled logs (normal vs. attack vectors) and computes
confusion matrix and classification metrics.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from colorama import Fore, Style, init

from sentinel.anomaly_model import AnomalyDetector
from sentinel.generate_logs import generate_attack_log, generate_normal_log
from sentinel.log_parser import LogParser

init(autoreset=True)


def evaluate_labeled_set(
    model_path: Path | str = "models/sentinel_model.joblib",
    normal_count: int = 1000,
    attack_count: int = 100,
    threshold: float = 0.65,
) -> dict[str, float]:
    """Runs evaluation and returns classification metrics."""
    model_file = Path(model_path)
    if not model_file.is_file():
        raise FileNotFoundError(f"Trained model not found at '{model_file}'")

    detector = AnomalyDetector.load(model_file)
    detector.threshold = threshold
    parser = LogParser()

    print(f"{Fore.CYAN}[*] Evaluating Sentinel Model: {model_file.resolve()}")
    print(f"[*] Generating {normal_count} normal logs and {attack_count} attack logs...")

    # Build labeled test dataset: (raw_line, is_anomaly, attack_category)
    test_set: list[tuple[str, bool, str]] = []

    for _ in range(normal_count):
        line = generate_normal_log()
        test_set.append((line, False, "Normal"))

    for _ in range(attack_count):
        line, cat = generate_attack_log()
        test_set.append((line, True, cat))

    tp = 0  # Attack predicted as Anomaly
    fp = 0  # Normal predicted as Anomaly
    tn = 0  # Normal predicted as Normal
    fn = 0  # Attack predicted as Normal

    category_stats: dict[str, dict[str, int]] = {}

    for line, ground_truth_anomaly, category in test_set:
        parsed = parser.parse_line(line)
        res = detector.predict_one(parsed)
        pred_anomaly = res["is_anomaly"]

        if category not in category_stats:
            category_stats[category] = {"total": 0, "detected": 0}
        category_stats[category]["total"] += 1

        if ground_truth_anomaly:
            if pred_anomaly:
                tp += 1
                category_stats[category]["detected"] += 1
            else:
                fn += 1
        else:
            if pred_anomaly:
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(test_set) if test_set else 0.0

    print(f"\n{Fore.GREEN}{Style.BRIGHT}================ CLASSIFICATION REPORT ================")
    print(f"Total Test Samples:    {len(test_set):,} (Normal: {normal_count:,}, Attacks: {attack_count:,})")
    print(f"Severity Threshold:    {threshold}")
    print(f"-------------------------------------------------------")
    print(f"True Positives (TP):   {tp:4d}  | False Positives (FP): {fp:4d}")
    print(f"False Negatives (FN):  {fn:4d}  | True Negatives (TN):  {tn:4d}")
    print(f"-------------------------------------------------------")
    print(f"Accuracy:              {accuracy * 100:.2f}%")
    print(f"Precision:             {precision * 100:.2f}%")
    print(f"Recall:                {recall * 100:.2f}%")
    print(f"F1-Score:              {f1:.4f}")
    print(f"-------------------------------------------------------")
    print(f"Detection by Category:")
    for cat, data in sorted(category_stats.items()):
        if cat != "Normal":
            det_rate = (data["detected"] / data["total"]) * 100 if data["total"] > 0 else 0.0
            print(f"  * {cat:<38s}: {data['detected']:3d}/{data['total']:3d} ({det_rate:.1f}%)")
    print(f"{Fore.GREEN}{Style.BRIGHT}=======================================================\n")

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Sentinel model precision & recall")
    parser.add_argument("--model-path", "-m", default="models/sentinel_model.joblib", help="Path to model")
    parser.add_argument("--normal-count", "-n", type=int, default=1000, help="Number of normal test logs")
    parser.add_argument("--attack-count", "-a", type=int, default=100, help="Number of attack test logs")
    parser.add_argument("--threshold", "-t", type=float, default=0.65, help="Severity threshold")
    args = parser.parse_args()

    evaluate_labeled_set(
        model_path=args.model_path,
        normal_count=args.normal_count,
        attack_count=args.attack_count,
        threshold=args.threshold,
    )


if __name__ == "__main__":
    main()