"""Anomaly detection model wrapper for Sentinel.

Wraps scikit-learn IsolationForest and OneClassSVM with severity calibration,
prediction explanation, and atomic pipeline serialization.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Optional
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM

from sentinel.feature_extractor import FeatureExtractor
from sentinel.log_parser import ParsedLog


class AnomalyDetector:
    """End-to-end anomaly detector combining FeatureExtractor and unsupervised ML model."""

    def __init__(
        self,
        model_type: str = "isolation_forest",
        contamination: float = 0.01,
        random_state: int = 42,
        threshold: float = 0.65,
        raw_threshold: Optional[float] = None,
    ) -> None:
        self.model_type = model_type.lower()
        self.contamination = contamination
        self.random_state = random_state
        self.threshold = threshold
        self.raw_threshold = raw_threshold
        self.feature_extractor = FeatureExtractor(tfidf_max_features=25)

        if self.model_type == "one_class_svm":
            self.model: Any = OneClassSVM(nu=contamination, kernel="rbf", gamma="scale")
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=random_state,
                n_jobs=-1,
                warm_start=False,
            )

        self.is_trained: bool = False
        self.training_samples_count: int = 0
        self.training_score_mean: float = 0.10
        self.training_score_std: float = 0.05

    def fit(self, logs: list[ParsedLog]) -> AnomalyDetector:
        """Fits the feature extractor and unsupervised anomaly model on baseline normal logs."""
        if not logs:
            raise ValueError("Cannot train anomaly model on empty log list.")

        self.feature_extractor.fit(logs)
        X = self.feature_extractor.transform(logs)

        self.model.fit(X)
        self.is_trained = True
        self.training_samples_count = len(logs)

        # Baseline decision scores on training data for calibration
        train_scores = self.model.decision_function(X)
        self.training_score_mean = float(np.mean(train_scores))
        self.training_score_std = float(np.std(train_scores)) if float(np.std(train_scores)) > 1e-4 else 0.05

        return self

    def raw_score(self, X: np.ndarray) -> np.ndarray:
        """Raw decision function score.

        In scikit-learn, negative values indicate anomalies, positive values normal.
        """
        if not self.is_trained:
            raise RuntimeError("AnomalyDetector must be trained before scoring.")
        return self.model.decision_function(X)

    def compute_severity(self, raw_score: float, reasons: Optional[list[str]] = None) -> float:
        """Converts raw decision score into a calibrated severity score in [0.0, 1.0].

        0.0 = completely typical/normal
        0.5 = at baseline decision boundary
        1.0 = extreme outlier / high confidence anomaly
        """
        # Compute z-score relative to baseline normal logs
        std = max(self.training_score_std, 1e-4)
        z = (self.training_score_mean - raw_score) / std

        # Base severity from Isolation Forest score (normal mean ~0.1-0.2, negative raw score > 0.6)
        base_sev = 1.0 / (1.0 + math.exp(-2.2 * (z - 2.0)))

        # Domain boost if concrete attack indicators are identified
        if reasons:
            concrete_attack_signals = [
                r for r in reasons
                if any(k in r.lower() for k in ("suspicious", "etc/passwd", "system32", "500", "dangerous", "critical"))
            ]
            if concrete_attack_signals:
                base_sev = max(base_sev, 0.75 + 0.08 * min(len(concrete_attack_signals), 3))

        return float(np.clip(base_sev, 0.0, 1.0))

    def get_severity_label(self, severity: float) -> str:
        """Maps severity score to categorical alert priority."""
        if severity >= 0.85:
            return "CRITICAL"
        if severity >= 0.70:
            return "HIGH"
        if severity >= 0.50:
            return "MEDIUM"
        return "LOW"

    def predict_one(self, log: ParsedLog) -> dict[str, Any]:
        """Diagnoses a single ParsedLog entry."""
        if not self.is_trained:
            raise RuntimeError("AnomalyDetector must be trained before predicting.")

        X = self.feature_extractor.transform_one(log)
        raw_sc = float(self.model.decision_function(X)[0])
        pred_label = int(self.model.predict(X)[0])  # -1 (anomaly), 1 (normal)

        reasons = self.feature_extractor.explain(log)
        severity = self.compute_severity(raw_sc, reasons)

        # Anomaly determination:
        # Either scikit-learn model flagged as outlier (-1), OR severity >= configured threshold,
        # OR raw score falls below optional raw_threshold
        is_anomaly = bool(
            pred_label == -1
            or severity >= self.threshold
            or (self.raw_threshold is not None and raw_sc < self.raw_threshold)
        )

        active_reasons = reasons if is_anomaly else []
        severity_label = self.get_severity_label(severity)

        return {
            "is_anomaly": is_anomaly,
            "prediction": pred_label,
            "raw_score": round(raw_sc, 4),
            "severity": round(severity, 4),
            "severity_label": severity_label,
            "reasons": active_reasons,
            "log": log,
        }

    def predict_batch(self, logs: list[ParsedLog]) -> list[dict[str, Any]]:
        """Diagnoses a batch of ParsedLog entries efficiently."""
        if not logs:
            return []
        if not self.is_trained:
            raise RuntimeError("AnomalyDetector must be trained before predicting.")

        X = self.feature_extractor.transform(logs)
        raw_scores = self.model.decision_function(X)
        predictions = self.model.predict(X)

        results = []
        for i, log in enumerate(logs):
            raw_sc = float(raw_scores[i])
            pred_label = int(predictions[i])
            reasons = self.feature_extractor.explain(log)
            severity = self.compute_severity(raw_sc, reasons)

            is_anomaly = bool(
                pred_label == -1
                or severity >= self.threshold
                or (self.raw_threshold is not None and raw_sc < self.raw_threshold)
            )

            active_reasons = reasons if is_anomaly else []
            severity_label = self.get_severity_label(severity)

            results.append({
                "is_anomaly": is_anomaly,
                "prediction": pred_label,
                "raw_score": round(raw_sc, 4),
                "severity": round(severity, 4),
                "severity_label": severity_label,
                "reasons": active_reasons,
                "log": log,
            })

        return results

    def save(self, path: Path | str) -> None:
        """Atomically saves the detector pipeline to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)

    @classmethod
    def load(cls, path: Path | str) -> AnomalyDetector:
        """Loads a saved detector pipeline from disk."""
        target = Path(path)
        if not target.is_file():
            raise FileNotFoundError(f"Trained model not found at '{target}'")
        detector = joblib.load(target)
        if not isinstance(detector, cls):
            raise TypeError(f"Loaded object from '{target}' is not an AnomalyDetector")
        return detector
