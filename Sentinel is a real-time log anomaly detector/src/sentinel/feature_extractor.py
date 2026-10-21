"""Feature extraction pipeline for Sentinel.

Converts structured ParsedLog entries into numeric feature vectors combining:
1. Lexical and statistical features (message length, special character counts)
2. HTTP protocol features (status codes, method one-hot encoding, error flags)
3. Domain security indicators (SQLi, XSS, Path Traversal, RCE keywords)
4. TF-IDF representation of log message and URL content.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from sentinel.log_parser import ParsedLog


class FeatureExtractor:
    """Extracts numeric feature vectors from ParsedLog objects."""

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    # Security keywords to inspect (grouped by threat pattern)
    KEYWORDS = [
        # SQL Injection
        "select", "union", "insert", "update", "delete", "drop", "table",
        "1=1", "or 1", "--", "information_schema", "sleep(", "benchmark(",
        # Path Traversal
        "../", "..\\", "etc/passwd", "win.ini", "system32", "boot.ini",
        # XSS
        "<script", "javascript:", "onerror", "onload", "alert(", "<svg", "<img",
        # RCE / Shell
        "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "eval(", "exec(",
        # Internal Errors / Exceptions
        "traceback", "exception", "syntax error", "fatal", "denied", "forbidden",
        "internal error", "nullpointer", "stacktrace"
    ]

    SPECIAL_CHARS = ["'", '"', ";", "<", ">", "%", "=", "\\", "/", "(", ")", "{", "}", "$", "&", "*"]

    def __init__(self, tfidf_max_features: int = 25) -> None:
        self.tfidf_max_features = tfidf_max_features
        self.vectorizer = TfidfVectorizer(
            max_features=tfidf_max_features,
            ngram_range=(1, 2),
            lowercase=True,
            token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.\/]{2,}\b",
        )
        self.is_fitted: bool = False
        self.feature_names_: list[str] = []

    def _extract_text(self, log: ParsedLog) -> str:
        """Extract combined text for TF-IDF."""
        parts = []
        if log.method:
            parts.append(log.method)
        if log.url:
            parts.append(log.url)
        if log.message:
            parts.append(log.message)
        if not parts:
            parts.append(log.raw)
        return " ".join(parts).lower()

    def _extract_manual_features(self, log: ParsedLog) -> np.ndarray:
        """Extract non-TFIDF statistical and categorical features for a single log."""
        raw = log.raw
        raw_lower = raw.lower()
        msg = log.message or ""
        msg_lower = msg.lower()
        url = log.url or ""
        url_lower = url.lower()
        combined_text = f"{url_lower} {msg_lower}"

        features: list[float] = []

        # 1. Length features (normalized)
        raw_len = float(len(raw))
        msg_len = float(len(msg))
        url_len = float(len(url))
        features.extend([raw_len / 100.0, msg_len / 100.0, url_len / 100.0])

        # 2. HTTP Status Code features
        status = log.status_code if log.status_code is not None else 0
        is_2xx = 1.0 if 200 <= status < 300 else 0.0
        is_3xx = 1.0 if 300 <= status < 400 else 0.0
        is_4xx = 1.0 if 400 <= status < 500 else 0.0
        is_5xx = 1.0 if 500 <= status < 600 else 0.0
        features.extend([status / 100.0, is_2xx, is_3xx, is_4xx, is_5xx])

        # 3. Log Level features
        level = (log.level or "INFO").upper()
        features.extend([
            1.0 if level == "DEBUG" else 0.0,
            1.0 if level == "INFO" else 0.0,
            1.0 if level in ("WARN", "WARNING") else 0.0,
            1.0 if level in ("ERROR", "CRITICAL", "FATAL") else 0.0,
        ])

        # 4. HTTP Method One-Hot Encoding
        method = (log.method or "").upper()
        method_matched = False
        for m in self.HTTP_METHODS:
            if method == m:
                features.append(1.0)
                method_matched = True
            else:
                features.append(0.0)
        # 'OTHER' method flag
        features.append(1.0 if (method and not method_matched) else 0.0)

        # 5. Special Character Counts
        total_specials = sum(raw.count(c) for c in self.SPECIAL_CHARS)
        features.append(float(total_specials))
        for c in ["'", '"', ";", "--", "<", ">", "%", "="]:
            features.append(float(raw.count(c)))

        # 6. Suspicious Keyword Indicators (binary presence + frequency)
        matched_kw_count = 0
        for kw in self.KEYWORDS:
            present = 1.0 if (kw in combined_text or kw in raw_lower) else 0.0
            features.append(present)
            if present > 0:
                matched_kw_count += 1
        features.append(float(matched_kw_count))

        return np.array(features, dtype=np.float32)

    def fit(self, logs: list[ParsedLog]) -> FeatureExtractor:
        """Fit the TF-IDF vectorizer on the provided training logs."""
        texts = [self._extract_text(log) for log in logs]
        if not texts or all(not t.strip() for t in texts):
            texts = ["dummy initialization log message"]

        self.vectorizer.fit(texts)
        self.is_fitted = True

        # Build feature names
        sample_manual = self._extract_manual_features(logs[0] if logs else ParsedLog(raw="", format="dummy"))
        manual_names = [f"manual_{i}" for i in range(len(sample_manual))]
        tfidf_names = [f"tfidf_{w}" for w in self.vectorizer.get_feature_names_out()]
        self.feature_names_ = manual_names + tfidf_names

        return self

    def transform(self, logs: list[ParsedLog]) -> np.ndarray:
        """Transform a list of ParsedLog entries into a 2D numpy feature matrix."""
        if not self.is_fitted:
            raise RuntimeError("FeatureExtractor must be fitted before calling transform().")

        manual_feats = np.array([self._extract_manual_features(log) for log in logs], dtype=np.float32)
        texts = [self._extract_text(log) for log in logs]
        tfidf_feats = self.vectorizer.transform(texts).toarray().astype(np.float32)

        return np.hstack([manual_feats, tfidf_feats])

    def transform_one(self, log: ParsedLog) -> np.ndarray:
        """Transform a single ParsedLog entry into a 2D array (1, num_features)."""
        return self.transform([log])

    def explain(self, log: ParsedLog) -> list[str]:
        """Provides human-readable reasons why this log might be anomalous."""
        reasons: list[str] = []
        raw_lower = log.raw.lower()
        msg_lower = (log.message or "").lower()
        url_lower = (log.url or "").lower()
        combined = f"{raw_lower} {msg_lower} {url_lower}"

        # 1. Suspicious keywords in URL, message, or raw
        found_keywords = [kw for kw in self.KEYWORDS if kw in combined]
        if found_keywords:
            reasons.append(f"Suspicious patterns detected: {', '.join(found_keywords[:5])}")

        # 2. HTTP Status issues
        if log.status_code is not None:
            if log.status_code >= 500:
                reasons.append(f"Server error: HTTP {log.status_code}")
            elif log.status_code == 404 and any(k in combined for k in ("admin", "config", ".env", "passwd", "setup")):
                reasons.append("Reconnaissance probe: HTTP 404 on sensitive path")

        # 3. Log level
        if log.level in ("ERROR", "CRITICAL", "FATAL"):
            reasons.append(f"Critical log level: [{log.level}]")

        # 4. Injection characters in request path/query/message (SQLi, XSS, Command injection)
        target = f"{log.url or ''} {log.message or ''}".lower()
        dangerous_chars = ["'", ";", "<", ">", "--", "`"]
        found_danger = [c for c in dangerous_chars if c in target]
        if found_danger:
            reasons.append(f"Dangerous characters in request target: {', '.join(found_danger)}")

        # 5. Abnormally long payload
        if len(log.raw) > 350:
            reasons.append(f"Abnormally long payload ({len(log.raw)} characters)")

        return reasons

    def save(self, path: Path | str) -> None:
        """Serialize fitted extractor to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)

    @classmethod
    def load(cls, path: Path | str) -> FeatureExtractor:
        """Load fitted extractor from disk."""
        return joblib.load(Path(path))
