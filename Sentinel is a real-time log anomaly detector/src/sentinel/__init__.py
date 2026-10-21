"""Sentinel: Real-time Log Anomaly Detector.

Sentinel continuously tails, parses, extracts features from, and detects
anomalies in server and application logs using machine learning, dispatching
real-time alerts to Slack or Discord.
"""

__version__ = "0.1.0"
__author__ = "Sentinel DevOps & Security Team"

from sentinel.log_parser import LogParser, ParsedLog
from sentinel.feature_extractor import FeatureExtractor
from sentinel.anomaly_model import AnomalyDetector
from sentinel.log_ingestor import LogIngestor
from sentinel.alerting import AlertManager, AlertPayload
from sentinel.config import SentinelConfig, load_config

__all__ = [
    "LogParser",
    "ParsedLog",
    "FeatureExtractor",
    "AnomalyDetector",
    "LogIngestor",
    "AlertManager",
    "AlertPayload",
    "SentinelConfig",
    "load_config",
]
