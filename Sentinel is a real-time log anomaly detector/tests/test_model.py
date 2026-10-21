"""Unit tests for AnomalyDetector."""

import numpy as np
import pytest
from sentinel.anomaly_model import AnomalyDetector
from sentinel.log_parser import LogParser


@pytest.fixture
def parser():
    return LogParser()


@pytest.fixture
def normal_training_logs(parser):
    # 50 realistic normal logs with standard web patterns
    logs = []
    for i in range(50):
        path = f"/page_{i % 5}"
        line = f'192.168.1.{10 + (i % 5)} - - [20/Oct/2026:14:00:{i:02d} +0000] "GET {path} HTTP/1.1" 200 450 "-" "Mozilla/5.0"'
        logs.append(parser.parse_line(line))
    return logs


def test_train_isolation_forest(normal_training_logs, parser):
    detector = AnomalyDetector(model_type="isolation_forest", contamination=0.01)
    detector.fit(normal_training_logs)

    assert detector.is_trained
    assert detector.training_samples_count == len(normal_training_logs)

    # Test on a normal log
    test_normal = parser.parse_line('192.168.1.10 - - [20/Oct/2026:14:05:00 +0000] "GET /page_1 HTTP/1.1" 200 450 "-" "Mozilla/5.0"')
    res_normal = detector.predict_one(test_normal)
    assert not res_normal["is_anomaly"]
    assert res_normal["severity"] < 0.65

    # Test on an attack log
    test_attack = parser.parse_line(
        '198.51.100.99 - - [20/Oct/2026:14:05:00 +0000] "GET /login?user=admin\'%20OR%201=1;-- HTTP/1.1" 500 120 "-" "sqlmap"'
    )
    res_attack = detector.predict_one(test_attack)
    assert res_attack["is_anomaly"]
    assert res_attack["severity"] >= 0.65
    assert len(res_attack["reasons"]) > 0


def test_train_one_class_svm(normal_training_logs, parser):
    detector = AnomalyDetector(model_type="one_class_svm", contamination=0.05)
    detector.fit(normal_training_logs)

    assert detector.is_trained
    assert detector.model_type == "one_class_svm"

    test_attack = parser.parse_line(
        '198.51.100.5 - - [20/Oct/2026:14:05:00 +0000] "GET /static/../../etc/passwd HTTP/1.1" 403 80 "-" "-"'
    )
    res = detector.predict_one(test_attack)
    assert res["is_anomaly"]


def test_save_and_load_detector(tmp_path, normal_training_logs, parser):
    detector = AnomalyDetector(threshold=0.70)
    detector.fit(normal_training_logs)

    model_file = tmp_path / "model.joblib"
    detector.save(model_file)

    loaded = AnomalyDetector.load(model_file)
    assert loaded.is_trained
    assert loaded.threshold == 0.70

    test_log = parser.parse_line('192.168.1.10 - - [20/Oct/2026:14:00:00 +0000] "GET /page_1 HTTP/1.1" 200 450 "-" "-"')
    res1 = detector.predict_one(test_log)
    res2 = loaded.predict_one(test_log)

    assert res1["is_anomaly"] == res2["is_anomaly"]
    assert res1["severity"] == res2["severity"]


def test_predict_batch(normal_training_logs, parser):
    detector = AnomalyDetector().fit(normal_training_logs)
    batch = [normal_training_logs[0], normal_training_logs[1]]
    results = detector.predict_batch(batch)

    assert len(results) == 2
    for r in results:
        assert not r["is_anomaly"]
