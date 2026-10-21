"""Unit tests for FeatureExtractor."""

import numpy as np
import pytest
from sentinel.feature_extractor import FeatureExtractor
from sentinel.log_parser import LogParser, ParsedLog


@pytest.fixture
def parser():
    return LogParser()


@pytest.fixture
def sample_normal_logs(parser):
    lines = [
        '192.168.1.10 - - [20/Oct/2026:14:00:00 +0000] "GET /index.html HTTP/1.1" 200 450 "-" "Mozilla/5.0"',
        '192.168.1.11 - - [20/Oct/2026:14:00:01 +0000] "POST /api/login HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
        '192.168.1.12 - - [20/Oct/2026:14:00:02 +0000] "GET /products/items HTTP/1.1" 200 3200 "-" "Mozilla/5.0"',
        '192.168.1.13 - - [20/Oct/2026:14:00:03 +0000] "GET /about HTTP/1.1" 200 800 "-" "Mozilla/5.0"',
    ]
    return [parser.parse_line(line) for line in lines]


def test_fit_and_transform_shape(sample_normal_logs):
    extractor = FeatureExtractor(tfidf_max_features=20)
    extractor.fit(sample_normal_logs)

    assert extractor.is_fitted
    X = extractor.transform(sample_normal_logs)

    assert isinstance(X, np.ndarray)
    assert X.shape[0] == len(sample_normal_logs)
    assert X.shape[1] > 20
    assert X.shape[1] == len(extractor.feature_names_)


def test_transform_one(sample_normal_logs):
    extractor = FeatureExtractor(tfidf_max_features=20).fit(sample_normal_logs)
    x1 = extractor.transform_one(sample_normal_logs[0])

    assert x1.shape[0] == 1
    assert x1.shape[1] == len(extractor.feature_names_)


def test_special_chars_and_keyword_detection(parser):
    extractor = FeatureExtractor().fit([
        parser.parse_line('192.168.1.1 - - [20/Oct/2026:14:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"')
    ])

    attack_line = (
        '192.168.1.99 - - [20/Oct/2026:14:00:00 +0000] '
        '"GET /search?q=1\'%20UNION%20SELECT%20*%20FROM%20users;-- HTTP/1.1" 500 240 "-" "sqlmap"'
    )
    parsed = parser.parse_line(attack_line)
    reasons = extractor.explain(parsed)

    assert any("Suspicious patterns detected" in r for r in reasons)
    assert any("Server error: HTTP 500" in r for r in reasons)


def test_path_traversal_detection(parser):
    extractor = FeatureExtractor().fit([
        parser.parse_line('192.168.1.1 - - [20/Oct/2026:14:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"')
    ])

    parsed = parser.parse_line(
        '10.0.0.1 - - [20/Oct/2026:14:00:00 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 403 120 "-" "-"'
    )
    reasons = extractor.explain(parsed)
    assert any("etc/passwd" in r or "Suspicious" in r for r in reasons)


def test_save_load_extractor(tmp_path, sample_normal_logs):
    extractor = FeatureExtractor(tfidf_max_features=25).fit(sample_normal_logs)
    save_file = tmp_path / "extractor.joblib"
    extractor.save(save_file)

    loaded = FeatureExtractor.load(save_file)
    assert loaded.is_fitted
    assert len(loaded.feature_names_) == len(extractor.feature_names_)

    orig_x = extractor.transform(sample_normal_logs)
    loaded_x = loaded.transform(sample_normal_logs)
    np.testing.assert_allclose(orig_x, loaded_x)
