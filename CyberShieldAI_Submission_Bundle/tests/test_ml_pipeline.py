"""
Unit tests for ML Engine and Feature Vector extraction in CyberShield AI.
Verifies vector dimensionality, consistency, and prediction behavior.
"""

import unittest
from detector.url_analyzer import URLAnalyzer
from detector.ml_engine import (
    PhishingMLClassifier,
    extract_features_vector,
    FEATURE_NAMES,
    get_benchmark_metrics
)


class TestMLEngine(unittest.TestCase):

    def setUp(self):
        self.analyzer = URLAnalyzer()
        self.classifier = PhishingMLClassifier()

    def test_feature_vector_dimensionality(self):
        """Verify feature vector length strictly matches FEATURE_NAMES count."""
        sample_url = "https://example.com/login"
        feat = self.analyzer.extract_features(sample_url)
        vec = extract_features_vector(feat)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertEqual(len(vec), 14)

    def test_benign_prediction(self):
        """Verify reputable benign site yields low phishing probability."""
        sample_url = "https://github.com/torvalds/linux"
        feat = self.analyzer.extract_features(sample_url)
        pred = self.classifier.predict(feat)
        self.assertEqual(pred["prediction"], "Legitimate")
        self.assertLess(pred["phishing_probability"], 0.40)

    def test_malicious_prediction(self):
        """Verify blatant IP-based credential lure yields high phishing probability."""
        sample_url = "http://192.168.1.1/paypal/login.php?verify=1"
        feat = self.analyzer.extract_features(sample_url)
        pred = self.classifier.predict(feat)
        self.assertEqual(pred["prediction"], "Phishing")
        self.assertGreaterEqual(pred["phishing_probability"], 0.50)

    def test_benchmark_metrics_presence(self):
        """Verify benchmark evaluation metrics structure and accuracy >= 0.90."""
        metrics = get_benchmark_metrics()
        self.assertIn("accuracy", metrics)
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1_score", metrics)
        self.assertIn("confusion_matrix", metrics)
        self.assertGreater(metrics["accuracy"], 0.90)


if __name__ == "__main__":
    unittest.main()
