"""Unit tests for Aegis ML IDPS service."""

import unittest
from ml_service.dataset import TRAINING_DATA
from ml_service.model import HybridIDPSClassifier


class TestMLService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classifier = HybridIDPSClassifier()
        cls.classifier.fit(TRAINING_DATA)

    def test_metrics_computed(self):
        metrics = self.classifier.metrics
        self.assertIn("accuracy", metrics)
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1", metrics)
        self.assertGreaterEqual(metrics["accuracy"], 0.95)

    def test_sqli_detection(self):
        test_payloads = [
            "' OR '1'='1' --",
            "admin'--",
            "1; DROP TABLE users;--",
            "union select null, username, password from users",
            "1' AND SLEEP(5)--",
        ]
        for p in test_payloads:
            label, conf, _ = self.classifier.predict_single(p)
            self.assertEqual(label, "SQL Injection", f"Failed for payload: {p}")
            self.assertGreater(conf, 0.8)

    def test_xss_detection(self):
        test_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert(1)>",
        ]
        for p in test_payloads:
            label, conf, _ = self.classifier.predict_single(p)
            self.assertEqual(label, "XSS", f"Failed for payload: {p}")
            self.assertGreater(conf, 0.8)

    def test_command_injection_detection(self):
        test_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "../../../../../etc/shadow",
            "&& id",
        ]
        for p in test_payloads:
            label, conf, _ = self.classifier.predict_single(p)
            self.assertEqual(label, "Command Injection", f"Failed for payload: {p}")

    def test_benign_classification(self):
        test_samples = [
            "Hello, where is my package tracking info?",
            "Great wireless earphones with noise cancellation",
            "How do I update my profile settings?",
            "What is the return policy for damaged goods?",
        ]
        for s in test_samples:
            label, _, _ = self.classifier.predict_single(s)
            self.assertEqual(label, "Benign", f"False positive on benign sample: {s}")


if __name__ == "__main__":
    unittest.main()
