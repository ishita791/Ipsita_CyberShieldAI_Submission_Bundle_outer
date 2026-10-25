"""
Unit tests for RiskScorer and Decision Engine in CyberShield AI.
Verifies score calculation, risk categorization tiers, and defensive recommendation generation.
"""

import unittest
from detector.url_analyzer import URLAnalyzer
from detector.email_analyzer import EmailAnalyzer
from detector.risk_scorer import RiskScorer, evaluate_risk


class TestRiskScorer(unittest.TestCase):

    def setUp(self):
        self.scorer = RiskScorer()
        self.url_analyzer = URLAnalyzer()
        self.email_analyzer = EmailAnalyzer()

    def test_score_categorization_tiers(self):
        """Verify score bounds correctly map to Low, Medium, High, and Critical."""
        self.assertEqual(self.scorer.categorize_score(15)[0], "Low Risk")
        self.assertEqual(self.scorer.categorize_score(50)[0], "Medium Risk")
        self.assertEqual(self.scorer.categorize_score(75)[0], "High Risk")
        self.assertEqual(self.scorer.categorize_score(95)[0], "Critical Risk")

    def test_benign_url_receives_low_risk(self):
        """Verify normal reputable HTTPS domain receives Low Risk."""
        url_feat = self.url_analyzer.extract_features("https://www.google.com/search")
        res = self.scorer.score_url(url_feat)
        self.assertEqual(res["tier"], "Low Risk")
        self.assertLess(res["score"], 35)

    def test_aggressive_phishing_url_receives_high_or_critical(self):
        """Verify URL with raw IP, @ sign, and login keyword receives Critical or High risk."""
        url_feat = self.url_analyzer.extract_features("http://user@192.168.1.100/paypal/login/verify")
        res = self.scorer.score_url(url_feat)
        self.assertIn(res["tier"], ["High Risk", "Critical Risk"])
        self.assertGreaterEqual(res["score"], 65)
        self.assertTrue(len(res["recommendations"]) > 0)

    def test_phishing_email_score(self):
        """Verify coercive credential lure email receives elevated risk score."""
        msg = (
            "URGENT: Your account has been suspended! Enter your password and credit card "
            "immediately or face legal action."
        )
        msg_feat = self.email_analyzer.analyze_message(msg)
        res = self.scorer.score_email_message(msg_feat)
        self.assertIn(res["tier"], ["High Risk", "Critical Risk"])
        self.assertGreater(res["score"], 60)


if __name__ == "__main__":
    unittest.main()
