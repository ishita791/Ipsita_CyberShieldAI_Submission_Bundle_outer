"""
Unit tests for EmailAnalyzer module in CyberShield AI.
Verifies social engineering detection, credential harvest flags, urgency indicators,
and embedded URL extraction.
"""

import unittest
from detector.email_analyzer import EmailAnalyzer


class TestEmailAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = EmailAnalyzer()

    def test_empty_message_handling(self):
        """Verify empty message does not raise exception."""
        res = self.analyzer.analyze_message("")
        self.assertFalse(res["valid"])
        self.assertEqual(len(res["indicators"]), 0)

    def test_urgency_and_credential_detection(self):
        """Verify message with urgency and credential prompt triggers indicators."""
        sample_email = (
            "URGENT ACTION REQUIRED: Your account has been suspended due to suspicious activity. "
            "Please confirm your password and 2fa code within 24 hours to restore access."
        )
        res = self.analyzer.analyze_message(sample_email)
        self.assertTrue(res["valid"])
        categories = [ind["category"] for ind in res["indicators"]]
        self.assertIn("Urgency & Artificial Scarcity", categories)
        self.assertIn("Credential & Sensitive Data Solicitation", categories)

    def test_prize_reward_lure(self):
        """Verify lottery and reward claims are flagged."""
        sample_email = (
            "Congratulations! You have won $5,000,000 in the international cash prize lottery! "
            "Claim your prize immediately."
        )
        res = self.analyzer.analyze_message(sample_email)
        self.assertTrue(res["valid"])
        categories = [ind["category"] for ind in res["indicators"]]
        self.assertIn("Baiting & Unsolicited Rewards", categories)

    def test_url_extraction_from_message(self):
        """Verify embedded URLs are extracted from message text."""
        sample_email = (
            "Please review the invoice at http://192.168.1.50/invoice.pdf and update "
            "your credentials on https://secure-bank.example.com/login."
        )
        urls = self.analyzer.extract_urls(sample_email)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://192.168.1.50/invoice.pdf", urls)
        self.assertIn("https://secure-bank.example.com/login", urls)

    def test_benign_business_email(self):
        """Verify standard polite work email triggers minimal/no critical alerts."""
        benign_email = (
            "Hi Alice, here is the agenda for our project review meeting next Tuesday. "
            "Let me know if you would like to add any discussion points."
        )
        res = self.analyzer.analyze_message(benign_email)
        self.assertTrue(res["valid"])
        # No credential harvesting or intimidation in benign email
        categories = [ind["category"] for ind in res["indicators"]]
        self.assertNotIn("Credential & Sensitive Data Solicitation", categories)
        self.assertNotIn("Coercion & Intimidation Tactics", categories)


if __name__ == "__main__":
    unittest.main()
