"""
Unit tests for URLAnalyzer module in CyberShield AI.
Verifies feature extraction, IP detection, shorteners, punycode, and malformed inputs.
"""

import unittest
from detector.url_analyzer import URLAnalyzer, calculate_shannon_entropy


class TestURLAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = URLAnalyzer()

    def test_empty_or_whitespace_url(self):
        """Verify empty and whitespace URLs fail gracefully without crashing."""
        res = self.analyzer.extract_features("")
        self.assertFalse(res["valid"])
        self.assertIn("error", res)

        res2 = self.analyzer.extract_features("   ")
        self.assertFalse(res2["valid"])

    def test_raw_ip_address_detection(self):
        """Verify IP address URLs are identified with High severity signal."""
        url = "http://192.168.1.100/login"
        res = self.analyzer.extract_features(url)
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_ip"])
        signal_types = [s["type"] for s in res["signals"]]
        self.assertIn("IP_HOST", signal_types)

    def test_url_shortener_detection(self):
        """Verify shortener domains trigger URL_SHORTENER indicator."""
        url = "https://bit.ly/3x8f9Aa"
        res = self.analyzer.extract_features(url)
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_shortener"])
        signal_types = [s["type"] for s in res["signals"]]
        self.assertIn("URL_SHORTENER", signal_types)

    def test_at_symbol_obfuscation(self):
        """Verify presence of '@' in URL triggers USERINFO_OBFUSCATION."""
        url = "http://google.com@evil-phish.net/login"
        res = self.analyzer.extract_features(url)
        self.assertTrue(res["valid"])
        self.assertTrue(res["has_at_symbol"])
        signal_types = [s["type"] for s in res["signals"]]
        self.assertIn("USERINFO_OBFUSCATION", signal_types)

    def test_punycode_homograph(self):
        """Verify punycode IDN homographs are flagged."""
        url = "http://xn--pple-43d.com/login"
        res = self.analyzer.extract_features(url)
        self.assertTrue(res["valid"])
        self.assertTrue(res["is_punycode"])
        signal_types = [s["type"] for s in res["signals"]]
        self.assertIn("PUNYCODE_HOMOGRAPH", signal_types)

    def test_entropy_calculation(self):
        """Verify Shannon entropy calculates positive value for randomized string."""
        entropy_normal = calculate_shannon_entropy("google")
        entropy_random = calculate_shannon_entropy("q7w8e9r0t1y2u3i4o5p")
        self.assertGreater(entropy_random, entropy_normal)

    def test_legitimate_url_cleanliness(self):
        """Verify a clean legitimate URL produces minimal threat signals."""
        url = "https://www.google.com/search?q=cybersecurity"
        res = self.analyzer.extract_features(url)
        self.assertTrue(res["valid"])
        self.assertTrue(res["uses_https"])
        self.assertFalse(res["is_ip"])
        self.assertFalse(res["is_shortener"])
        self.assertFalse(res["has_at_symbol"])


if __name__ == "__main__":
    unittest.main()
