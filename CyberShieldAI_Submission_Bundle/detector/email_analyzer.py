"""
CyberShield AI — Email and Message Phishing Analyzer
Analyzes textual message body for social engineering indicators, coercive language,
credential harvesting lures, and embedded suspicious links.
"""

import re
from typing import Any, Dict, List
from .url_analyzer import URLAnalyzer

# Social engineering indicator patterns
URGENCY_PATTERNS = [
    (r"\b(immediately|right now|urgent|urgently|within 24 hours?|within 12 hours?|promptly|without delay|act now)\b", "Immediate action deadline demanded"),
    (r"\b(account (will be|has been) (suspended|locked|terminated|deactivated|closed|restricted))\b", "Threat of immediate account suspension or penalty"),
    (r"\b(action required|final warning|last notice|immediate verification)\b", "Urgent coercive ultimatum"),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\b(password|passcode|passphrase|pin|one[- ]time password|otp|2fa code|verification code)\b", "Direct request for authentication credentials or 2FA codes"),
    (r"\b(credit card|debit card|cvv|security code|card number|expiration date)\b", "Financial payment card data solicitation"),
    (r"\b(social security|ssn|tax id|national id|bank account|routing number)\b", "High-risk personal identification or banking info requested"),
    (r"\b(verify your (account|identity|credentials|information)|confirm your (identity|password))\b", "Generic credential verification lure"),
]

FEAR_THREAT_PATTERNS = [
    (r"\b(legal action|law enforcement|police|court|fbi|arrest|lawsuit|penalty)\b", "Intimidation through threat of law enforcement or legal sanctions"),
    (r"\b(unauthorized (access|transaction|activity|charge)|suspicious login|compromised)\b", "Fabricated security alert designed to provoke panic"),
    (r"\b(fail(ure)? to comply|consequences|disciplinary action)\b", "Coercive punitive language"),
]

PRIZE_REWARD_PATTERNS = [
    (r"\b(congratulations|you have won|lottery winner|cash prize|unclaimed funds|jackpot)\b", "Unsolicited lottery or prize reward claim"),
    (r"\b(claim your (reward|prize|gift card|bonus|crypto|free bitcoin))\b", "Baiting with financial or gift card incentives"),
    (r"\b(100% free|exclusive offer|selected especially for you)\b", "Commercial incentive lure"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(microsoft|apple|google|paypal|amazon|netflix|bank of america|wells fargo|chase)\b", "Impersonation of high-profile tech or banking institution"),
    (r"\b(it department|help desk|system administrator|security officer|hr team|payroll department)\b", "Internal organizational authority impersonation"),
    (r"\b(irs|internal revenue|hmrc|tax authority|customs|border protection)\b", "Government or taxation authority impersonation"),
]

GENERIC_GREETING_PATTERNS = [
    (r"\b(dear customer|dear user|valued client|dear member|undisclosed recipients|dear sir/madam)\b", "Impersonal, generic greeting typical of mass phishing campaigns"),
]


class EmailAnalyzer:
    """
    Analyzes email and message text for social engineering signals.
    Extracts embedded URLs and passes them through static URL evaluation.
    """

    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs found inside the message body."""
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        raw_urls = re.findall(url_pattern, text)
        cleaned: List[str] = []
        for u in raw_urls:
            # Strip trailing punctuation often caught in regex
            u_clean = u.rstrip('.,;!?)\'\"')
            if u_clean and u_clean not in cleaned:
                cleaned.append(u_clean)
        return cleaned

    def analyze_message(self, text: str) -> Dict[str, Any]:
        """
        Analyze email body or SMS text for phishing and social engineering indicators.
        """
        if not text or not text.strip():
            return {
                "valid": False,
                "error": "Empty message body provided",
                "indicators": [],
                "extracted_urls": []
            }

        text_content = text.strip()
        lower_text = text_content.lower()

        indicators: List[Dict[str, Any]] = []

        # Check urgency
        for pattern, explanation in URGENCY_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Urgency & Artificial Scarcity",
                    "severity": "High",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Check credential harvest
        for pattern, explanation in CREDENTIAL_HARVEST_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Credential & Sensitive Data Solicitation",
                    "severity": "Critical",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Check fear & threats
        for pattern, explanation in FEAR_THREAT_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Coercion & Intimidation Tactics",
                    "severity": "High",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Check prize/lottery lure
        for pattern, explanation in PRIZE_REWARD_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Baiting & Unsolicited Rewards",
                    "severity": "Medium",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Check impersonation
        for pattern, explanation in IMPERSONATION_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Brand & Authority Impersonation",
                    "severity": "Medium",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Check generic greeting
        for pattern, explanation in GENERIC_GREETING_PATTERNS:
            matches = re.findall(pattern, lower_text)
            if matches:
                indicators.append({
                    "category": "Impersonal Salutation",
                    "severity": "Low",
                    "detected_term": matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "explanation": explanation
                })

        # Extract and analyze embedded links
        found_urls = self.extract_urls(text_content)
        url_reports: List[Dict[str, Any]] = []
        for u in found_urls:
            report = self.url_analyzer.extract_features(u)
            url_reports.append(report)

        return {
            "valid": True,
            "char_count": len(text_content),
            "word_count": len(text_content.split()),
            "indicators": indicators,
            "extracted_urls": found_urls,
            "url_analysis_reports": url_reports,
            "disclaimer": "These indicators represent heuristic risk signals. Contextual business emails may legitimately use some of these words; verify through trusted independent channels."
        }


def analyze_email_message(text: str) -> Dict[str, Any]:
    """Helper function to analyze email text."""
    analyzer = EmailAnalyzer()
    return analyzer.analyze_message(text)
