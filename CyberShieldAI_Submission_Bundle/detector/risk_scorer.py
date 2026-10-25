"""
CyberShield AI — Risk Scorer and Decision Engine
Calculates calibrated heuristic risk scores (0–100), maps them to discrete tiers,
and generates actionable defensive security recommendations.
"""

from typing import Any, Dict, List, Tuple


class RiskScorer:
    """
    Transparent scoring engine. Combines structural signals, keyword triggers,
    and message characteristics into a 0–100 risk index.
    """

    # Scoring weights for URL indicators
    URL_WEIGHTS = {
        "IP_HOST": 30,
        "USERINFO_OBFUSCATION": 35,
        "PUNYCODE_HOMOGRAPH": 25,
        "NON_STANDARD_PORT": 20,
        "URL_SHORTENER": 18,
        "SUSPICIOUS_KEYWORDS": 15,
        "HIGH_RISK_TLD": 15,
        "INSECURE_PROTOCOL": 12,
        "EXCESSIVE_DOTS": 10,
        "HIGH_DOMAIN_ENTROPY": 10,
        "EXCESSIVE_LENGTH": 8,
    }

    # Scoring weights for Message indicators
    MESSAGE_WEIGHTS = {
        "Credential & Sensitive Data Solicitation": 35,
        "Coercion & Intimidation Tactics": 25,
        "Urgency & Artificial Scarcity": 20,
        "Brand & Authority Impersonation": 15,
        "Baiting & Unsolicited Rewards": 15,
        "Impersonal Salutation": 5,
    }

    @staticmethod
    def categorize_score(score: float) -> Tuple[str, str]:
        """
        Map a numerical score (0-100) to a standardized risk tier and semantic color.
        Returns (Tier Name, CSS Hex Color).
        """
        if score < 35:
            return "Low Risk", "#10B981"      # Emerald / Green
        elif score < 65:
            return "Medium Risk", "#F59E0B"   # Amber / Orange
        elif score < 85:
            return "High Risk", "#EF4444"     # Rose / Red
        else:
            return "Critical Risk", "#DC2626" # Crimson / Deep Red

    def score_url(self, url_features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for a single analyzed URL."""
        if not url_features.get("valid", False):
            return {
                "score": 0,
                "tier": "Unknown",
                "color": "#64748B",
                "factors": [],
                "recommendations": ["Ensure input URL has valid syntax before scanning."]
            }

        raw_score = 0.0
        factors: List[Dict[str, Any]] = []

        for signal in url_features.get("signals", []):
            sig_type = signal.get("type", "")
            weight = self.URL_WEIGHTS.get(sig_type, 10)
            raw_score += weight
            factors.append({
                "signal": sig_type,
                "severity": signal.get("severity", "Low"),
                "contribution": weight,
                "description": signal.get("description", "")
            })

        # Cap score between 0 and 100
        final_score = min(100.0, max(0.0, round(raw_score, 1)))
        tier, color = self.categorize_score(final_score)
        recommendations = self.generate_url_recommendations(final_score, url_features)

        return {
            "score": final_score,
            "tier": tier,
            "color": color,
            "factors": factors,
            "recommendations": recommendations,
            "methodology": "Rule-based heuristic risk index (distinct from ML classifier probability)"
        }

    def score_email_message(self, message_features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for an analyzed email/message."""
        if not message_features.get("valid", False):
            return {
                "score": 0,
                "tier": "Unknown",
                "color": "#64748B",
                "factors": [],
                "recommendations": ["Provide non-empty email content."]
            }

        raw_score = 0.0
        factors: List[Dict[str, Any]] = []

        seen_categories = set()
        for ind in message_features.get("indicators", []):
            cat = ind.get("category", "")
            weight = self.MESSAGE_WEIGHTS.get(cat, 10)
            if cat not in seen_categories:
                raw_score += weight
                seen_categories.add(cat)
            else:
                # Diminishing weight for repeated categories
                raw_score += weight * 0.4

            factors.append({
                "category": cat,
                "severity": ind.get("severity", "Low"),
                "detected_term": ind.get("detected_term", ""),
                "contribution": weight,
                "description": ind.get("explanation", "")
            })

        # Cross-evaluate embedded URLs if any
        url_reports = message_features.get("url_analysis_reports", [])
        max_url_score = 0.0
        for u_rep in url_reports:
            u_score_res = self.score_url(u_rep)
            if u_score_res["score"] > max_url_score:
                max_url_score = u_score_res["score"]

        # Incorporate highest risk URL found in message
        if max_url_score > 0:
            url_factor = max_url_score * 0.4
            raw_score += url_factor
            factors.append({
                "category": "Embedded Suspicious Link Risk",
                "severity": "High" if max_url_score >= 65 else "Medium",
                "detected_term": f"Max embedded URL score: {max_url_score}/100",
                "contribution": round(url_factor, 1),
                "description": "Risk elevated due to suspicious URLs found inside the message body."
            })

        final_score = min(100.0, max(0.0, round(raw_score, 1)))
        tier, color = self.categorize_score(final_score)
        recommendations = self.generate_email_recommendations(final_score, message_features)

        return {
            "score": final_score,
            "tier": tier,
            "color": color,
            "factors": factors,
            "recommendations": recommendations,
            "methodology": "Social engineering heuristic aggregation + link cross-correlation"
        }

    def generate_url_recommendations(self, score: float, features: Dict[str, Any]) -> List[str]:
        """Generate concrete defensive advice based on detected URL risks."""
        recs: List[str] = []
        if score >= 85:
            recs.append("CRITICAL: Do not navigate to this link or enter credentials under any circumstance.")
            recs.append("Submit this URL to your organization's IT Security Operations Center (SOC) for domain blocking.")
        elif score >= 65:
            recs.append("HIGH RISK: Exercise extreme caution. Do not input passwords, credit cards, or personal identifiers.")
            recs.append("Verify the claimed organization directly by typing their known official address into a fresh browser window.")
        elif score >= 35:
            recs.append("MEDIUM RISK: Several suspicious traits detected. Verify HTTPS certificate identity before proceeding.")
            recs.append("Check if the link was received unexpectedly via unsolicited email or SMS.")
        else:
            recs.append("LOW RISK: URL structure appears consistent with conventional registered web properties.")
            recs.append("Remain vigilant: even legitimate sites can be compromised or host user-generated phishing pages.")

        if features.get("is_shortener"):
            recs.append("Use a trusted URL unshortener service or browser developer tools to inspect the target destination safely.")

        if features.get("is_ip"):
            recs.append("Enterprise websites rarely serve user-facing services via raw IP addresses; treat this as an untrusted destination.")

        return recs

    def generate_email_recommendations(self, score: float, features: Dict[str, Any]) -> List[str]:
        """Generate concrete defensive advice for suspicious messages."""
        recs: List[str] = []
        if score >= 85:
            recs.append("DO NOT comply with urgent demands or follow links in this message.")
            recs.append("Never share one-time passwords (OTP), login credentials, or credit card details via email or chat.")
            recs.append("Report this message as a phishing attempt using your email client's 'Report Phishing' tool.")
        elif score >= 65:
            recs.append("Contact the alleged sender through an established out-of-band communication channel (e.g. phone or known app).")
            recs.append("Check the full sender email header to verify SPF, DKIM, and DMARC alignment if available.")
        elif score >= 35:
            recs.append("Review whether you initiated this transaction or inquiry before clicking any confirmation button.")
            recs.append("Hover over links (without clicking) to inspect if the display text matches the destination address.")
        else:
            recs.append("Message does not trigger common social engineering heuristics.")
            recs.append("Standard security hygiene: confirm identity before transferring funds or executing attachments.")

        return recs


def evaluate_risk(data: Dict[str, Any], is_url: bool = True) -> Dict[str, Any]:
    """Helper function to calculate risk and recommendations."""
    scorer = RiskScorer()
    if is_url:
        return scorer.score_url(data)
    else:
        return scorer.score_email_message(data)
