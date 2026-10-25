"""
CyberShield AI — URL Threat Analyzer Module
Extracts structural, lexical, and behavioral threat indicators from URLs.
All analysis is performed statically without network requests to external infrastructure.
"""

import math
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, unquote

# Configurable list of common URL shortener domains
DEFAULT_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "goo.gl", "cutt.ly", "tiny.cc", "shorte.st", "bl.ink",
    "adf.ly", "v.gd", "tr.im", "s.id", "soo.gd", "qr.ae"
}

# High-risk keywords commonly found in phishing lures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "signin",
    "banking", "ebayisapi", "webscr", "password", "confirm",
    "billing", "wallet", "support", "auth", "validation", "recover",
    "security", "re-activate", "suspend", "unlock", "alert", "service"
]

# High-risk Top-Level Domains (frequently abused in throwaway phishing kits)
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "buzz", "tk", "ml", "ga", "cf", "gq",
    "icu", "club", "monster", "rest", "cam", "fit"
}

# Standard legitimate ports vs suspicious custom ports
SUSPICIOUS_PORTS = {8080, 8443, 8888, 3128, 9000, 4444, 1337}


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (higher entropy indicates algorithmic randomness)."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class URLAnalyzer:
    """
    Analyzes URLs using static heuristic analysis.
    Does NOT initiate socket connections, resolve DNS, or fetch content.
    """

    def __init__(self, shorteners: List[str] = None):
        self.shorteners = set(shorteners) if shorteners else DEFAULT_URL_SHORTENERS

    def is_ip_address(self, netloc: str) -> bool:
        """Check if hostname is a raw IPv4 or IPv6 address instead of a registered domain."""
        host = netloc.split(':')[0].strip('[]')
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, host):
            parts = host.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        # IPv6 pattern
        ipv6_pattern = r'^[0-9a-fA-F:]+$'
        if ':' in host and re.match(ipv6_pattern, host):
            return True
        return False

    def extract_features(self, raw_url: str) -> Dict[str, Any]:
        """
        Extract lexical, syntactic, and behavioral features from a URL string.
        Returns a dictionary of extracted features and threat signals.
        """
        cleaned_url = raw_url.strip()
        if not cleaned_url:
            return {"error": "Empty URL provided", "valid": False}

        # Normalize scheme if omitted for structural inspection
        working_url = cleaned_url
        if not (working_url.startswith("http://") or working_url.startswith("https://") or working_url.startswith("//")):
            working_url = "http://" + working_url

        try:
            parsed = urlparse(working_url)
        except Exception as e:
            return {"error": f"Malformed URL syntax: {str(e)}", "valid": False}

        scheme = parsed.scheme.lower() if parsed.scheme else "none"
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        # Extract hostname and port, handling userinfo if present
        hostname = (parsed.hostname or "").lower()
        if not hostname and netloc:
            # Fallback if hostname is None due to unusual parsing
            clean_host = netloc.split('@')[-1]
            hostname = clean_host.split(':')[0].strip('[]')

        port = parsed.port

        # Lexical statistics
        url_len = len(cleaned_url)
        dot_count = cleaned_url.count('.')
        hyphen_count = cleaned_url.count('-')
        digit_count = sum(c.isdigit() for c in cleaned_url)
        special_char_count = len(re.findall(r'[@_%=?&#+~]', cleaned_url))
        at_symbol_present = '@' in cleaned_url
        double_slash_in_path = '//' in path

        # IP Address check
        is_ip = self.is_ip_address(hostname)

        # HTTPS usage
        uses_https = cleaned_url.lower().startswith("https://")

        # URL Shortener check
        is_shortener = hostname in self.shorteners or any(hostname.endswith("." + s) for s in self.shorteners)

        # Subdomain analysis
        domain_parts = [p for p in hostname.split('.') if p]
        subdomain_count = max(0, len(domain_parts) - 2) if not is_ip else 0
        tld = domain_parts[-1] if domain_parts and not is_ip else ""
        is_suspicious_tld = tld in SUSPICIOUS_TLDS

        # Keyword matching
        lower_url = cleaned_url.lower()
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]

        # Domain entropy & encoded characters
        domain_entropy = calculate_shannon_entropy(hostname)
        has_hex_encoding = bool(re.search(r'%[0-9a-fA-F]{2}', cleaned_url))
        punycode = hostname.startswith("xn--") or ".xn--" in hostname

        # Suspicious port usage
        has_suspicious_port = port in SUSPICIOUS_PORTS

        # Collect threat signals
        signals: List[Dict[str, Any]] = []

        if is_ip:
            signals.append({
                "type": "IP_HOST",
                "severity": "High",
                "description": "Host uses a raw numerical IP address instead of a legitimate domain name."
            })

        if not uses_https:
            signals.append({
                "type": "INSECURE_PROTOCOL",
                "severity": "Medium",
                "description": "URL does not use HTTPS encryption (HTTP or unspecified protocol)."
            })

        if at_symbol_present:
            signals.append({
                "type": "USERINFO_OBFUSCATION",
                "severity": "Critical",
                "description": "Contains '@' symbol, which browsers treat as user credentials, obscuring the actual destination host."
            })

        if is_shortener:
            signals.append({
                "type": "URL_SHORTENER",
                "severity": "Medium",
                "description": f"Domain '{hostname}' is a known URL shortening service that conceals the true landing page."
            })

        if url_len > 75:
            signals.append({
                "type": "EXCESSIVE_LENGTH",
                "severity": "Low",
                "description": f"URL length is {url_len} characters, which is unusually long and often used to embed phishing parameters."
            })

        if dot_count > 4:
            signals.append({
                "type": "EXCESSIVE_DOTS",
                "severity": "Medium",
                "description": f"Contains {dot_count} dots, indicating excessive subdomain nesting or confusing domain structure."
            })

        if matched_keywords:
            signals.append({
                "type": "SUSPICIOUS_KEYWORDS",
                "severity": "Medium" if len(matched_keywords) <= 2 else "High",
                "description": f"Found high-risk security/banking keywords: {', '.join(matched_keywords[:5])}."
            })

        if is_suspicious_tld:
            signals.append({
                "type": "HIGH_RISK_TLD",
                "severity": "Medium",
                "description": f"Top-level domain '.{tld}' has a statistically higher frequency of phishing and spam registration."
            })

        if punycode:
            signals.append({
                "type": "PUNYCODE_HOMOGRAPH",
                "severity": "High",
                "description": "Hostname uses Punycode (xn--), which can be exploited for IDN homograph impersonation attacks."
            })

        if domain_entropy > 3.8 and not is_ip:
            signals.append({
                "type": "HIGH_DOMAIN_ENTROPY",
                "severity": "Medium",
                "description": f"Domain Shannon entropy is {domain_entropy}, indicating machine-generated or randomized strings."
            })

        if has_suspicious_port:
            signals.append({
                "type": "NON_STANDARD_PORT",
                "severity": "High",
                "description": f"URL connects over non-standard port {port}, bypassing standard HTTP/HTTPS filtering."
            })

        return {
            "valid": True,
            "url": cleaned_url,
            "scheme": scheme,
            "hostname": hostname,
            "path": path,
            "port": port,
            "tld": tld,
            "url_length": url_len,
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "digit_count": digit_count,
            "special_char_count": special_char_count,
            "is_ip": is_ip,
            "uses_https": uses_https,
            "is_shortener": is_shortener,
            "subdomain_count": subdomain_count,
            "matched_keywords": matched_keywords,
            "has_at_symbol": at_symbol_present,
            "has_hex_encoding": has_hex_encoding,
            "is_punycode": punycode,
            "domain_entropy": domain_entropy,
            "signals": signals
        }


def analyze_url(url: str, shorteners: List[str] = None) -> Dict[str, Any]:
    """Convenience helper to extract features from a URL."""
    analyzer = URLAnalyzer(shorteners=shorteners)
    return analyzer.extract_features(url)
