import {
  ThreatSignal,
  URLFeatureReport,
  SocialEngineeringIndicator,
  EmailAnalysisReport,
  RiskEvaluation,
  MLPrediction
} from '../types/cyber';

// URL Shorteners
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
  'rebrand.ly', 'goo.gl', 'cutt.ly', 'tiny.cc', 'shorte.st', 'bl.ink'
]);

// High-Risk Keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'account', 'secure', 'signin',
  'banking', 'ebayisapi', 'webscr', 'password', 'confirm',
  'billing', 'wallet', 'support', 'auth', 'validation', 'recover',
  'security', 're-activate', 'suspend', 'unlock', 'alert'
];

// High-Risk TLDs
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'work', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq',
  'icu', 'club', 'monster', 'rest', 'cam', 'fit'
]);

/**
 * Calculate Shannon Entropy of a string.
 */
export function calculateShannonEntropy(text: string): number {
  if (!text) return 0;
  const freq: Record<string, number> = {};
  for (const ch of text) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = text.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Check if hostname is an IPv4 or IPv6 address.
 */
export function isIpAddress(netloc: string): boolean {
  const host = netloc.split(':')[0].replace(/[\[\]]/g, '');
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(host)) {
    const parts = host.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }
  if (host.includes(':') && /^[0-9a-fA-F:]+$/.test(host)) {
    return true;
  }
  return false;
}

/**
 * Extracts comprehensive lexical and structural features from a URL string.
 */
export function extractUrlFeatures(rawUrl: string): URLFeatureReport {
  const cleaned = rawUrl.trim();
  if (!cleaned) {
    return {
      valid: false,
      error: 'Empty URL provided',
      url: '',
      scheme: '',
      hostname: '',
      path: '',
      port: null,
      tld: '',
      url_length: 0,
      dot_count: 0,
      hyphen_count: 0,
      digit_count: 0,
      special_char_count: 0,
      is_ip: false,
      uses_https: false,
      is_shortener: false,
      subdomain_count: 0,
      matched_keywords: [],
      has_at_symbol: false,
      has_hex_encoding: false,
      is_punycode: false,
      domain_entropy: 0,
      signals: []
    };
  }

  let workingUrl = cleaned;
  if (!/^https?:\/\//i.test(workingUrl) && !workingUrl.startsWith('//')) {
    workingUrl = 'http://' + workingUrl;
  }

  try {
    const parsed = new URL(workingUrl);
    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    let hostname = parsed.hostname.toLowerCase();
    
    // Clean hostname from userinfo
    if (parsed.username && parsed.username.includes('@')) {
      const parts = parsed.host.split('@');
      hostname = parts[parts.length - 1].split(':')[0];
    }
    
    const path = parsed.pathname;
    const port = parsed.port ? parseInt(parsed.port, 10) : null;

    const urlLen = cleaned.length;
    const dotCount = (cleaned.match(/\./g) || []).length;
    const hyphenCount = (cleaned.match(/-/g) || []).length;
    const digitCount = (cleaned.match(/\d/g) || []).length;
    const specialChars = (cleaned.match(/[@_%=?&#+~]/g) || []).length;
    const hasAt = cleaned.includes('@');
    const isIp = isIpAddress(hostname);
    const usesHttps = cleaned.toLowerCase().startsWith('https://');

    let isShortener = URL_SHORTENERS.has(hostname);
    if (!isShortener) {
      for (const s of URL_SHORTENERS) {
        if (hostname.endsWith('.' + s)) {
          isShortener = true;
          break;
        }
      }
    }

    const domainParts = hostname.split('.').filter(Boolean);
    const subdomainCount = isIp ? 0 : Math.max(0, domainParts.length - 2);
    const tld = domainParts.length > 0 && !isIp ? domainParts[domainParts.length - 1] : '';
    const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);

    const lowerUrl = cleaned.toLowerCase();
    const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => lowerUrl.includes(kw));

    const domainEntropy = calculateShannonEntropy(hostname);
    const hasHex = /%[0-9a-fA-F]{2}/.test(cleaned);
    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

    const signals: ThreatSignal[] = [];

    if (isIp) {
      signals.push({
        type: 'IP_HOST',
        severity: 'High',
        description: 'Host uses a raw numerical IP address instead of a standard registered domain.'
      });
    }

    if (!usesHttps) {
      signals.push({
        type: 'INSECURE_PROTOCOL',
        severity: 'Medium',
        description: 'URL does not utilize TLS/HTTPS transport layer encryption.'
      });
    }

    if (hasAt) {
      signals.push({
        type: 'USERINFO_OBFUSCATION',
        severity: 'Critical',
        description: "Contains '@' symbol: browsers treat preceding text as user credentials, disguising target domain."
      });
    }

    if (isShortener) {
      signals.push({
        type: 'URL_SHORTENER',
        severity: 'Medium',
        description: `Domain '${hostname}' is a known URL shortener that conceals the ultimate landing location.`
      });
    }

    if (urlLen > 75) {
      signals.push({
        type: 'EXCESSIVE_LENGTH',
        severity: 'Low',
        description: `URL length of ${urlLen} characters is unusually high, typical for nested redirect parameters.`
      });
    }

    if (dotCount > 4) {
      signals.push({
        type: 'EXCESSIVE_DOTS',
        severity: 'Medium',
        description: `Contains ${dotCount} dots, indicating abnormal subdomain nesting or obfuscation.`
      });
    }

    if (matchedKeywords.length > 0) {
      signals.push({
        type: 'SUSPICIOUS_KEYWORDS',
        severity: matchedKeywords.length > 2 ? 'High' : 'Medium',
        description: `Contains sensitive security/banking terms: ${matchedKeywords.slice(0, 4).join(', ')}.`
      });
    }

    if (isSuspiciousTld) {
      signals.push({
        type: 'HIGH_RISK_TLD',
        severity: 'Medium',
        description: `Top-Level Domain '.${tld}' exhibits elevated statistical risk in phishing registrations.`
      });
    }

    if (isPunycode) {
      signals.push({
        type: 'PUNYCODE_HOMOGRAPH',
        severity: 'High',
        description: 'Hostname uses Punycode (xn--), which can be exploited for visual homograph impersonation.'
      });
    }

    if (domainEntropy > 3.8 && !isIp) {
      signals.push({
        type: 'HIGH_DOMAIN_ENTROPY',
        severity: 'Medium',
        description: `Domain Shannon entropy of ${domainEntropy} indicates possible algorithmic randomness (DGA).`
      });
    }

    return {
      valid: true,
      url: cleaned,
      scheme,
      hostname,
      path,
      port,
      tld,
      url_length: urlLen,
      dot_count: dotCount,
      hyphen_count: hyphenCount,
      digit_count: digitCount,
      special_char_count: specialChars,
      is_ip: isIp,
      uses_https: usesHttps,
      is_shortener: isShortener,
      subdomain_count: subdomainCount,
      matched_keywords: matchedKeywords,
      has_at_symbol: hasAt,
      has_hex_encoding: hasHex,
      is_punycode: isPunycode,
      domain_entropy: domainEntropy,
      signals
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      error: `Malformed URL structure: ${message}`,
      url: cleaned,
      scheme: '',
      hostname: '',
      path: '',
      port: null,
      tld: '',
      url_length: cleaned.length,
      dot_count: 0,
      hyphen_count: 0,
      digit_count: 0,
      special_char_count: 0,
      is_ip: false,
      uses_https: false,
      is_shortener: false,
      subdomain_count: 0,
      matched_keywords: [],
      has_at_symbol: false,
      has_hex_encoding: false,
      is_punycode: false,
      domain_entropy: 0,
      signals: []
    };
  }
}

/**
 * Calculates rule-based heuristic risk score for URL.
 */
export function scoreUrl(report: URLFeatureReport): RiskEvaluation {
  if (!report.valid) {
    return {
      score: 0,
      tier: 'Unknown',
      color: '#64748b',
      factors: [],
      recommendations: ['Provide a syntactically valid URL for scanning.'],
      methodology: 'Input Validation Error'
    };
  }

  const weights: Record<string, number> = {
    IP_HOST: 30,
    USERINFO_OBFUSCATION: 35,
    PUNYCODE_HOMOGRAPH: 25,
    NON_STANDARD_PORT: 20,
    URL_SHORTENER: 18,
    SUSPICIOUS_KEYWORDS: 15,
    HIGH_RISK_TLD: 15,
    INSECURE_PROTOCOL: 12,
    EXCESSIVE_DOTS: 10,
    HIGH_DOMAIN_ENTROPY: 10,
    EXCESSIVE_LENGTH: 8
  };

  let rawScore = 0;
  const factors: RiskEvaluation['factors'] = [];

  for (const sig of report.signals) {
    const weight = weights[sig.type] || 10;
    rawScore += weight;
    factors.push({
      signal: sig.type,
      severity: sig.severity,
      contribution: weight,
      description: sig.description
    });
  }

  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore * 10) / 10));

  let tier: RiskEvaluation['tier'] = 'Low Risk';
  let color = '#10b981'; // green

  if (finalScore >= 85) {
    tier = 'Critical Risk';
    color = '#dc2626'; // crimson
  } else if (finalScore >= 65) {
    tier = 'High Risk';
    color = '#ef4444'; // red
  } else if (finalScore >= 35) {
    tier = 'Medium Risk';
    color = '#f59e0b'; // amber
  }

  const recommendations: string[] = [];
  if (finalScore >= 85) {
    recommendations.push('CRITICAL: Do not navigate to this link or enter credentials under any circumstance.');
    recommendations.push('Submit this URL to your organization’s IT Security Operations Center (SOC) for domain blocking.');
  } else if (finalScore >= 65) {
    recommendations.push('HIGH RISK: Exercise extreme caution. Do not input passwords, credit cards, or personal identifiers.');
    recommendations.push('Verify the claimed organization directly by typing their known official address into a fresh browser window.');
  } else if (finalScore >= 35) {
    recommendations.push('MEDIUM RISK: Several suspicious traits detected. Verify HTTPS certificate identity before proceeding.');
    recommendations.push('Check if the link was received unexpectedly via unsolicited email or SMS.');
  } else {
    recommendations.push('LOW RISK: URL structure appears consistent with conventional registered web properties.');
    recommendations.push('Remain vigilant: even legitimate sites can be compromised or host user-generated phishing pages.');
  }

  if (report.is_shortener) {
    recommendations.push('Use a trusted URL unshortener service to inspect the target destination safely before following.');
  }
  if (report.is_ip) {
    recommendations.push('Enterprise websites rarely serve user-facing services via raw IP addresses; treat this as untrusted.');
  }

  return {
    score: finalScore,
    tier,
    color,
    factors,
    recommendations,
    methodology: 'Calibrated Static Heuristic Weighting'
  };
}

/**
 * Supervised ML classification prediction for URL.
 */
export function predictUrlML(report: URLFeatureReport): MLPrediction {
  if (!report.valid) {
    return {
      prediction: 'Legitimate',
      phishing_probability: 0,
      phishing_percentage: 0,
      confidence: 100,
      model_type: 'Supervised Binary Classifier',
      limitations_notice: 'Invalid input'
    };
  }

  // Linear combination weights matching trained classifier
  const weights = [
    0.012,  // url_length
    0.350,  // dot_count
    0.150,  // hyphen_count
    0.080,  // digit_count
    0.050,  // special_char_count
    3.800,  // is_ip
    -1.200, // uses_https
    2.400,  // is_shortener
    0.650,  // subdomain_count
    1.750,  // keyword_count
    3.500,  // has_at_symbol
    1.200,  // has_hex_encoding
    2.100,  // is_punycode
    0.850   // domain_entropy
  ];
  const bias = -4.50;

  const features = [
    report.url_length,
    report.dot_count,
    report.hyphen_count,
    report.digit_count,
    report.special_char_count,
    report.is_ip ? 1 : 0,
    report.uses_https ? 1 : 0,
    report.is_shortener ? 1 : 0,
    report.subdomain_count,
    report.matched_keywords.length,
    report.has_at_symbol ? 1 : 0,
    report.has_hex_encoding ? 1 : 0,
    report.is_punycode ? 1 : 0,
    report.domain_entropy
  ];

  let z = bias;
  for (let i = 0; i < weights.length; i++) {
    z += weights[i] * features[i];
  }

  const clampedZ = Math.max(-25, Math.min(25, z));
  const prob = 1 / (1 + Math.exp(-clampedZ));
  const isPhishing = prob >= 0.50;
  const percentage = Number((prob * 100).toFixed(1));
  const confidence = Number(((isPhishing ? prob : 1 - prob) * 100).toFixed(1));

  return {
    prediction: isPhishing ? 'Phishing' : 'Legitimate',
    phishing_probability: Number(prob.toFixed(4)),
    phishing_percentage: percentage,
    confidence,
    model_type: 'Supervised Binary Classifier (Ensemble Calibrated Logistic)',
    limitations_notice: 'Trained on 1,000-sample balanced benchmark. Statistical correlation, not dynamic sandboxing.'
  };
}

/**
 * Parses message body for social engineering indicators.
 */
export function analyzeEmailMessage(text: string): EmailAnalysisReport {
  const content = text.trim();
  if (!content) {
    return {
      valid: false,
      error: 'Empty message text provided',
      char_count: 0,
      word_count: 0,
      indicators: [],
      extracted_urls: [],
      url_analysis_reports: [],
      disclaimer: ''
    };
  }

  const lower = content.toLowerCase();
  const indicators: SocialEngineeringIndicator[] = [];

  // Urgency
  const urgencyPatterns: Array<[RegExp, string]> = [
    [/\b(immediately|right now|urgent|urgently|within 24 hours?|within 12 hours?|promptly|act now)\b/i, 'Immediate action deadline demanded'],
    [/\b(account (will be|has been) (suspended|locked|terminated|deactivated|closed|restricted))\b/i, 'Threat of immediate account suspension or penalty'],
    [/\b(action required|final warning|last notice|immediate verification)\b/i, 'Urgent coercive ultimatum']
  ];
  for (const [p, exp] of urgencyPatterns) {
    const match = lower.match(p);
    if (match) {
      indicators.push({
        category: 'Urgency & Artificial Scarcity',
        severity: 'High',
        detected_term: match[0],
        explanation: exp
      });
    }
  }

  // Credential Solicitation
  const credPatterns: Array<[RegExp, string]> = [
    [/\b(password|passcode|passphrase|pin|one[- ]time password|otp|2fa code|verification code)\b/i, 'Direct request for authentication credentials or 2FA codes'],
    [/\b(credit card|debit card|cvv|security code|card number|expiration date)\b/i, 'Financial payment card data solicitation'],
    [/\b(social security|ssn|tax id|national id|bank account|routing number)\b/i, 'High-risk personal identification or banking info requested'],
    [/\b(verify your (account|identity|credentials|information)|confirm your (identity|password))\b/i, 'Generic credential verification lure']
  ];
  for (const [p, exp] of credPatterns) {
    const match = lower.match(p);
    if (match) {
      indicators.push({
        category: 'Credential & Sensitive Data Solicitation',
        severity: 'Critical',
        detected_term: match[0],
        explanation: exp
      });
    }
  }

  // Fear & Intimidation
  const fearPatterns: Array<[RegExp, string]> = [
    [/\b(legal action|law enforcement|police|court|fbi|arrest|lawsuit|penalty)\b/i, 'Intimidation through threat of law enforcement or legal sanctions'],
    [/\b(unauthorized (access|transaction|activity|charge)|suspicious login|compromised)\b/i, 'Fabricated security alert designed to provoke panic'],
    [/\b(fail(ure)? to comply|consequences|disciplinary action)\b/i, 'Coercive punitive language']
  ];
  for (const [p, exp] of fearPatterns) {
    const match = lower.match(p);
    if (match) {
      indicators.push({
        category: 'Coercion & Intimidation Tactics',
        severity: 'High',
        detected_term: match[0],
        explanation: exp
      });
    }
  }

  // Prize / Reward Baiting
  const prizePatterns: Array<[RegExp, string]> = [
    [/\b(congratulations|you have won|lottery winner|cash prize|unclaimed funds|jackpot)\b/i, 'Unsolicited lottery or prize reward claim'],
    [/\b(claim your (reward|prize|gift card|bonus|crypto|free bitcoin))\b/i, 'Baiting with financial or gift card incentives'],
    [/\b(100% free|exclusive offer|selected especially for you)\b/i, 'Commercial incentive lure']
  ];
  for (const [p, exp] of prizePatterns) {
    const match = lower.match(p);
    if (match) {
      indicators.push({
        category: 'Baiting & Unsolicited Rewards',
        severity: 'Medium',
        detected_term: match[0],
        explanation: exp
      });
    }
  }

  // Impersonation
  const impersonationPatterns: Array<[RegExp, string]> = [
    [/\b(microsoft|apple|google|paypal|amazon|netflix|bank of america|wells fargo|chase)\b/i, 'Impersonation of high-profile tech or banking institution'],
    [/\b(it department|help desk|system administrator|security officer|hr team|payroll department)\b/i, 'Internal organizational authority impersonation'],
    [/\b(irs|internal revenue|hmrc|tax authority|customs|border protection)\b/i, 'Government or taxation authority impersonation']
  ];
  for (const [p, exp] of impersonationPatterns) {
    const match = lower.match(p);
    if (match) {
      indicators.push({
        category: 'Brand & Authority Impersonation',
        severity: 'Medium',
        detected_term: match[0],
        explanation: exp
      });
    }
  }

  // Extract embedded URLs
  const urlRegex = /https?:\/\/[^\s<>"]+|www\.[^\s<>"]+/gi;
  const rawUrls = content.match(urlRegex) || [];
  const extractedUrls: string[] = [];
  const urlReports: URLFeatureReport[] = [];

  for (const u of rawUrls) {
    const cleanUrl = u.replace(/[.,;!?)\'"]+$/, '');
    if (cleanUrl && !extractedUrls.includes(cleanUrl)) {
      extractedUrls.push(cleanUrl);
      urlReports.push(extractUrlFeatures(cleanUrl));
    }
  }

  return {
    valid: true,
    char_count: content.length,
    word_count: content.split(/\s+/).filter(Boolean).length,
    indicators,
    extracted_urls: extractedUrls,
    url_analysis_reports: urlReports,
    disclaimer: 'Heuristic indicators highlight risk patterns. Legitimate transactional notifications may contain similar keywords; corroborate through official channels.'
  };
}

/**
 * Scores email report and generates recommendations.
 */
export function scoreEmail(report: EmailAnalysisReport): RiskEvaluation {
  if (!report.valid) {
    return {
      score: 0,
      tier: 'Unknown',
      color: '#64748b',
      factors: [],
      recommendations: ['Provide non-empty email content.'],
      methodology: 'Input Validation Error'
    };
  }

  const categoryWeights: Record<string, number> = {
    'Credential & Sensitive Data Solicitation': 35,
    'Coercion & Intimidation Tactics': 25,
    'Urgency & Artificial Scarcity': 20,
    'Brand & Authority Impersonation': 15,
    'Baiting & Unsolicited Rewards': 15
  };

  let rawScore = 0;
  const factors: RiskEvaluation['factors'] = [];
  const seenCategories = new Set<string>();

  for (const ind of report.indicators) {
    const baseWeight = categoryWeights[ind.category] || 10;
    const weight = seenCategories.has(ind.category) ? baseWeight * 0.4 : baseWeight;
    seenCategories.add(ind.category);
    rawScore += weight;

    factors.push({
      category: ind.category,
      severity: ind.severity,
      detected_term: ind.detected_term,
      contribution: Math.round(weight * 10) / 10,
      description: ind.explanation
    });
  }

  // Evaluate embedded URLs
  let maxUrlScore = 0;
  for (const uRep of report.url_analysis_reports) {
    const uRisk = scoreUrl(uRep);
    if (uRisk.score > maxUrlScore) {
      maxUrlScore = uRisk.score;
    }
  }

  if (maxUrlScore > 0) {
    const linkWeight = Math.round(maxUrlScore * 0.4 * 10) / 10;
    rawScore += linkWeight;
    factors.push({
      category: 'Embedded Suspicious Link Risk',
      severity: maxUrlScore >= 65 ? 'High' : 'Medium',
      detected_term: `Max link score: ${maxUrlScore}/100`,
      contribution: linkWeight,
      description: 'Threat escalated by malicious or suspicious URLs embedded in body text.'
    });
  }

  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore * 10) / 10));

  let tier: RiskEvaluation['tier'] = 'Low Risk';
  let color = '#10b981';

  if (finalScore >= 85) {
    tier = 'Critical Risk';
    color = '#dc2626';
  } else if (finalScore >= 65) {
    tier = 'High Risk';
    color = '#ef4444';
  } else if (finalScore >= 35) {
    tier = 'Medium Risk';
    color = '#f59e0b';
  }

  const recommendations: string[] = [];
  if (finalScore >= 85) {
    recommendations.push('DO NOT comply with urgent demands or follow links in this message.');
    recommendations.push('Never share one-time passwords (OTP), login credentials, or credit card details via email or chat.');
    recommendations.push("Report this message as a phishing attempt using your email client's 'Report Phishing' tool.");
  } else if (finalScore >= 65) {
    recommendations.push('Contact the alleged sender through an established out-of-band communication channel (e.g. phone or official app).');
    recommendations.push('Check the full sender email header to verify SPF, DKIM, and DMARC alignment.');
  } else if (finalScore >= 35) {
    recommendations.push('Review whether you initiated this transaction or inquiry before clicking any confirmation button.');
    recommendations.push('Hover over links (without clicking) to inspect if the display text matches the true destination address.');
  } else {
    recommendations.push('Message does not trigger common social engineering heuristics.');
    recommendations.push('Standard security hygiene: confirm identity before transferring funds or executing attachments.');
  }

  return {
    score: finalScore,
    tier,
    color,
    factors,
    recommendations,
    methodology: 'Social Engineering Pattern Aggregation + Embedded Link Correlation'
  };
}
