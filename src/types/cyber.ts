export interface ThreatSignal {
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export interface URLFeatureReport {
  valid: boolean;
  error?: string;
  url: string;
  scheme: string;
  hostname: string;
  path: string;
  port: number | null;
  tld: string;
  url_length: number;
  dot_count: number;
  hyphen_count: number;
  digit_count: number;
  special_char_count: number;
  is_ip: boolean;
  uses_https: boolean;
  is_shortener: boolean;
  subdomain_count: number;
  matched_keywords: string[];
  has_at_symbol: boolean;
  has_hex_encoding: boolean;
  is_punycode: boolean;
  domain_entropy: number;
  signals: ThreatSignal[];
}

export interface SocialEngineeringIndicator {
  category: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  detected_term: string;
  explanation: string;
}

export interface EmailAnalysisReport {
  valid: boolean;
  error?: string;
  char_count: number;
  word_count: number;
  indicators: SocialEngineeringIndicator[];
  extracted_urls: string[];
  url_analysis_reports: URLFeatureReport[];
  disclaimer: string;
}

export interface RiskEvaluation {
  score: number;
  tier: 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical Risk' | 'Unknown';
  color: string;
  factors: Array<{
    signal?: string;
    category?: string;
    severity: string;
    contribution: number;
    description: string;
    detected_term?: string;
  }>;
  recommendations: string[];
  methodology: string;
}

export interface MLPrediction {
  prediction: 'Legitimate' | 'Phishing';
  phishing_probability: number;
  phishing_percentage: number;
  confidence: number;
  model_type: string;
  limitations_notice: string;
}

export interface ScanHistoryRecord {
  id: string;
  timestamp: string;
  type: 'URL' | 'Email/Message';
  target: string;
  score: number;
  tier: string;
  ml_verdict: string;
  ml_confidence: string;
}
