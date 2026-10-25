import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight, CornerDownRight } from 'lucide-react';
import { extractUrlFeatures, scoreUrl, predictUrlML } from '../utils/cyberDetector';
import { URLFeatureReport, RiskEvaluation, MLPrediction, ScanHistoryRecord } from '../types/cyber';

interface UrlScannerViewProps {
  onScanLogged: (record: ScanHistoryRecord) => void;
}

export const UrlScannerView: React.FC<UrlScannerViewProps> = ({ onScanLogged }) => {
  const [inputUrl, setInputUrl] = useState('');
  const [report, setReport] = useState<URLFeatureReport | null>(null);
  const [risk, setRisk] = useState<RiskEvaluation | null>(null);
  const [mlPred, setMlPred] = useState<MLPrediction | null>(null);

  const sampleCases = [
    { label: '🟢 Official Government Portal', url: 'https://www.cisa.gov/resources-tools/cybersecurity-alerts' },
    { label: '🟡 Concealed URL Shortener', url: 'https://bit.ly/secure-banking-verification-notice' },
    { label: '🔴 Blatant IP Credential Harvester', url: 'http://user@192.168.1.100/paypal/login.php?cmd=verify' },
    { label: '🟠 Deceptive Punycode Homograph', url: 'http://xn--appl-43d.com/support/account/verify' }
  ];

  const handleScan = (urlToScan?: string) => {
    const target = (urlToScan !== undefined ? urlToScan : inputUrl).trim();
    if (!target) return;

    if (urlToScan) setInputUrl(urlToScan);

    const rep = extractUrlFeatures(target);
    const rsk = scoreUrl(rep);
    const ml = predictUrlML(rep);

    setReport(rep);
    setRisk(rsk);
    setMlPred(ml);

    if (rep.valid) {
      onScanLogged({
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        type: 'URL',
        target: target.length > 55 ? target.substring(0, 52) + '...' : target,
        score: rsk.score,
        tier: rsk.tier,
        ml_verdict: ml.prediction,
        ml_confidence: `${ml.confidence}%`
      });
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          URL Threat Analyzer
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Static lexical and structural inspection of suspicious links without initiating outbound network connections.
        </p>
      </div>

      {/* Simulated Sample Links */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
        <div className="text-xs font-medium text-slate-300 mb-2.5">
          Simulated Test Cases (Safe Demo Links):
        </div>
        <div className="flex flex-wrap gap-2">
          {sampleCases.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleScan(s.url)}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input Box */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            placeholder="Enter URL to analyze (e.g. http://192.168.1.50/account/login)"
            className="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 font-mono"
          />
        </div>
        <button
          onClick={() => handleScan()}
          className="px-5 py-2.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-lg transition-colors cursor-pointer shrink-0"
        >
          Scan URL
        </button>
      </div>

      {/* Analysis Results */}
      {report && risk && mlPred && (
        <div className="space-y-6 pt-2">
          {/* Main Verdict Strip */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Heuristic Risk Score */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                  Heuristic Risk Score
                </span>
                <span 
                  className="px-2.5 py-1 rounded text-xs font-semibold"
                  style={{ backgroundColor: `${risk.color}22`, color: risk.color, border: `1px solid ${risk.color}` }}
                >
                  {risk.tier}
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-bold font-mono tabular-nums" style={{ color: risk.color }}>
                  {risk.score}
                </span>
                <span className="text-slate-500 text-sm font-mono">/ 100</span>
              </div>
              <div className="text-xs text-slate-400 leading-relaxed">
                Calculated from transparent structural indicator weights. Calibrated to avoid presenting heuristic counts as verified attack probabilities.
              </div>
            </div>

            {/* Supervised ML Prediction */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                  Supervised ML Verdict
                </span>
                <span className={`px-2.5 py-1 rounded text-xs font-semibold ${
                  mlPred.prediction === 'Phishing' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}>
                  {mlPred.prediction}
                </span>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-4xl font-bold font-mono text-white tabular-nums">
                  {mlPred.confidence}%
                </span>
                <span className="text-slate-500 text-xs">confidence (P: {mlPred.phishing_percentage}%)</span>
              </div>
              <div className="text-xs text-slate-400 leading-relaxed">
                Evaluated against the canonical 14-dimensional feature vector using trained logistic ensemble decision boundaries.
              </div>
            </div>
          </div>

          {/* Threat Signals & Actionable Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Detected Indicators */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>Detected Risk Signals ({report.signals.length})</span>
              </h2>
              {report.signals.length > 0 ? (
                <div className="space-y-2">
                  {report.signals.map((sig, i) => (
                    <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">{sig.type}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          sig.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                          sig.severity === 'High' ? 'bg-rose-500/20 text-rose-400' :
                          sig.severity === 'Medium' ? 'bg-amber-500/20 text-amber-400' :
                          'bg-slate-700 text-slate-300'
                        }`}>
                          {sig.severity}
                        </span>
                      </div>
                      <p className="text-slate-400">{sig.description}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>No high-risk structural threat indicators were detected in this URL.</span>
                </div>
              )}
            </div>

            {/* Actionable Recommendations */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-teal-400" />
                <span>Actionable Defensive Recommendations</span>
              </h2>
              <div className="space-y-2">
                {risk.recommendations.map((rec, i) => (
                  <div key={i} className="p-3 rounded-lg border-l-2 border-teal-400 bg-slate-900/80 text-xs text-slate-300 flex items-start gap-2">
                    <CornerDownRight className="w-3.5 h-3.5 text-teal-400 shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Feature Matrix Table */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
            <h2 className="text-sm font-semibold text-white">Extracted Lexical & Structural Metrics</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-800/80 text-slate-400 uppercase font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-4">Feature Name</th>
                    <th className="py-2.5 px-4">Observed Value</th>
                    <th className="py-2.5 px-4">Benign Baseline</th>
                    <th className="py-2.5 px-4">Evaluation Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  <tr>
                    <td className="py-2 px-4 font-mono">url_length</td>
                    <td className="py-2 px-4 font-mono tabular-nums text-white">{report.url_length} chars</td>
                    <td className="py-2 px-4 text-slate-400">&lt; 75 chars</td>
                    <td className="py-2 px-4 text-slate-400">{report.url_length > 75 ? 'Abnormally long URL' : 'Within normal bounds'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">dot_count</td>
                    <td className="py-2 px-4 font-mono tabular-nums text-white">{report.dot_count}</td>
                    <td className="py-2 px-4 text-slate-400">1 – 3</td>
                    <td className="py-2 px-4 text-slate-400">{report.dot_count > 4 ? 'Deeply nested subdomains' : 'Standard domain dot distribution'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">is_ip</td>
                    <td className="py-2 px-4 font-mono text-white">{report.is_ip ? 'Yes (FLAGGED)' : 'No'}</td>
                    <td className="py-2 px-4 text-slate-400">No (Domain)</td>
                    <td className="py-2 px-4 text-slate-400">{report.is_ip ? 'Bypasses DNS reputation systems' : 'Standard registered domain'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">uses_https</td>
                    <td className="py-2 px-4 font-mono text-white">{report.uses_https ? 'Yes' : 'No (FLAGGED)'}</td>
                    <td className="py-2 px-4 text-slate-400">Yes (TLS)</td>
                    <td className="py-2 px-4 text-slate-400">{report.uses_https ? 'Encrypted transport' : 'Unencrypted plaintext communication'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">is_shortener</td>
                    <td className="py-2 px-4 font-mono text-white">{report.is_shortener ? 'Yes (SHORTENER)' : 'No'}</td>
                    <td className="py-2 px-4 text-slate-400">No</td>
                    <td className="py-2 px-4 text-slate-400">{report.is_shortener ? 'Conceals actual landing destination' : 'Direct domain address'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">domain_entropy</td>
                    <td className="py-2 px-4 font-mono tabular-nums text-white">{report.domain_entropy}</td>
                    <td className="py-2 px-4 text-slate-400">&lt; 3.8</td>
                    <td className="py-2 px-4 text-slate-400">{report.domain_entropy > 3.8 ? 'High algorithmic randomness (DGA signature)' : 'Natural language character distribution'}</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 font-mono">matched_keywords</td>
                    <td className="py-2 px-4 font-mono text-white">
                      {report.matched_keywords.length > 0 ? report.matched_keywords.join(', ') : 'None'}
                    </td>
                    <td className="py-2 px-4 text-slate-400">None</td>
                    <td className="py-2 px-4 text-slate-400">Sensitive credential or banking tokens</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
