import React, { useState } from 'react';
import { Mail, AlertTriangle, ShieldCheck, Link2, ExternalLink, CornerDownRight } from 'lucide-react';
import { analyzeEmailMessage, scoreEmail, scoreUrl } from '../utils/cyberDetector';
import { EmailAnalysisReport, RiskEvaluation, ScanHistoryRecord } from '../types/cyber';

interface EmailScannerViewProps {
  onScanLogged: (record: ScanHistoryRecord) => void;
}

export const EmailScannerView: React.FC<EmailScannerViewProps> = ({ onScanLogged }) => {
  const [inputText, setInputText] = useState('');
  const [report, setReport] = useState<EmailAnalysisReport | null>(null);
  const [risk, setRisk] = useState<RiskEvaluation | null>(null);

  const sampleMessages = [
    {
      title: '🟢 Benign Meeting Agenda',
      text: "Hi Team, please find attached the agenda for tomorrow's technical security architecture review at 2 PM. Let me know if you would like to add any discussion points."
    },
    {
      title: '🔴 Coercive Account Suspension Threat',
      text: "URGENT ACTION REQUIRED: Your bank account will be suspended within 24 hours due to unauthorized activity. Verify your password and 2FA code immediately at http://192.168.1.50/bank/verify.php to prevent legal action and account closure."
    },
    {
      title: '🟡 Unsolicited Prize Baiting Lure',
      text: "Congratulations! You have won $1,000,000 in the international reward lottery! Claim your prize immediately by responding with your credit card number and mailing address to release funds."
    }
  ];

  const handleScan = (textToScan?: string) => {
    const content = (textToScan !== undefined ? textToScan : inputText).trim();
    if (!content) return;

    if (textToScan) setInputText(textToScan);

    const rep = analyzeEmailMessage(content);
    const rsk = scoreEmail(rep);

    setReport(rep);
    setRisk(rsk);

    if (rep.valid) {
      onScanLogged({
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        type: 'Email/Message',
        target: content.length > 55 ? content.substring(0, 52) + '...' : content,
        score: rsk.score,
        tier: rsk.tier,
        ml_verdict: 'Social Eng NLP',
        ml_confidence: `${rep.indicators.length} signals`
      });
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* Header */}
      <div>
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
          Email & Message Phishing Analyzer
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          Detect coercive language, credential solicitation lures, urgency tactics, and embedded malicious links in message bodies.
        </p>
      </div>

      {/* Simulated Sample Cases */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
        <div className="text-xs font-medium text-slate-300 mb-2.5">
          Simulated Test Cases (Safe Demo Messages):
        </div>
        <div className="flex flex-wrap gap-2">
          {sampleMessages.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleScan(s.text)}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
            >
              {s.title}
            </button>
          ))}
        </div>
      </div>

      {/* Text Area Input */}
      <div className="space-y-3">
        <textarea
          rows={5}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste email body or message text here to evaluate social engineering indicators..."
          className="w-full p-4 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 font-sans resize-y"
        />
        <div className="flex items-center justify-between">
          <span className="text-xs text-slate-500">
            {inputText.length} characters · {inputText.split(/\s+/).filter(Boolean).length} words
          </span>
          <button
            onClick={() => handleScan()}
            className="px-5 py-2.5 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
          >
            Scan Message
          </button>
        </div>
      </div>

      {/* Scan Results */}
      {report && risk && (
        <div className="space-y-6 pt-2">
          {/* Risk Overview Banner */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/70 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Composite Threat Risk Index
              </span>
              <div className="flex items-baseline gap-3">
                <span className="text-4xl font-bold font-mono tabular-nums" style={{ color: risk.color }}>
                  {risk.score}
                </span>
                <span className="text-slate-500 text-sm font-mono">/ 100</span>
                <span 
                  className="px-2.5 py-1 rounded text-xs font-semibold"
                  style={{ backgroundColor: `${risk.color}22`, color: risk.color, border: `1px solid ${risk.color}` }}
                >
                  {risk.tier}
                </span>
              </div>
            </div>

            <div className="text-xs text-slate-400 max-w-md">
              Evaluates urgency pressures, credential/PIN inquiries, threat language, and embedded link risk factors in aggregate.
            </div>
          </div>

          {/* Indicators & Link Analysis */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Social Engineering Triggers */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Identified Social Engineering Signals ({report.indicators.length})</span>
              </h2>

              {report.indicators.length > 0 ? (
                <div className="space-y-2">
                  {report.indicators.map((ind, i) => (
                    <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">{ind.category}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          ind.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                          ind.severity === 'High' ? 'bg-rose-500/20 text-rose-400' :
                          ind.severity === 'Medium' ? 'bg-amber-500/20 text-amber-400' :
                          'bg-slate-700 text-slate-300'
                        }`}>
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-slate-400">{ind.explanation}</p>
                      <div className="font-mono text-teal-400 text-[11px] pt-0.5">
                        Matched Term: &quot;{ind.detected_term}&quot;
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4" />
                  <span>No obvious coercive or credential-harvesting patterns found in body text.</span>
                </div>
              )}
            </div>

            {/* Embedded Links Analysis */}
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Link2 className="w-4 h-4 text-sky-400" />
                <span>Embedded Link Inspection ({report.extracted_urls.length})</span>
              </h2>

              {report.extracted_urls.length > 0 ? (
                <div className="space-y-2">
                  {report.url_analysis_reports.map((uRep, i) => {
                    const uRisk = scoreUrl(uRep);
                    return (
                      <div key={i} className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 text-xs space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-white truncate max-w-[280px]">{uRep.url}</span>
                          <span 
                            className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold"
                            style={{ backgroundColor: `${uRisk.color}22`, color: uRisk.color }}
                          >
                            {uRisk.score}/100 ({uRisk.tier})
                          </span>
                        </div>
                        <div className="text-slate-400 text-[11px]">
                          {uRep.signals.length > 0 ? (
                            <span>Flags: {uRep.signals.map(s => s.type).join(', ')}</span>
                          ) : (
                            <span className="text-emerald-400">Clean baseline URL structure</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-slate-800/40 text-slate-400 text-xs">
                  No hyperlinks or URL strings were detected inside the message body.
                </div>
              )}
            </div>
          </div>

          {/* Recommendations Strip */}
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
            <h2 className="text-sm font-semibold text-white">Actionable Security Recommendations</h2>
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
      )}
    </div>
  );
};
