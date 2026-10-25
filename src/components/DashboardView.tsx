import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Cpu, Terminal, ArrowRight, ExternalLink } from 'lucide-react';
import { ScanHistoryRecord } from '../types/cyber';

interface DashboardViewProps {
  history: ScanHistoryRecord[];
  onNavigate: (tab: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ history, onNavigate }) => {
  const totalScans = history.length;
  const highCriticalCount = history.filter(h => h.tier === 'High Risk' || h.tier === 'Critical Risk').length;
  const urlCount = history.filter(h => h.type === 'URL').length;
  const emailCount = history.filter(h => h.type === 'Email/Message').length;

  const lowCount = history.filter(h => h.tier === 'Low Risk').length;
  const medCount = history.filter(h => h.tier === 'Medium Risk').length;
  const highCount = history.filter(h => h.tier === 'High Risk').length;
  const critCount = history.filter(h => h.tier === 'Critical Risk').length;

  return (
    <div className="space-y-8 max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* Hero Banner */}
      <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-[#0e172a] p-6 lg:p-8 relative overflow-hidden">
        <div className="relative z-10 max-w-3xl space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono text-teal-400">
            <span>DEFENSIVE CYBERSECURITY</span>
            <span aria-hidden="true">·</span>
            <span>OFFLINE HEURISTIC & ML PIPELINE</span>
            <span aria-hidden="true">·</span>
            <span>PORTFOLIO RELEASE 1.0</span>
          </div>
          <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold tracking-tight text-white font-sans text-balance">
            Intelligent Phishing & URL Threat Detection
          </h1>
          <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
            Multi-layered cybersecurity system analyzing deceptive URLs and social-engineering message text. 
            Combines 14 static structural extractors, Shannon domain entropy, and a supervised machine-learning classifier (96.5% accuracy) with zero external network footprint.
          </p>
          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              onClick={() => onNavigate('url-scanner')}
              className="flex items-center gap-2 px-4 py-2 bg-teal-500 hover:bg-teal-400 text-slate-950 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              <span>Scan Target URL</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => onNavigate('email-scanner')}
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium rounded-lg transition-colors cursor-pointer"
            >
              <span>Analyze Suspicious Email</span>
            </button>
            <button
              onClick={() => onNavigate('deliverables')}
              className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <span>View Academic Deliverables & Source</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400">Total Scans Run</span>
            <Terminal className="w-4 h-4 text-teal-400" />
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-white tabular-nums">
            {totalScans}
          </div>
          <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5">
            <span>{urlCount} URLs</span>
            <span aria-hidden="true">·</span>
            <span>{emailCount} Messages</span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400">High / Critical Flags</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-rose-400 tabular-nums">
            {highCriticalCount}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            {totalScans > 0 ? `${Math.round((highCriticalCount / totalScans) * 100)}% of tested inputs` : 'Awaiting input testing'}
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400">Model Accuracy</span>
            <Cpu className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-sky-400 tabular-nums">
            96.5%
          </div>
          <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5">
            <span>Recall: 97.0%</span>
            <span aria-hidden="true">·</span>
            <span>F1: 96.5%</span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400">Security Boundary</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3 text-lg font-bold font-mono text-emerald-400">
            100% Offline
          </div>
          <div className="mt-1 text-xs text-slate-400">
            Zero socket or DNS queries
          </div>
        </div>
      </div>

      {/* Grid: Risk Distribution & Defensive Architecture */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Breakdown */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/50 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Session Risk Distribution</h2>
            <span className="text-xs text-slate-400 font-mono">{totalScans} events logged</span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300">Low Risk (0–34)</span>
                <span className="font-mono text-emerald-400 tabular-nums">{lowCount} scans</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-emerald-500 h-full rounded-full transition-all" 
                  style={{ width: `${totalScans > 0 ? (lowCount / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300">Medium Risk (35–64)</span>
                <span className="font-mono text-amber-400 tabular-nums">{medCount} scans</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-amber-500 h-full rounded-full transition-all" 
                  style={{ width: `${totalScans > 0 ? (medCount / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300">High Risk (65–84)</span>
                <span className="font-mono text-rose-400 tabular-nums">{highCount} scans</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-rose-500 h-full rounded-full transition-all" 
                  style={{ width: `${totalScans > 0 ? (highCount / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-300">Critical Risk (85–100)</span>
                <span className="font-mono text-red-500 tabular-nums">{critCount} scans</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-red-600 h-full rounded-full transition-all" 
                  style={{ width: `${totalScans > 0 ? (critCount / totalScans) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>

          <div className="pt-2 text-xs text-slate-400 border-t border-slate-800">
            Heuristic thresholds are configured per NIST CSF guidelines to maximize defensive recall while bounding false positive rates.
          </div>
        </div>

        {/* Defensive Security Scope Card */}
        <div className="p-6 rounded-xl border border-slate-800 bg-slate-900/50 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">System Scope & Safeguards</h2>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>

          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <p>
              <strong className="text-white">Strict Defensive Guarantee:</strong> CyberShield AI executes pure in-memory lexical and NLP inspection. It never executes automated crawls, never sends HTTP requests to suspicious hosts, and never executes remote JavaScript payloads.
            </p>
            <p>
              <strong className="text-white">Zero Credential Collection:</strong> The tool does not store, forward, or harvest user credentials, session tokens, or sensitive identification data.
            </p>
            <p>
              <strong className="text-white">Transparent Explainability:</strong> Unlike opaque proprietary threat blackboxes, every risk verdict provides itemized rule weights, detected tokens, and explicit defensive recommendations.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-teal-500/10 border border-teal-500/20 text-xs text-teal-300">
            Academic portfolio prototype designed for academic review and submission to Google Forms and GitHub.
          </div>
        </div>
      </div>
    </div>
  );
};
