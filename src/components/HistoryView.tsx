import React, { useState } from 'react';
import { Download, Trash2, Search, Filter } from 'lucide-react';
import { ScanHistoryRecord } from '../types/cyber';

interface HistoryViewProps {
  history: ScanHistoryRecord[];
  onClearHistory: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({ history, onClearHistory }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [tierFilter, setTierFilter] = useState('ALL');

  const filtered = history.filter(item => {
    const matchesSearch = item.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          item.type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesTier = tierFilter === 'ALL' || item.tier.toUpperCase().includes(tierFilter);
    return matchesSearch && matchesTier;
  });

  const exportCSV = () => {
    if (history.length === 0) return;
    const headers = ['Timestamp', 'Type', 'Target', 'Score', 'Tier', 'ML Verdict', 'ML Confidence'];
    const rows = history.map(h => [
      `"${h.timestamp}"`,
      `"${h.type}"`,
      `"${h.target.replace(/"/g, '""')}"`,
      h.score,
      `"${h.tier}"`,
      `"${h.ml_verdict}"`,
      `"${h.ml_confidence}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cybershield_scan_history_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
            Session Scan Audit Log
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Historical audit log of all URL and email scans performed during the current active session.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportCSV}
            disabled={history.length === 0}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 text-xs font-medium rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={onClearHistory}
            disabled={history.length === 0}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-rose-500/10 hover:bg-rose-500/20 disabled:opacity-40 text-rose-300 border border-rose-500/30 text-xs font-medium rounded-lg transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Log</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search targets, URLs, or message snippets..."
            className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-teal-400 font-mono"
          />
        </div>

        <div className="flex items-center gap-1 w-full sm:w-auto overflow-x-auto p-1 bg-slate-900 rounded-lg border border-slate-800">
          {['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((tier) => (
            <button
              key={tier}
              onClick={() => setTierFilter(tier)}
              className={`px-3 py-1 text-xs font-medium rounded-md whitespace-nowrap transition-colors cursor-pointer ${
                tierFilter === tier
                  ? 'bg-slate-800 text-teal-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tier}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-900/50">
        {filtered.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-800/80 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="py-2.5 px-4">Time</th>
                  <th className="py-2.5 px-4">Type</th>
                  <th className="py-2.5 px-4">Target Inspected</th>
                  <th className="py-2.5 px-4">Score</th>
                  <th className="py-2.5 px-4">Risk Tier</th>
                  <th className="py-2.5 px-4">ML Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {filtered.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-4 font-mono text-slate-400 tabular-nums">{item.timestamp}</td>
                    <td className="py-2.5 px-4">
                      <span className="font-mono text-xs text-teal-400">{item.type}</span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-white max-w-xs truncate" title={item.target}>
                      {item.target}
                    </td>
                    <td className="py-2.5 px-4 font-mono font-bold tabular-nums">
                      {item.score}/100
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        item.tier === 'Critical Risk' ? 'bg-red-500/20 text-red-400' :
                        item.tier === 'High Risk' ? 'bg-rose-500/20 text-rose-400' :
                        item.tier === 'Medium Risk' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {item.tier}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-300">
                      {item.ml_verdict} ({item.ml_confidence})
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs">
            {history.length === 0 
              ? 'No scans conducted in current session. Analyze URLs or emails to generate audit entries.'
              : 'No log entries match the current search or risk tier filter.'}
          </div>
        )}
      </div>
    </div>
  );
};
