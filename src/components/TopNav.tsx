import React from 'react';
import { Shield, Download } from 'lucide-react';

interface TopNavProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  onDownloadBundle: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({ currentTab, onTabChange, onDownloadBundle }) => {
  const navItems = [
    { id: 'dashboard', label: 'Threat Overview' },
    { id: 'url-scanner', label: 'URL Scanner' },
    { id: 'email-scanner', label: 'Email Scanner' },
    { id: 'ml-eval', label: 'ML Architecture' },
    { id: 'deliverables', label: 'Academic Hub' },
    { id: 'history', label: 'Scan Audit Log' }
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#080d1a]/95 backdrop-blur-md border-b border-slate-800/80 px-6 py-3.5 flex items-center justify-between gap-8">
      {/* Zone 1: Brand Wordmark */}
      <div 
        onClick={() => onTabChange('dashboard')} 
        className="flex items-center gap-2.5 cursor-pointer whitespace-nowrap shrink-0 group"
      >
        <div className="w-8 h-8 rounded-lg bg-teal-500/10 border border-teal-500/30 flex items-center justify-center text-teal-400 group-hover:border-teal-400 transition-colors">
          <Shield className="w-4 h-4 text-teal-400" />
        </div>
        <span className="text-lg font-bold tracking-tight text-white font-sans">
          CyberShield <span className="text-teal-400 font-mono text-sm tracking-normal">AI</span>
        </span>
      </div>

      {/* Zone 2: Single-line Nav Links */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-400">
        {navItems.map(item => (
          <button
            key={item.id}
            onClick={() => onTabChange(item.id)}
            className={`whitespace-nowrap shrink-0 transition-colors py-1 cursor-pointer ${
              currentTab === item.id
                ? 'text-teal-400 font-semibold border-b-2 border-teal-400 -mb-[15px]'
                : 'hover:text-slate-200'
            }`}
          >
            {item.label}
          </button>
        ))}
      </nav>

      {/* Zone 3: Primary Action Button */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onDownloadBundle}
          className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg shadow-sm transition-all whitespace-nowrap shrink-0 cursor-pointer"
          title="Download complete submission zip archive"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Package (.ZIP)</span>
        </button>
      </div>
    </header>
  );
};
