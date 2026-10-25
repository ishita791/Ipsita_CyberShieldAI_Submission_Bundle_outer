/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { TopNav } from './components/TopNav';
import { DashboardView } from './components/DashboardView';
import { UrlScannerView } from './components/UrlScannerView';
import { EmailScannerView } from './components/EmailScannerView';
import { MlExplorerView } from './components/MlExplorerView';
import { DeliverablesHubView } from './components/DeliverablesHubView';
import { HistoryView } from './components/HistoryView';
import { ScanHistoryRecord } from './types/cyber';

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');

  // Pre-seed with realistic baseline history so charts and metrics display immediately on load
  const [history, setHistory] = useState<ScanHistoryRecord[]>(() => {
    const saved = localStorage.getItem('cybershield_history');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // Fallback to initial seeds
      }
    }
    return [
      {
        id: 'seed-1',
        timestamp: '10:14:22 AM',
        type: 'URL',
        target: 'http://user@192.168.1.100/paypal/login.php?cmd=verify',
        score: 95.0,
        tier: 'Critical Risk',
        ml_verdict: 'Phishing',
        ml_confidence: '99.8%'
      },
      {
        id: 'seed-2',
        timestamp: '10:15:05 AM',
        type: 'URL',
        target: 'https://www.cisa.gov/resources-tools/cybersecurity-alerts',
        score: 0.0,
        tier: 'Low Risk',
        ml_verdict: 'Legitimate',
        ml_confidence: '98.7%'
      },
      {
        id: 'seed-3',
        timestamp: '10:16:40 AM',
        type: 'Email/Message',
        target: 'URGENT: Your account will be suspended within 24 hours...',
        score: 95.0,
        tier: 'Critical Risk',
        ml_verdict: 'Social Eng NLP',
        ml_confidence: '3 signals'
      },
      {
        id: 'seed-4',
        timestamp: '10:18:12 AM',
        type: 'URL',
        target: 'https://bit.ly/secure-banking-verification-notice',
        score: 45.0,
        tier: 'Medium Risk',
        ml_verdict: 'Phishing',
        ml_confidence: '78.4%'
      }
    ];
  });

  useEffect(() => {
    localStorage.setItem('cybershield_history', JSON.stringify(history));
  }, [history]);

  const handleScanLogged = (record: ScanHistoryRecord) => {
    setHistory(prev => [record, ...prev]);
  };

  const handleClearHistory = () => {
    setHistory([]);
    localStorage.removeItem('cybershield_history');
  };

  const handleDownloadBundle = () => {
    const link = document.createElement('a');
    link.href = '/CyberShieldAI_Submission_Bundle.zip';
    link.download = 'CyberShieldAI_Submission_Bundle.zip';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex flex-col font-sans selection:bg-teal-500/30 selection:text-teal-200">
      {/* Top Bar Navigation */}
      <TopNav
        currentTab={currentTab}
        onTabChange={(tab) => setCurrentTab(tab)}
        onDownloadBundle={handleDownloadBundle}
      />

      {/* Main View Area */}
      <main className="flex-1 pb-16">
        {currentTab === 'dashboard' && (
          <DashboardView
            history={history}
            onNavigate={(tab) => setCurrentTab(tab)}
          />
        )}

        {currentTab === 'url-scanner' && (
          <UrlScannerView
            onScanLogged={handleScanLogged}
          />
        )}

        {currentTab === 'email-scanner' && (
          <EmailScannerView
            onScanLogged={handleScanLogged}
          />
        )}

        {currentTab === 'ml-eval' && (
          <MlExplorerView />
        )}

        {currentTab === 'deliverables' && (
          <DeliverablesHubView />
        )}

        {currentTab === 'history' && (
          <HistoryView
            history={history}
            onClearHistory={handleClearHistory}
          />
        )}
      </main>

      {/* Quiet Academic & Portfolio Footer */}
      <footer className="border-t border-slate-800/80 py-6 px-6 text-center text-xs text-slate-500">
        <div className="flex flex-wrap items-center justify-center gap-2">
          <span>CyberShield AI · Academic Cybersecurity & Portfolio Project</span>
          <span aria-hidden="true">·</span>
          <span>Author: Ipsita</span>
          <span aria-hidden="true">·</span>
          <span>Defensive Offline Analysis Mode</span>
        </div>
      </footer>
    </div>
  );
}
