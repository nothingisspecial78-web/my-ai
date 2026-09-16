'use client';

import { useState, useEffect } from 'react';
import {
  FileSpreadsheet,
  CheckCircle2,
  AlertCircle,
  Loader2,
  RefreshCw,
  Unlink,
  ShieldCheck,
} from 'lucide-react';
import type { GoogleSheetsStatusResponse } from '@/lib/integrations/google-sheets/types';

export function IntegrationsSettingsTab() {
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<GoogleSheetsStatusResponse | null>(null);
  const [spreadsheetId, setSpreadsheetId] = useState('');
  const [sheetName, setSheetName] = useState('Security Telemetry');
  const [isSaving, setIsSaving] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/integrations/google-sheets/status');
      if (res.ok) {
        const data: GoogleSheetsStatusResponse = await res.json();
        setStatus(data);
        if (data.spreadsheetId) setSpreadsheetId(data.spreadsheetId);
        if (data.sheetName) setSheetName(data.sheetName);
      }
    } catch {
      // Non-critical
    }
  };

  useEffect(() => {
    let active = true;
    const fetchInitialStatus = async () => {
      try {
        const res = await fetch('/api/integrations/google-sheets/status');
        if (active && res.ok) {
          const data: GoogleSheetsStatusResponse = await res.json();
          setStatus(data);
          if (data.spreadsheetId) setSpreadsheetId(data.spreadsheetId);
          if (data.sheetName) setSheetName(data.sheetName);
        }
      } catch {
        // Non-critical
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };
    fetchInitialStatus();
    return () => {
      active = false;
    };
  }, []);

  const handleConnect = async () => {
    try {
      const res = await fetch('/api/integrations/google-sheets/auth');
      if (res.ok) {
        const data = await res.json();
        if (data.url) {
          window.location.href = data.url;
        }
      } else {
        alert('Failed to initiate Google authorization.');
      }
    } catch {
      alert('Error connecting to Google.');
    }
  };

  const handleSaveSettings = async () => {
    if (!spreadsheetId.trim()) return;
    try {
      setIsSaving(true);
      setSaveSuccess(false);
      const res = await fetch('/api/integrations/google-sheets/sheets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spreadsheetId: spreadsheetId.trim(),
          sheetName: sheetName.trim() || 'Security Telemetry',
        }),
      });
      if (res.ok) {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 2500);
        fetchStatus();
      }
    } catch {
      alert('Failed to save spreadsheet settings.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestConnection = async () => {
    if (!spreadsheetId.trim()) {
      setTestResult({ success: false, message: 'Please enter a Spreadsheet ID first.' });
      return;
    }
    try {
      setIsTesting(true);
      setTestResult(null);
      const res = await fetch('/api/integrations/google-sheets/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spreadsheetId: spreadsheetId.trim(),
          sheetName: sheetName.trim() || 'Security Telemetry',
        }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setTestResult({
          success: true,
          message: 'Connected successfully to "' + (data.spreadsheetTitle || 'Spreadsheet') + '". Test row appended.',
        });
        fetchStatus();
      } else {
        setTestResult({
          success: false,
          message: data.error || 'Connection test failed. Check permissions and ID.',
        });
      }
    } catch (e: unknown) {
      setTestResult({
        success: false,
        message: e instanceof Error ? e.message : 'Network error testing connection.',
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!confirm('Disconnect Google Sheets? Real-time security exports will be disabled.')) return;
    try {
      setIsDisconnecting(true);
      const res = await fetch('/api/integrations/google-sheets/disconnect', { method: 'POST' });
      if (res.ok) {
        setTestResult(null);
        fetchStatus();
      }
    } catch {
      alert('Failed to disconnect Google Sheets.');
    } finally {
      setIsDisconnecting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-8 space-y-3 text-slate-400">
        <Loader2 className="animate-spin text-cyan-500" size={24} />
        <span className="text-xs font-mono">Loading integrations...</span>
      </div>
    );
  }

  const isConnected = status?.connected === true;
  const isRevokedOrError = status?.status === 'revoked' || status?.status === 'error';

  return (
    <div role="tabpanel" id="panel-integrations" aria-labelledby="tab-integrations" className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
      <div>
        <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center gap-2">
          <span>Integrations</span>
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Export privacy-filtered security analysis telemetry directly to your external systems.
        </p>
      </div>

      {/* Integration Card: Google Sheets */}
      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-950/50 p-5 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/60">
              <FileSpreadsheet size={20} />
            </div>
            <div>
              <div className="font-semibold text-sm text-gray-900 dark:text-white flex items-center gap-2">
                <span>Google Sheets</span>
                {isConnected && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    Connected
                  </span>
                )}
                {isRevokedOrError && (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30">
                    {status?.status === 'revoked' ? 'Revoked' : 'Connection Error'}
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                Automatically append sanitized analysis records to your spreadsheet.
              </p>
            </div>
          </div>

          {!isConnected ? (
            <button
              type="button"
              onClick={handleConnect}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 shrink-0 shadow-xs"
            >
              <span>Connect</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={handleDisconnect}
              disabled={isDisconnecting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 border border-red-200 dark:border-red-900/50 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 shrink-0"
            >
              {isDisconnecting ? <Loader2 size={13} className="animate-spin" /> : <Unlink size={13} />}
              <span>Disconnect</span>
            </button>
          )}
        </div>

        {/* Privacy Disclosure Banner */}
        <div className="flex items-start gap-2 p-3 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400">
          <ShieldCheck size={16} className="shrink-0 mt-0.5 text-cyan-500" />
          <p className="leading-relaxed">
            <span className="font-semibold text-slate-800 dark:text-slate-200">Privacy Guarantee:</span> Only privacy-filtered security analysis metadata is exported. Raw messages, secrets, passwords, and uploaded files are never sent.
          </p>
        </div>

        {/* Revoked Warning */}
        {status?.status === 'revoked' && (
          <div className="flex items-center justify-between gap-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-700 dark:text-amber-300">
            <div className="flex items-center gap-2">
              <AlertCircle size={15} className="shrink-0 text-amber-500" />
              <span>Google authorization was revoked or expired. Please reconnect to resume logging.</span>
            </div>
            <button
              type="button"
              onClick={handleConnect}
              className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs transition-colors shrink-0"
            >
              Reconnect
            </button>
          </div>
        )}

        {/* Config Form (Visible when Connected or configured) */}
        {isConnected && (
          <div className="pt-2 border-t border-gray-200 dark:border-gray-800 space-y-3.5">
            <div className="space-y-1">
              <label htmlFor="spreadsheetId" className="text-xs font-medium text-gray-700 dark:text-gray-300">
                Google Spreadsheet ID
              </label>
              <input
                id="spreadsheetId"
                type="text"
                value={spreadsheetId}
                onChange={(e) => setSpreadsheetId(e.target.value)}
                placeholder="e.g. 1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"
                className="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-gray-900 dark:text-white text-xs font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 transition-all"
              />
              <p className="text-[11px] text-gray-400 dark:text-gray-500">
                Found in your Google Sheet URL: docs.google.com/spreadsheets/d/<strong>[SPREADSHEET_ID]</strong>/edit
              </p>
            </div>

            <div className="space-y-1">
              <label htmlFor="sheetName" className="text-xs font-medium text-gray-700 dark:text-gray-300">
                Worksheet Name (Tab)
              </label>
              <input
                id="sheetName"
                type="text"
                value={sheetName}
                onChange={(e) => setSheetName(e.target.value)}
                placeholder="Security Telemetry"
                className="w-full bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-gray-900 dark:text-white text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500/30 focus:border-cyan-500 transition-all"
              />
            </div>

            {/* Test Connection Output */}
            {testResult && (
              <div
                className={'flex items-start gap-2 p-3 rounded-lg text-xs leading-relaxed ' + (
                  testResult.success
                    ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300'
                    : 'bg-red-500/10 border border-red-500/30 text-red-700 dark:text-red-300'
                )}
              >
                {testResult.success ? (
                  <CheckCircle2 size={15} className="shrink-0 mt-0.5 text-emerald-500" />
                ) : (
                  <AlertCircle size={15} className="shrink-0 mt-0.5 text-red-500" />
                )}
                <span>{testResult.message}</span>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleSaveSettings}
                  disabled={isSaving || !spreadsheetId.trim()}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  {isSaving ? 'Saving...' : saveSuccess ? 'Saved!' : 'Save Sheet'}
                </button>
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={isTesting || !spreadsheetId.trim()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-gray-200 dark:border-gray-800 hover:bg-gray-100 dark:hover:bg-gray-900 text-gray-700 dark:text-gray-300 transition-colors disabled:opacity-50"
                >
                  {isTesting ? <Loader2 size={13} className="animate-spin text-cyan-500" /> : <RefreshCw size={13} />}
                  <span>Test Connection</span>
                </button>
              </div>

              {status?.lastSyncedAt && (
                <div className="text-[11px] font-mono text-gray-400 dark:text-gray-500">
                  Last synced: {new Date(status.lastSyncedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
