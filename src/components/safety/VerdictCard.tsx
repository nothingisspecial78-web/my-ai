'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  Lock,
  Layers,
  Sparkles,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  RiskLevel,
  ConfidenceLevel,
  FindingSeverity,
  SafetyReport,
} from '@/lib/safety/types';
import type {
  UnifiedSecurityReport,
  ConsolidatedFinding,
  UnifiedEvidence,
} from '@/lib/safety/unified/types';

export interface VerdictEvidenceItem {
  tag: string; // e.g. 'URGENCY', 'CREDENTIAL REQUEST', 'LINK', 'REPUTATION', 'CODE INJECTION', 'QR PAYLOAD', 'EXIF TAMPERING'
  label: string;
  description?: string;
  severity?: FindingSeverity;
  source?: string;
}

export interface VerdictCardData {
  riskLevel: RiskLevel;
  confidenceLevel: ConfidenceLevel;
  score?: number;
  verdict?: string;
  evidenceItems?: VerdictEvidenceItem[];
  recommendations?: Array<{
    action: string;
    title: string;
    description?: string;
    priority?: string;
  }>;
  limitations?: string[];
  privacyGuarantees?: string[];
  status?: 'completed' | 'partial' | 'failed' | 'scanning';
  targetEntity?: string;
  scannerStep?: string;
}

export interface VerdictCardProps {
  report?: SafetyReport | UnifiedSecurityReport;
  data?: VerdictCardData;
  className?: string;
  initiallyExpanded?: boolean;
  onActionClick?: (action: string) => void;
}

/**
 * Maps raw finding or evidence into a clean, capitalized signal tag.
 */
function deriveSignalTag(type: string, category?: string): string {
  const norm = (category || type).toLowerCase();
  if (norm.includes('urgency') || norm.includes('threat_coercion')) return 'URGENCY';
  if (norm.includes('credential') || norm.includes('otp') || norm.includes('password')) return 'CREDENTIAL REQUEST';
  if (norm.includes('lookalike') || norm.includes('typo') || norm.includes('brand')) return 'LINK MISMATCH';
  if (norm.includes('reputation') || norm.includes('safebrowsing') || norm.includes('urlhaus') || norm.includes('blocklist')) return 'REPUTATION';
  if (norm.includes('qr') || norm.includes('quishing')) return 'QR PAYLOAD';
  if (norm.includes('sql') || norm.includes('injection') || norm.includes('eval') || norm.includes('command')) return 'CODE INJECTION';
  if (norm.includes('secret') || norm.includes('api_key') || norm.includes('token') || norm.includes('private_key')) return 'EXPOSED SECRET';
  if (norm.includes('manipulation') || norm.includes('ai_generated') || norm.includes('exif') || norm.includes('authenticity')) return 'AUTHENTICITY CUE';
  if (norm.includes('financial') || norm.includes('payment') || norm.includes('prize')) return 'FINANCIAL DECEPTION';
  if (norm.includes('fake_banking') || norm.includes('fake_courier') || norm.includes('screenshot')) return 'VISUAL SPOOFING';
  if (norm.includes('private_network') || norm.includes('internal')) return 'NETWORK BOUNDARY';
  return 'THREAT SIGNAL';
}

/**
 * Extracts clean VerdictCardData from a SafetyReport or UnifiedSecurityReport.
 */
export function extractVerdictData(report: SafetyReport | UnifiedSecurityReport): VerdictCardData {
  const isUnified = 'domainsInvolved' in report || 'primaryConcern' in report;
  const unified = isUnified ? (report as UnifiedSecurityReport) : null;

  // Plain-language verdict sentence
  let verdict = '';
  if (unified?.primaryConcern) {
    verdict = unified.primaryConcern;
  } else if (report.summary) {
    verdict = report.summary;
  } else if (report.riskLevel === 'critical') {
    verdict = 'Critical security threats identified. Interaction poses severe risk to credentials or system integrity.';
  } else if (report.riskLevel === 'high') {
    verdict = 'High security risk detected. Indicators align closely with active deception or compromise vectors.';
  } else if (report.riskLevel === 'medium') {
    verdict = 'This message shows several characteristics commonly associated with phishing attempts.';
  } else if (report.riskLevel === 'low') {
    verdict = 'No significant security threats or deceptive indicators detected in the analyzed submission.';
  } else {
    verdict = 'Analysis inconclusive from available data. Exercise standard digital caution.';
  }

  // Derive evidence items with signal tags
  const evidenceItems: VerdictEvidenceItem[] = [];
  const findings = (report.findings || []) as ConsolidatedFinding[];

  for (const f of findings) {
    const tag = deriveSignalTag(f.type, f.metadata?.category as string | undefined);
    evidenceItems.push({
      tag,
      label: f.title,
      description: f.description,
      severity: f.severity,
      source: (f as ConsolidatedFinding).targetEntity || (f.metadata?.sourceContext as string | undefined),
    });
  }

  // Fallback to raw evidence if findings are sparse
  if (evidenceItems.length === 0 && report.evidence && report.evidence.length > 0) {
    for (const e of report.evidence.slice(0, 5)) {
      const uEv = e as UnifiedEvidence;
      evidenceItems.push({
        tag: deriveSignalTag(uEv.category || uEv.sourceType || 'evidence'),
        label: e.label || e.description,
        description: e.description !== e.label ? e.description : undefined,
        severity: uEv.severity || 'low',
        source: uEv.source?.attachmentName || uEv.sourceType,
      });
    }
  }

  return {
    riskLevel: report.riskLevel,
    confidenceLevel: report.confidenceLevel,
    score: report.score,
    verdict,
    evidenceItems,
    recommendations: (report.recommendations || []).map(r => ({
      action: r.action,
      title: r.title,
      description: r.description,
      priority: r.priority,
    })),
    limitations: report.limitations || [],
    privacyGuarantees: unified?.privacyGuarantees || [],
    status: (report.status as 'completed' | 'partial' | 'failed') || 'completed',
    targetEntity: unified?.affectedEntities?.[0],
  };
}

export function VerdictCard({
  report,
  data: explicitData,
  className,
  initiallyExpanded = false,
  onActionClick,
}: VerdictCardProps) {
  const data = explicitData || (report ? extractVerdictData(report) : null);
  const [evidenceExpanded, setEvidenceExpanded] = useState(initiallyExpanded);
  const [technicalExpanded, setTechnicalExpanded] = useState(false);
  const [copiedAction, setCopiedAction] = useState<string | null>(null);

  if (!data) return null;

  const {
    riskLevel,
    confidenceLevel,
    score,
    verdict,
    evidenceItems = [],
    recommendations = [],
    limitations = [],
    privacyGuarantees = [],
    status = 'completed',
    targetEntity,
    scannerStep,
  } = data;

  const isScanning = status === 'scanning';

  // Strict Risk Styling (Red / Amber / Green reserved strictly for risk)
  const riskBadgeStyles: Record<RiskLevel, { bg: string; text: string; border: string; label: string; icon: typeof Shield }> = {
    critical: {
      bg: 'bg-red-500/15 dark:bg-red-950/40',
      text: 'text-red-700 dark:text-red-400',
      border: 'border-red-500/30 dark:border-red-500/40',
      label: 'CRITICAL RISK',
      icon: ShieldAlert,
    },
    high: {
      bg: 'bg-red-500/10 dark:bg-red-950/30',
      text: 'text-red-600 dark:text-red-400',
      border: 'border-red-400/30 dark:border-red-600/30',
      label: 'HIGH RISK',
      icon: ShieldAlert,
    },
    medium: {
      bg: 'bg-amber-500/15 dark:bg-amber-950/40',
      text: 'text-amber-700 dark:text-amber-400',
      border: 'border-amber-500/30 dark:border-amber-500/40',
      label: 'MEDIUM RISK',
      icon: AlertTriangle,
    },
    low: {
      bg: 'bg-emerald-500/15 dark:bg-emerald-950/40',
      text: 'text-emerald-700 dark:text-emerald-400',
      border: 'border-emerald-500/30 dark:border-emerald-500/40',
      label: 'LOW RISK',
      icon: ShieldCheck,
    },
    unknown: {
      bg: 'bg-slate-500/15 dark:bg-slate-800/40',
      text: 'text-slate-700 dark:text-slate-300',
      border: 'border-slate-400/30 dark:border-slate-600/30',
      label: 'UNKNOWN RISK',
      icon: Info,
    },
  };

  const currentRisk = riskBadgeStyles[riskLevel] || riskBadgeStyles.unknown;
  const RiskIcon = currentRisk.icon;

  // Independent Confidence Styling (Neutral Instrument / Tech Meter, Never Red/Green)
  const confidenceLabels: Record<ConfidenceLevel, { label: string; dots: number; desc: string }> = {
    high: { label: 'HIGH CONFIDENCE', dots: 3, desc: 'Multiple authoritative signals correlated' },
    medium: { label: 'MEDIUM CONFIDENCE', dots: 2, desc: 'Signals present; secondary heuristics applied' },
    low: { label: 'LOW CONFIDENCE', dots: 1, desc: 'Limited observation context; unverified' },
  };
  const currentConfidence = confidenceLabels[confidenceLevel] || confidenceLabels.medium;

  const handleCopyVerdict = () => {
    if (typeof navigator !== 'undefined' && verdict) {
      navigator.clipboard.writeText(verdict);
      setCopiedAction('verdict');
      setTimeout(() => setCopiedAction(null), 2000);
    }
  };

  return (
    <div
      data-testid="verdict-card"
      data-risk={riskLevel}
      data-confidence={confidenceLevel}
      className={cn(
        'w-full rounded-2xl border transition-all duration-200 overflow-hidden font-sans shadow-sm',
        'bg-white dark:bg-slate-950',
        riskLevel === 'critical' || riskLevel === 'high'
          ? 'border-red-200 dark:border-red-900/50'
          : riskLevel === 'medium'
          ? 'border-amber-200 dark:border-amber-900/50'
          : 'border-slate-200 dark:border-slate-800',
        className
      )}
    >
      {/* 1. Header Bar: Status & Target */}
      <div className="flex items-center justify-between px-5 py-2.5 bg-slate-50/80 dark:bg-slate-900/80 border-b border-slate-100 dark:border-slate-800/80 text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-2 font-mono uppercase tracking-wider font-semibold">
          {isScanning ? (
            <>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
              </span>
              <span className="text-cyan-600 dark:text-cyan-400">
                {scannerStep || 'ANALYSIS IN PROGRESS...'}
              </span>
            </>
          ) : (
            <>
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-slate-400 dark:bg-slate-500" />
              <span>BEFORE YOU CLICK — VERDICT</span>
            </>
          )}
        </div>

        {targetEntity && (
          <div className="font-mono text-[11px] text-slate-400 dark:text-slate-500 truncate max-w-[180px] sm:max-w-[280px]" title={targetEntity}>
            {targetEntity}
          </div>
        )}
      </div>

      <div className="p-5 sm:p-6 space-y-5">
        {/* 2. Dual Badge Hierarchy: Risk != Confidence */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-1 border-b border-slate-100 dark:border-slate-800/80">
          {/* Risk Level Badge */}
          <div
            data-testid="risk-badge"
            className={cn(
              'inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-xl border text-sm font-semibold tracking-wide shadow-xs',
              currentRisk.bg,
              currentRisk.text,
              currentRisk.border
            )}
          >
            <RiskIcon size={18} strokeWidth={2.2} className="shrink-0" aria-hidden="true" />
            <span>{currentRisk.label}</span>
            {typeof score === 'number' && (
              <span className="font-mono text-xs opacity-75 font-normal pl-1 border-l border-current/30">
                {score}/100
              </span>
            )}
          </div>

          {/* Confidence Level Badge (Independent Instrument Styling) */}
          <div
            data-testid="confidence-badge"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-700/80 bg-slate-100/60 dark:bg-slate-900/60 text-slate-700 dark:text-slate-300 text-xs font-mono font-medium shadow-xs"
            title={currentConfidence.desc}
          >
            <span className="text-slate-400 dark:text-slate-500 font-sans text-[11px] uppercase tracking-wider">
              CONFIDENCE
            </span>
            <span className="flex items-center gap-1">
              {[1, 2, 3].map(dot => (
                <span
                  key={dot}
                  className={cn(
                    'w-2 h-2 rounded-full transition-colors',
                    dot <= currentConfidence.dots
                      ? 'bg-cyan-600 dark:bg-cyan-400'
                      : 'bg-slate-300 dark:bg-slate-700'
                  )}
                />
              ))}
            </span>
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {currentConfidence.label.replace(' CONFIDENCE', '')}
            </span>
          </div>
        </div>

        {/* 3. Plain-Language Verdict Sentence */}
        <div className="space-y-1.5">
          <p
            data-testid="verdict-sentence"
            className="text-base sm:text-lg font-medium text-slate-900 dark:text-slate-100 leading-relaxed"
          >
            {verdict}
          </p>
          {confidenceLevel === 'low' && (
            <p className="text-xs text-slate-500 dark:text-slate-400 italic">
              Note: Low confidence indicates observational data is limited, not that the target is verified safe.
            </p>
          )}
        </div>

        {/* 4. Categorized Evidence Section with Signal Tags */}
        {evidenceItems.length > 0 && (
          <div className="space-y-3 pt-1">
            <button
              type="button"
              onClick={() => setEvidenceExpanded(prev => !prev)}
              className="flex items-center justify-between w-full text-left text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider py-1 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 rounded"
              aria-expanded={evidenceExpanded}
            >
              <span className="flex items-center gap-2">
                <span>Evidence Signals ({evidenceItems.length})</span>
              </span>
              <span className="flex items-center gap-1 text-[11px] text-slate-400 font-normal">
                {evidenceExpanded ? (
                  <>
                    <span>Hide</span> <ChevronUp size={14} />
                  </>
                ) : (
                  <>
                    <span>Review Reasons</span> <ChevronDown size={14} />
                  </>
                )}
              </span>
            </button>

            {evidenceExpanded && (
              <div
                data-testid="evidence-list"
                className="space-y-2.5 pl-1 border-l-2 border-slate-100 dark:border-slate-800 ml-1 mt-2 transition-all"
              >
                {evidenceItems.map((item, idx) => (
                  <div
                    key={idx}
                    className="pl-3 py-1 space-y-0.5 text-sm group"
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        • {item.tag}
                      </span>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">
                        {item.label}
                      </span>
                      {item.source && (
                        <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500 truncate max-w-[150px]">
                          [{item.source}]
                        </span>
                      )}
                    </div>
                    {item.description && item.description !== item.label && (
                      <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed pl-1">
                        {item.description}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 5. Recommended Actions Banner */}
        {recommendations.length > 0 && (
          <div className="pt-2 flex flex-wrap gap-2 items-center">
            {recommendations.slice(0, 2).map((rec, idx) => {
              const isDanger = rec.priority === 'high' || riskLevel === 'critical' || riskLevel === 'high';
              const content = (
                <>
                  {rec.action === 'do_not_click' || rec.action === 'quarantine' ? (
                    <XCircle size={14} className="shrink-0 text-red-500" />
                  ) : (
                    <CheckCircle2 size={14} className="shrink-0 text-cyan-500" />
                  )}
                  <span className="font-semibold">{rec.title}:</span>
                  <span className="opacity-90">{rec.description || 'Proceed with caution'}</span>
                </>
              );

              if (onActionClick) {
                return (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => onActionClick(rec.action)}
                    className={cn(
                      'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border shadow-xs text-left cursor-pointer transition-colors',
                      isDanger
                        ? 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800/60 hover:bg-red-100 dark:hover:bg-red-900/40'
                        : 'bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'
                    )}
                  >
                    {content}
                  </button>
                );
              }

              return (
                <div
                  key={idx}
                  className={cn(
                    'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border shadow-xs',
                    isDanger
                      ? 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800/60'
                      : 'bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800'
                  )}
                >
                  {content}
                </div>
              );
            })}
          </div>
        )}

        {/* 6. Technical Forensics & Limitations Toggle */}
        {(limitations.length > 0 || privacyGuarantees.length > 0) && (
          <div className="pt-1 border-t border-slate-100 dark:border-slate-800/60">
            <button
              type="button"
              onClick={() => setTechnicalExpanded(prev => !prev)}
              className="text-[11px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 flex items-center gap-1.5 focus:outline-none"
            >
              <Layers size={12} />
              <span>{technicalExpanded ? 'Hide Forensic & Privacy Disclosures' : 'View Forensic Limitations & Privacy Disclosures'}</span>
            </button>

            {technicalExpanded && (
              <div className="mt-2.5 p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/60 dark:border-slate-800/60 text-xs space-y-2">
                {privacyGuarantees.length > 0 && (
                  <div className="flex items-start gap-2 text-slate-600 dark:text-slate-300">
                    <Lock size={13} className="shrink-0 mt-0.5 text-cyan-600 dark:text-cyan-400" />
                    <span>Privacy protections applied: Redacted raw tokens, secrets, coordinates, and sensitive credentials.</span>
                  </div>
                )}
                {limitations.map((lim, i) => (
                  <div key={i} className="flex items-start gap-2 text-slate-500 dark:text-slate-400">
                    <Info size={13} className="shrink-0 mt-0.5 text-slate-400" />
                    <span>{lim}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 7. Signature Footer Note */}
        <div className="pt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 dark:text-slate-500">
          <div
            data-testid="verdict-transparency-note"
            className="flex items-center gap-1.5 italic"
          >
            <Sparkles size={12} className="shrink-0 text-cyan-500/70" />
            <span>AI helps understand. Security logic decides.</span>
          </div>

          <button
            type="button"
            onClick={handleCopyVerdict}
            className="flex items-center gap-1 hover:text-slate-600 dark:hover:text-slate-300 transition-colors p-1"
            title="Copy verdict summary"
            aria-label="Copy verdict summary"
          >
            {copiedAction === 'verdict' ? (
              <>
                <Check size={12} className="text-emerald-500" />
                <span className="text-emerald-600 dark:text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy size={12} />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
