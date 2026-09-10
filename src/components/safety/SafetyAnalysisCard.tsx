'use client';

import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  AlertOctagon, 
  CheckCircle2, 
  Info,
  Globe,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { SafetyReport, RiskLevel } from '@/lib/safety/types';
import { cn } from '@/lib/utils';

interface SafetyAnalysisCardProps {
  report: SafetyReport;
  className?: string;
}

export function SafetyAnalysisCard({ report, className }: SafetyAnalysisCardProps) {
  const [isExpanded, setIsExpanded] = React.useState(true);

  if (!report) return null;

  const { riskLevel, confidenceLevel, score, findings, recommendations, limitations, summary, evidence = [] } = report;

  const getRiskConfig = (level: RiskLevel) => {
    switch (level) {
      case 'critical':
        return {
          label: 'CRITICAL RISK',
          icon: AlertOctagon,
          cardBorder: 'border-red-500/40 dark:border-red-500/50',
          bgHeader: 'bg-red-500/10 text-red-700 dark:text-red-300',
          badge: 'bg-red-600 text-white',
          desc: 'High probability of malicious intent, credential theft, or severe hazard.',
        };
      case 'high':
        return {
          label: 'HIGH RISK',
          icon: ShieldAlert,
          cardBorder: 'border-rose-500/40 dark:border-rose-500/50',
          bgHeader: 'bg-rose-500/10 text-rose-700 dark:text-rose-300',
          badge: 'bg-rose-600 text-white',
          desc: 'Strong deceptive patterns or phishing indicators detected.',
        };
      case 'medium':
        return {
          label: 'MEDIUM RISK',
          icon: AlertTriangle,
          cardBorder: 'border-amber-500/40 dark:border-amber-500/50',
          bgHeader: 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
          badge: 'bg-amber-600 text-white',
          desc: 'Elevated caution warranted. Contains suspicious characteristics.',
        };
      case 'low':
      default:
        return {
          label: 'LOW RISK',
          icon: ShieldCheck,
          cardBorder: 'border-emerald-500/40 dark:border-emerald-500/50',
          bgHeader: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
          badge: 'bg-emerald-600 text-white',
          desc: 'No immediate suspicious threat patterns identified.',
        };
    }
  };

  const config = getRiskConfig(riskLevel);
  const RiskIcon = config.icon;

  return (
    <div
      className={cn(
        'my-3 overflow-hidden rounded-xl border bg-card text-card-foreground shadow-sm transition-all',
        config.cardBorder,
        className
      )}
      role="region"
      aria-label={`Safety Checkup Result: ${config.label}`}
    >
      {/* Header bar */}
      <div className={cn('flex items-center justify-between px-4 py-3 border-b', config.bgHeader)}>
        <div className="flex items-center gap-2.5">
          <RiskIcon className="h-5 w-5 shrink-0" aria-hidden="true" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-wider uppercase">Safety Checkup</span>
              <span className={cn('text-[11px] font-semibold px-2 py-0.5 rounded-full', config.badge)}>
                {config.label}
              </span>
            </div>
            <p className="text-xs opacity-90 mt-0.5">{config.desc}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex flex-col items-end text-right text-[11px] opacity-80">
            <span>Confidence: <strong className="capitalize">{confidenceLevel}</strong></span>
            {typeof score === 'number' && (
              <span>Heuristic score: <strong>{score}/100</strong></span>
            )}
          </div>
          <button
            type="button"
            onClick={() => setIsExpanded(prev => !prev)}
            className="p-1 rounded-md hover:bg-black/5 dark:hover:bg-white/10 transition-colors text-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={isExpanded ? 'Collapse analysis details' : 'Expand analysis details'}
          >
            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Expandable details */}
      {isExpanded && (
        <div className="p-4 space-y-4 text-sm bg-background/60">
          {/* Summary */}
          {summary && (
            <p className="text-xs text-muted-foreground leading-relaxed">
              {summary}
            </p>
          )}

          {/* Detected Indicators */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
              Detected Indicators ({findings.length})
            </h4>
            {findings.length > 0 ? (
              <ul className="space-y-1.5 list-none pl-0">
                {findings.map((f, i) => (
                  <li
                    key={i}
                    className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs flex flex-col gap-1"
                  >
                    <div className="flex items-center justify-between font-semibold text-foreground">
                      <span>{f.title}</span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-background border border-border text-muted-foreground">
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-muted-foreground leading-normal">{f.description}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground italic pl-1">
                No suspicious indicators were triggered by lexical analysis.
              </p>
            )}
          </div>

          {/* External Threat Intelligence Evidence */}
          {(() => {
            const repEvidence = (evidence || []).filter(e => e.sourceType === 'reputation_provider');
            if (repEvidence.length === 0) return null;
            return (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                  Reputation Telemetry ({repEvidence.length})
                </h4>
                <ul className="space-y-1.5 list-none pl-0">
                  {repEvidence.map((ev, i) => (
                    <li
                      key={i}
                      className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs flex flex-col gap-1"
                    >
                      <div className="flex items-center justify-between font-semibold text-foreground">
                        <span>{ev.label || ev.sourceName}</span>
                      </div>
                      <p className="text-muted-foreground leading-normal">{ev.description}</p>
                      {ev.snippet && (
                        <span className="font-mono text-[10px] text-muted-foreground/80 bg-background/80 px-2 py-1 rounded border border-border/40">
                          {ev.snippet}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })()}

          {/* Recommended Actions */}
          {recommendations.length > 0 && (
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                Recommended Actions
              </h4>
              <ul className="space-y-1.5 list-none pl-0">
                {recommendations.map((r, i) => (
                  <li
                    key={i}
                    className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs"
                  >
                    <div className="font-semibold text-foreground flex items-center gap-1.5">
                      <span>{r.title}</span>
                    </div>
                    <p className="text-muted-foreground mt-0.5 leading-normal">{r.description}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Limitations Notice */}
          {limitations.length > 0 && (
            <div className="rounded-lg bg-muted/20 border border-border/40 p-2.5 text-[11px] text-muted-foreground space-y-1">
              <div className="font-semibold flex items-center gap-1 text-foreground/80">
                <Info className="h-3 w-3" aria-hidden="true" />
                <span>Scope & Analysis Boundaries</span>
              </div>
              <ul className="list-disc pl-4 space-y-0.5">
                {limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
