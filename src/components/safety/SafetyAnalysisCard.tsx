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
  ChevronUp,
  Building2,
  Zap,
  Code2,
  ScanText,
  QrCode,
  Smartphone,
  Sparkles,
  EyeOff,
  FileImage,
  GitMerge,
  Layers,
  Lock,
  Loader2,
  type LucideIcon
} from 'lucide-react';
import { SafetyReport, RiskLevel, FindingSeverity } from '@/lib/safety/types';
import type { 
  UnifiedSecurityReport, 
  ConsolidatedFinding
} from '@/lib/safety/unified/types';
import { cn } from '@/lib/utils';
import { ThemeDefinition } from '@/lib/theme/types';
import { getThemePresentation } from '@/lib/theme/catalog';
import { redactSensitiveText } from '@/lib/safety/redaction';

const TACTIC_LABELS: Record<string, string> = {
  urgency: 'Artificial Urgency',
  fear_threat: 'Threat & Coercion',
  authority_pressure: 'Authority Pressure',
  credential_pressure: 'Credential / OTP Request',
  reward_temptation: 'Reward / Lottery Lure',
  scarcity: 'Artificial Scarcity',
  secrecy: 'Secrecy / Channel Bypass',
  financial_pressure: 'Upfront Payment Request',
};

const CATEGORY_LABELS: Record<string, string> = {
  fake_banking: 'Banking Fraud Alert',
  fake_courier: 'Package Delivery Lure',
  account_suspension: 'Account Suspension Warning',
  kyc_verification: 'KYC Document Solicitation',
  prize_reward: 'Prize / Lottery Lure',
  crypto_fraud: 'Crypto Recovery Key Solicitation',
  fake_customer_support: 'Fake Tech Support Prompt',
  login_credential_harvesting: 'Credential / OTP Harvesting',
  government_service_impersonation: 'Government / Legal Threat',
  social_media_warning: 'Social Media Warning Lure',
  urgent_action_required: 'Urgent Action Pressure',
  suspicious_payment_slip: 'Suspicious Payment Slip',
  general_visual_fraud: 'Visual Deception Cue',
};

const PRIVACY_TAG_LABELS: Record<string, string> = {
  redacted_api_key: 'API Key Redacted',
  redacted_auth_token: 'Bearer Token Redacted',
  redacted_password: 'Password Redacted',
  redacted_otp: 'OTP Redacted',
  redacted_wifi_credentials: 'Wi-Fi Password Redacted',
  redacted_otpauth_secret: '2FA / TOTP Secret Redacted',
  redacted_private_key: 'Private Key Redacted',
  redacted_db_uri: 'Database URI Redacted',
  redacted_url_params: 'Sensitive Query Params Redacted',
  redacted_credit_card: 'Payment Card Redacted',
  redacted_seed_phrase: 'Crypto Recovery Key Redacted',
  redacted_gps_coordinates: 'GPS Coordinates Redacted',
  redacted_device_id: 'Device ID Redacted',
};

export type FindingCategory = 'safety' | 'security' | 'authenticity' | 'privacy';

export const CATEGORY_META: Record<
  FindingCategory,
  { label: string; icon: LucideIcon; colorClass: string }
> = {
  safety: {
    label: 'Safety Finding',
    icon: ShieldAlert,
    colorClass: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
  },
  security: {
    label: 'Security Threat',
    icon: AlertOctagon,
    colorClass: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
  },
  authenticity: {
    label: 'Authenticity Observation',
    icon: Sparkles,
    colorClass: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20',
  },
  privacy: {
    label: 'Privacy Notice',
    icon: EyeOff,
    colorClass: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20',
  },
};

const SEVERITY_WEIGHT: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Classifies a finding into one of the four canonical UI categories:
 * Safety, Security, Authenticity, or Privacy.
 */
export function categorizeFinding(f: { type: string; title?: string; metadata?: Record<string, unknown> }): FindingCategory {
  const title = (f.title || '').toLowerCase();
  const signalType = (f.metadata?.signalType as string) || '';

  if (title.includes('gps') || title.includes('privacy') || signalType === 'privacy') {
    return 'privacy';
  }
  if (
    f.type === 'possible_ai_generated' ||
    f.type === 'possible_manipulation' ||
    (f.type === 'metadata_anomaly' && !title.includes('gps')) ||
    signalType === 'possible_ai_generated' ||
    signalType === 'possible_manipulation' ||
    signalType === 'metadata_anomaly'
  ) {
    return 'authenticity';
  }
  if (
    f.type === 'phishing_indicator' ||
    f.type === 'suspicious_qr' ||
    f.type === 'suspicious_code' ||
    f.type === 'exposed_secret' ||
    f.type === 'dangerous_function' ||
    f.type === 'sql_injection_pattern' ||
    f.type === 'command_injection_pattern' ||
    f.type === 'syntax_anomaly' ||
    f.type === 'suspicious_attachment' ||
    f.type === 'suspicious_domain' ||
    f.type === 'lookalike_domain' ||
    f.type === 'lookalike_brand' ||
    f.type === 'suspicious_keyword' ||
    f.type === 'host_confusion' ||
    f.type === 'private_network_host' ||
    f.type === 'excessive_subdomains' ||
    f.type === 'excessive_encoding' ||
    f.type === 'suspicious_redirect' ||
    f.type === 'insecure_protocol' ||
    f.type === 'ip_as_host' ||
    f.type === 'shortened_url' ||
    f.type === 'credential_in_url' ||
    f.type.startsWith('reputation_')
  ) {
    return 'security';
  }
  return 'safety';
}

/**
 * Enforces epistemic humility on display strings:
 * Never displays absolute claims like "This image is AI-generated", "This image is fake", or "Proven authentic".
 */
export function enforceCautiousLanguage(text: string): string {
  if (!text) return text;
  return text
    .replace(/\b(?:this\s+image\s+is|is|an)\s+definitely\s+AI(?:-generated)?\b/gi, 'has possible synthetic-image indicators')
    .replace(/\b(?:this\s+image\s+is|is)\s+AI-generated\b/gi, 'has possible synthetic-image indicators')
    .replace(/\b(?:this\s+image\s+is|is)\s+definitely\s+fake\b/gi, 'shows possible manipulation indicators')
    .replace(/\b(?:this\s+image\s+is|is)\s+definitely\s+manipulated\b/gi, 'shows possible manipulation indicators')
    .replace(/\b(?:this\s+image\s+is|is)\s+fake\b/gi, 'shows possible manipulation indicators')
    .replace(/\bconfirmed\s+AI\b/gi, 'possible synthetic media indicators')
    .replace(/\bproven\s+fake\b/gi, 'possible manipulation indicators')
    .replace(/\breal\s+image\b/gi, 'image without synthetic anomalies')
    .replace(/\bauthentic\s+image\b/gi, 'image without overt manipulation flags')
    .replace(/\bproven\s+authentic\b/gi, 'exhibits typical photographic characteristics')
    .replace(/\bdefinitely\s+human\b/gi, 'exhibits typical human photographic markers')
    .replace(/\bconfirmed\s+genuine\b/gi, 'no overt tampering detected')
    .replace(/\b100%\s+safe\b/gi, 'no immediate threats detected');
}

/**
 * Sanitizes snippets to strictly prevent leaking GPS coordinates,
 * WiFi credentials, OTPAuth secrets, or sensitive tokens.
 */
export function sanitizeSnippetSafely(snippet?: string, maxLength = 160): string | undefined {
  if (!snippet) return undefined;
  let text = redactSensitiveText(String(snippet));
  text = text.replace(/-?\d{1,3}\.\d{4,8}[,\s]+-?\d{1,3}\.\d{4,8}/g, '[COORDINATES REDACTED]');
  text = text.replace(/\b(?:GPSLatitude|GPSLongitude|GPSPosition|GPSAltitude)=[^\s,;]+/gi, '[GPS DATA REDACTED]');
  text = text.replace(/(\bWIFI:[\s\S]*?\bP:)([^;]+)(;*)/gi, '$1[REDACTED_PASSWORD]$3');
  text = text.replace(/(otpauth:\/\/[^\s?]+\?[^\s]*secret=)([^&\s]+)/gi, '$1[REDACTED_SECRET]');
  if (text.length > maxLength) {
    text = text.slice(0, maxLength) + '...';
  }
  return text;
}

function formatBytes(bytes?: number): string | null {
  if (typeof bytes !== 'number' || isNaN(bytes)) return null;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export interface SafetyAnalysisCardProps {
  report: SafetyReport | UnifiedSecurityReport;
  className?: string;
  themeSlug?: string;
  theme?: ThemeDefinition;
}

export function SafetyAnalysisCard({ report, className, themeSlug, theme }: SafetyAnalysisCardProps) {
  const [isExpanded, setIsExpanded] = React.useState(true);

  // Categorization & Counts
  const categoryCounts = React.useMemo(() => {
    const counts: Record<FindingCategory, number> = { safety: 0, security: 0, authenticity: 0, privacy: 0 };
    for (const f of report?.findings || []) {
      const cat = categorizeFinding(f);
      counts[cat]++;
    }
    return counts;
  }, [report?.findings]);

  // Priority Sorting: Most severe finding first
  const sortedFindings = React.useMemo(() => {
    return [...(report?.findings || [])].sort(
      (a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0)
    );
  }, [report?.findings]);

  if (!report) return null;

  const activeSlug = themeSlug || theme?.slug;
  const isSecurity = activeSlug === 'security-checkup';
  const presentation = theme?.presentation || getThemePresentation(activeSlug || 'safety-checkup');
  const cardTitle = presentation.cardTitle || (isSecurity ? 'Security Inspection' : 'Safety Checkup');

  const { riskLevel, confidenceLevel, score, findings = [], recommendations = [], limitations = [], summary, evidence = [] } = report;

  // Unified report properties duck-typing
  const unifiedReport = (report as Partial<UnifiedSecurityReport>);
  const primaryConcern = unifiedReport.primaryConcern;
  const correlationSummaries = unifiedReport.correlationSummaries || [];
  const analyzerSummaries = unifiedReport.analyzerSummaries || [];
  const affectedEntities = unifiedReport.affectedEntities || [];
  const privacyGuarantees = unifiedReport.privacyGuarantees || [];
  const reportStatus = report.status;

  const topFinding = sortedFindings.length > 0 ? sortedFindings[0] : null;

  const getRiskConfig = (level: RiskLevel) => {
    switch (level) {
      case 'critical':
        return {
          label: 'CRITICAL RISK',
          icon: AlertOctagon,
          cardBorder: 'border-red-500/40 dark:border-red-500/50',
          bgHeader: 'bg-red-500/10 text-red-700 dark:text-red-300',
          badge: 'bg-red-600 text-white',
          desc: isSecurity
            ? 'Critical vulnerability, active exploit, or severe security hazard.'
            : 'High probability of malicious intent, credential theft, or severe hazard.',
        };
      case 'high':
        return {
          label: 'HIGH RISK',
          icon: ShieldAlert,
          cardBorder: 'border-rose-500/40 dark:border-rose-500/50',
          bgHeader: 'bg-rose-500/10 text-rose-700 dark:text-rose-300',
          badge: 'bg-rose-600 text-white',
          desc: isSecurity
            ? 'Elevated technical threat indicators or deceptive anomalies identified.'
            : 'Strong deceptive patterns or phishing indicators detected.',
        };
      case 'medium':
        return {
          label: 'MEDIUM RISK',
          icon: AlertTriangle,
          cardBorder: 'border-amber-500/40 dark:border-amber-500/50',
          bgHeader: 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
          badge: 'bg-amber-600 text-white',
          desc: isSecurity
            ? 'Anomalous characteristics or potential vulnerabilities detected.'
            : 'Elevated caution warranted. Contains suspicious characteristics.',
        };
      case 'unknown':
        return {
          label: 'ANALYSIS INCOMPLETE',
          icon: AlertTriangle,
          cardBorder: 'border-amber-500/40 dark:border-amber-500/50',
          bgHeader: 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
          badge: 'bg-amber-600 text-white',
          desc: isSecurity
            ? 'One or more attachments could not be retrieved for inspection. Exercise caution.'
            : 'Analysis could not be completed. Exercise general caution.',
        };
      case 'low':
      default:
        return {
          label: 'LOW RISK',
          icon: ShieldCheck,
          cardBorder: 'border-emerald-500/40 dark:border-emerald-500/50',
          bgHeader: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
          badge: 'bg-emerald-600 text-white',
          desc: isSecurity
            ? 'No anomalous threat patterns or vulnerable signatures identified.'
            : 'No immediate suspicious threat patterns identified.',
        };
    }
  };

  const config = getRiskConfig(riskLevel);
  const RiskIcon = config.icon;

  // Image Intelligence Evidence Extraction (Stages 7.1 - 7.5)
  const imageFoundationEvidence = (evidence || []).find(
    e => e.sourceType === 'image_analysis' && e.data && 'format' in e.data
  );
  const ocrEvidence = (evidence || []).find(
    e => e.sourceName?.includes('Gemini Vision OCR') || (e.data && 'hasText' in e.data && 'characterCount' in e.data)
  );
  const qrEvidence = (evidence || []).find(
    e => e.sourceName?.includes('QR Intelligence') || (e.data && 'detectedCount' in e.data && 'payloadTypes' in e.data)
  );
  const visualScamEvidence = (evidence || []).find(
    e => e.sourceName?.includes('Visual Scam & Screenshot Fraud') || (e.data && 'detectedCategories' in e.data)
  );
  const authEvidence = (evidence || []).find(
    e => e.sourceName?.includes('Authenticity & Manipulation') || (e.data && ('hasSoftwareTag' in e.data || 'hasExif' in e.data))
  );

  const isImageContext = report.inputType === 'image' || Boolean(imageFoundationEvidence || ocrEvidence || qrEvidence || visualScamEvidence || authEvidence);

  return (
    <div
      className={cn(
        'my-3 overflow-hidden rounded-xl border bg-card text-card-foreground shadow-sm transition-all',
        config.cardBorder,
        className
      )}
      role="region"
      aria-label={`${cardTitle} Result: ${config.label}`}
    >
      {/* Header bar */}
      <div className={cn('flex items-center justify-between px-4 py-3 border-b', config.bgHeader)}>
        <div className="flex items-center gap-2.5">
          <RiskIcon className="h-5 w-5 shrink-0" aria-hidden="true" />
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold tracking-wider uppercase">{cardTitle}</span>
              <span className={cn('text-[11px] font-semibold px-2 py-0.5 rounded-full', config.badge)}>
                {config.label}
              </span>
              {/* Mobile-friendly Confidence Tag */}
              <span className="sm:hidden text-[10px] font-medium px-2 py-0.5 rounded-full bg-background/80 border border-border/40 text-foreground">
                Confidence: <strong className="capitalize">{confidenceLevel}</strong>
              </span>
            </div>
            <p className="text-xs opacity-90 mt-0.5">{config.desc}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex flex-col items-end text-right text-[11px] opacity-80">
            <span>Confidence: <strong className="capitalize">{confidenceLevel}</strong></span>
            {typeof score === 'number' && (
              <span>{isSecurity ? 'Deterministic score:' : 'Heuristic score:'} <strong>{`${score}/100`}</strong></span>
            )}
          </div>
          <button
            type="button"
            onClick={() => setIsExpanded(prev => !prev)}
            aria-expanded={isExpanded}
            aria-controls="safety-analysis-details"
            className="flex h-9 w-9 sm:h-8 sm:w-8 items-center justify-center rounded-md hover:bg-black/5 dark:hover:bg-white/10 transition-colors text-muted-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={isExpanded ? 'Collapse analysis details' : 'Expand analysis details'}
          >
            {isExpanded ? <ChevronUp className="h-4 w-4" aria-hidden="true" /> : <ChevronDown className="h-4 w-4" aria-hidden="true" />}
          </button>
        </div>
      </div>

      {/* Expandable details */}
      {isExpanded && (
        <div id="safety-analysis-details" className="p-4 space-y-4 text-sm bg-background/60">
          {/* Live Analysis in Progress Banner */}
          {reportStatus === 'analyzing' && (
            <div className="rounded-lg border border-blue-500/40 bg-blue-500/10 p-3 text-xs flex items-center gap-2.5">
              <Loader2 className="h-4 w-4 text-blue-600 dark:text-blue-400 animate-spin shrink-0" aria-hidden="true" />
              <div>
                <span className="font-bold text-blue-800 dark:text-blue-300 block">Analysis in Progress</span>
                <p className="text-blue-700 dark:text-blue-400 mt-0.5 leading-normal">
                  Evaluating security signals across multi-domain intelligence analyzers...
                </p>
              </div>
            </div>
          )}

          {/* Partial Analysis Banner */}
          {(reportStatus as string) === 'partial' && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <span className="font-bold text-amber-800 dark:text-amber-300 block">Partial Analysis Completed</span>
                <p className="text-amber-700 dark:text-amber-400 mt-0.5 leading-normal">
                  One or more security analyzers could not complete inspection. Available verified findings are presented below.
                </p>
              </div>
            </div>
          )}

          {/* Incomplete or Limited Analysis Notice */}
          {(riskLevel === 'unknown' || reportStatus === 'failed') && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <span className="font-bold text-amber-800 dark:text-amber-300 block">Analysis Incomplete</span>
                <p className="text-amber-700 dark:text-amber-400 mt-0.5 leading-normal">
                  {summary || 'One or more analysis modules could not be completed. Exercise caution with unverified attachments and links.'}
                </p>
              </div>
            </div>
          )}

          {/* Top Priority Finding / Primary Concern Callout */}
          {topFinding && (topFinding.severity === 'critical' || topFinding.severity === 'high' || topFinding.severity === 'medium') ? (
            <div className={cn(
              'rounded-xl border p-3.5 flex flex-col gap-2 transition-all',
              topFinding.severity === 'critical'
                ? 'border-red-500/40 bg-red-500/5 dark:bg-red-950/20'
                : topFinding.severity === 'high'
                ? 'border-rose-500/40 bg-rose-500/5 dark:bg-rose-950/20'
                : 'border-amber-500/40 bg-amber-500/5 dark:bg-amber-950/20'
            )}>
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-background border border-border text-foreground">
                    Primary Concern
                  </span>
                  <span className={cn('text-[10px] font-semibold px-2 py-0.5 rounded-full border', CATEGORY_META[categorizeFinding(topFinding)].colorClass)}>
                    {CATEGORY_META[categorizeFinding(topFinding)].label}
                  </span>
                </div>
                <span className={cn(
                  'text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded-full text-white',
                  topFinding.severity === 'critical' ? 'bg-red-600' : topFinding.severity === 'high' ? 'bg-rose-600' : 'bg-amber-600'
                )}>
                  {topFinding.severity}
                </span>
              </div>
              <div>
                <h5 className="font-semibold text-foreground text-xs break-words [overflow-wrap:anywhere]">
                  {enforceCautiousLanguage(primaryConcern || topFinding.title)}
                </h5>
                <p className="text-muted-foreground text-xs mt-0.5 leading-normal break-words [overflow-wrap:anywhere]">
                  {enforceCautiousLanguage(topFinding.description)}
                </p>
              </div>

              {/* Immediate Action Callout for High/Critical Risk */}
              {(riskLevel === 'critical' || riskLevel === 'high' || topFinding.severity === 'critical' || topFinding.severity === 'high') && (
                <div className="flex items-center gap-2 rounded-lg bg-red-500/10 border border-red-500/20 p-2 text-xs text-red-700 dark:text-red-300 font-medium">
                  <AlertOctagon className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400" aria-hidden="true" />
                  <span>
                    <strong>Immediate Action:</strong> Do not interact with unverified links, submit sensitive credentials, or execute untrusted code.
                  </span>
                </div>
              )}

              {(() => {
                const rawSnippet = typeof topFinding.metadata?.snippet === 'string'
                  ? topFinding.metadata.snippet
                  : typeof topFinding.metadata?.redactedSnippet === 'string'
                  ? topFinding.metadata.redactedSnippet
                  : typeof topFinding.metadata?.evidenceSnippet === 'string'
                  ? topFinding.metadata.evidenceSnippet
                  : undefined;
                const sanitized = sanitizeSnippetSafely(rawSnippet);
                if (!sanitized) return null;
                return (
                  <div className="mt-0.5 font-mono text-[11px] bg-background/90 text-foreground/90 px-2.5 py-1.5 rounded border border-border/60 overflow-x-auto whitespace-pre">
                    <code>{sanitized.length > 160 ? sanitized.slice(0, 160) + '...' : sanitized}</code>
                  </div>
                );
              })()}
            </div>
          ) : primaryConcern && (riskLevel === 'critical' || riskLevel === 'high' || riskLevel === 'medium') ? (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-3.5 flex flex-col gap-2">
              <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-background border border-border text-foreground w-fit">
                Primary Concern
              </span>
              <p className="text-foreground text-xs font-semibold">
                {enforceCautiousLanguage(primaryConcern)}
              </p>
            </div>
          ) : null}

          {/* Indicators Category Breakdown Badges */}
          {findings.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
              <span className="font-semibold text-muted-foreground text-xs mr-1">Signal Breakdown:</span>
              {categoryCounts.safety > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 font-medium">
                  <ShieldAlert className="h-3 w-3" aria-hidden="true" />
                  {`Safety: ${categoryCounts.safety}`}
                </span>
              )}
              {categoryCounts.security > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 font-medium">
                  <AlertOctagon className="h-3 w-3" aria-hidden="true" />
                  {`Security: ${categoryCounts.security}`}
                </span>
              )}
              {categoryCounts.authenticity > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20 font-medium">
                  <Sparkles className="h-3 w-3" aria-hidden="true" />
                  {`Authenticity: ${categoryCounts.authenticity}`}
                </span>
              )}
              {categoryCounts.privacy > 0 && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 font-medium">
                  <EyeOff className="h-3 w-3" aria-hidden="true" />
                  {`Privacy: ${categoryCounts.privacy}`}
                </span>
              )}
            </div>
          )}

          {/* Affected Target Entities (Unified Intelligence) */}
          {affectedEntities.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap text-xs rounded-lg border border-border/60 bg-muted/20 p-2">
              <span className="font-semibold text-muted-foreground shrink-0">Affected Targets:</span>
              {affectedEntities.map((ent, idx) => (
                <span key={idx} className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-background border border-border text-foreground">
                  {sanitizeSnippetSafely(ent)}
                </span>
              ))}
            </div>
          )}

          {/* Correlated Threat Intelligence Section */}
          {correlationSummaries.length > 0 && (
            <div className="space-y-2 rounded-xl border border-purple-500/40 bg-purple-500/5 dark:bg-purple-950/20 p-3">
              <div className="flex items-center justify-between flex-wrap gap-1 border-b border-purple-500/20 pb-2">
                <span className="font-bold text-xs uppercase tracking-wider text-purple-700 dark:text-purple-300 flex items-center gap-1.5">
                  <GitMerge className="h-4 w-4 text-purple-600 dark:text-purple-400" aria-hidden="true" />
                  Correlated Threat Intelligence ({correlationSummaries.length})
                </span>
                <span className="text-[10px] text-purple-600 dark:text-purple-400 font-mono">
                  Multi-Domain Correlation
                </span>
              </div>
              <ul className="space-y-1.5 list-none pl-0 pt-1">
                {correlationSummaries.map((summaryText, idx) => (
                  <li
                    key={idx}
                    className="rounded-lg border border-purple-500/30 bg-background/80 p-2 text-xs flex items-start gap-2"
                  >
                    <GitMerge className="h-3.5 w-3.5 text-purple-500 shrink-0 mt-0.5" aria-hidden="true" />
                    <span className="text-foreground leading-normal break-words [overflow-wrap:anywhere]">
                      {enforceCautiousLanguage(summaryText)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Analyzer Coverage & Pipeline Scope */}
          {analyzerSummaries.length > 0 && (
            <div className="rounded-lg border border-border/60 bg-muted/30 p-2.5 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                <Layers className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                <span>Analyzer Coverage & Intelligence Scope ({analyzerSummaries.length})</span>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {analyzerSummaries.map((cov, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-background border border-border/70 text-[11px] text-foreground font-medium"
                  >
                    <Layers className="h-3 w-3 text-muted-foreground" aria-hidden="true" />
                    {cov}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Privacy Protections Applied */}
          {privacyGuarantees.length > 0 && (
            <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-2.5 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-sky-700 dark:text-sky-300">
                <Lock className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                <span>Privacy Protections Applied ({privacyGuarantees.length})</span>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {privacyGuarantees.map((tag, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-background border border-sky-500/30 text-sky-700 dark:text-sky-300 text-[10px] font-medium"
                  >
                    <EyeOff className="h-3 w-3" aria-hidden="true" />
                    {PRIVACY_TAG_LABELS[tag] || tag.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Unified Image Intelligence Telemetry Hub (Stages 7.1 - 7.5) */}
          {isImageContext && (
            <div className="space-y-2 rounded-xl border border-border/70 bg-muted/20 p-3">
              <div className="flex items-center justify-between flex-wrap gap-1 border-b border-border/50 pb-2">
                <span className="font-bold text-xs uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <FileImage className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                  Image Intelligence Overview
                </span>
                <span className="text-[10px] text-muted-foreground font-mono">
                  Stages 7.1 - 7.5 Verified
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                {/* 7.1 Image Foundation */}
                {imageFoundationEvidence && (
                  <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/30 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-muted-foreground flex items-center gap-1">
                        <FileImage className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        Structure & Format
                      </span>
                      <span className="font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-background border border-border text-foreground">
                        {String(imageFoundationEvidence.data?.format || 'IMAGE').toUpperCase()}
                      </span>
                    </div>
                    <div className="text-[11px] text-muted-foreground flex items-center gap-2 flex-wrap mt-0.5">
                      {Boolean(imageFoundationEvidence.data?.width && imageFoundationEvidence.data?.height) && (
                        <span>Dimensions: <strong>{`${imageFoundationEvidence.data?.width}×${imageFoundationEvidence.data?.height}`}</strong></span>
                      )}
                      {Boolean(imageFoundationEvidence.data?.rawSizeBytes) && (
                        <span>Size: <strong>{`${formatBytes(imageFoundationEvidence.data?.rawSizeBytes as number)}`}</strong></span>
                      )}
                    </div>
                  </div>
                )}

                {/* 7.2 Visual Text (OCR) */}
                {ocrEvidence && (
                  <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/30 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-muted-foreground flex items-center gap-1">
                        <ScanText className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        Visual OCR Text
                      </span>
                      <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-background border border-border text-foreground">
                        {ocrEvidence.data?.hasText ? 'Text Extracted' : 'No Text Detected'}
                      </span>
                    </div>
                    {Boolean(ocrEvidence.data?.hasText) && (
                      <div className="text-[11px] text-muted-foreground flex items-center gap-1.5 flex-wrap mt-0.5">
                        {ocrEvidence.data?.lineCount !== undefined && (
                          <span>{`${ocrEvidence.data.lineCount} lines`}</span>
                        )}
                        {ocrEvidence.data?.characterCount !== undefined && (
                          <span>{`(${Number(ocrEvidence.data.characterCount).toLocaleString()} chars)`}</span>
                        )}
                        {Boolean(ocrEvidence.data?.truncated) && (
                          <span className="text-[10px] font-medium px-1 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                            Bounded (10k limit)
                          </span>
                        )}
                      </div>
                    )}
                    {ocrEvidence.snippet && (
                      <div className="text-[10px] text-muted-foreground/90 font-mono bg-background/50 rounded px-1.5 py-1 line-clamp-2 border border-border/30 break-all mt-0.5">
                        &ldquo;{sanitizeSnippetSafely(ocrEvidence.snippet)}&rdquo;
                      </div>
                    )}
                  </div>
                )}

                {/* 7.3 QR Code Intelligence */}
                {qrEvidence && (
                  <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/30 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-muted-foreground flex items-center gap-1">
                        <QrCode className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        QR Intelligence
                      </span>
                      <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-background border border-border text-foreground">
                        {(qrEvidence.data?.detectedCount as number) > 0 ? `${qrEvidence.data?.detectedCount} Detected` : 'None'}
                      </span>
                    </div>
                    {Array.isArray(qrEvidence.data?.payloadTypes) && (qrEvidence.data.payloadTypes as string[]).length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap mt-0.5">
                        {(qrEvidence.data.payloadTypes as string[]).map((pt, idx) => (
                          <span key={idx} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                            {pt.replace('_uri', '').replace('_', ' ').toUpperCase()}
                          </span>
                        ))}
                        {Boolean(qrEvidence.data?.hasQuishingRisk) && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                            Quishing Threat
                          </span>
                        )}
                      </div>
                    )}
                    {qrEvidence.snippet && (
                      <div className="text-[10px] text-muted-foreground/90 font-mono bg-background/50 rounded px-1.5 py-1 line-clamp-2 border border-border/30 break-all mt-0.5">
                        &ldquo;{sanitizeSnippetSafely(qrEvidence.snippet)}&rdquo;
                      </div>
                    )}
                  </div>
                )}

                {/* 7.4 Visual Fraud & Scam Screenshot */}
                {visualScamEvidence && (
                  <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/30 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-muted-foreground flex items-center gap-1">
                        <Smartphone className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                        Visual Media Context
                      </span>
                      {Boolean(visualScamEvidence.data?.isScreenshot) && (
                        <span className="font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded bg-background border border-border text-foreground">
                          Screenshot Layout
                        </span>
                      )}
                    </div>
                    {Array.isArray(visualScamEvidence.data?.detectedCategories) && (visualScamEvidence.data.detectedCategories as string[]).length > 0 && (
                      <div className="flex items-center gap-1 flex-wrap mt-0.5">
                        {(visualScamEvidence.data.detectedCategories as string[]).map((cat, idx) => (
                          <span key={idx} className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                            {CATEGORY_LABELS[cat] || cat.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                    {Boolean(visualScamEvidence.data?.isEducational) && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 inline-block w-fit">
                        Educational Context Observed
                      </span>
                    )}
                  </div>
                )}

                {/* 7.5 Authenticity & Provenance */}
                {authEvidence && (
                  <div className="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/30 p-2 text-xs sm:col-span-2">
                    <div className="flex items-center justify-between flex-wrap gap-1">
                      <span className="font-semibold text-muted-foreground flex items-center gap-1">
                        <Sparkles className="h-3.5 w-3.5 text-purple-500" aria-hidden="true" />
                        Media Authenticity & Provenance
                      </span>
                      <span className="text-[10px] text-muted-foreground italic">
                        Observational indicators only
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
                      {Boolean(authEvidence.data?.software) && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20">
                          {`Software: ${authEvidence.data?.software}`}
                        </span>
                      )}
                      {Boolean(authEvidence.data?.cameraMake) && (
                        <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-background border border-border text-foreground">
                          {`Camera: ${authEvidence.data?.cameraMake}`}
                        </span>
                      )}
                      {Boolean(authEvidence.data?.resolution) && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                          {String(authEvidence.data?.resolution)}
                        </span>
                      )}
                      {Boolean(authEvidence.data?.hasGpsData) && (
                        <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">
                          GPS Present (Redacted)
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Explicit Authenticity Epistemic Disclaimer */}
              {categoryCounts.authenticity > 0 && (
                <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-2 text-xs text-muted-foreground flex items-start gap-2">
                  <Info className="h-3.5 w-3.5 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" aria-hidden="true" />
                  <p className="leading-normal text-[11px]">
                    Authenticity heuristics evaluate observable metadata, canvas dimensions, and visual structure. They do not constitute definitive proof of human or synthetic origin. Absence of metadata is normal in web-shared images and does not imply deception.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Target URL if URL intelligence */}
          {(() => {
            const urlEvidence = (evidence || []).find(e => e.sourceType === 'url_analysis');
            const targetUrl = (urlEvidence?.data?.displayUrl as string) || (urlEvidence?.data?.rawUrl as string);
            if (!targetUrl) return null;
            return (
              <div className="flex items-center gap-2 rounded-lg border border-border/60 bg-muted/30 px-3 py-2 text-xs">
                <Globe className="h-4 w-4 text-muted-foreground shrink-0" aria-hidden="true" />
                <span className="font-semibold text-muted-foreground shrink-0">Target URL:</span>
                <span className="font-mono text-foreground break-all">{targetUrl}</span>
              </div>
            );
          })()}

          {/* Claimed Identity & Social Engineering Tactics (Phase 6.2 & Stage 7.4) */}
          {(() => {
            const scamEvidence = (evidence || []).find(
              e => (e.sourceType === 'content_analysis' || e.sourceName?.includes('Visual Scam')) &&
                (Array.isArray(e.data?.detectedTactics) || Array.isArray(e.data?.claimedEntities))
            );
            if (!scamEvidence) return null;

            const tactics = (scamEvidence.data?.detectedTactics as string[]) || [];
            const entities = (scamEvidence.data?.claimedEntities as string[]) || [];

            if (tactics.length === 0 && entities.length === 0) return null;

            return (
              <div className="space-y-2 rounded-lg border border-border/60 bg-muted/30 p-3 text-xs">
                {entities.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-muted-foreground flex items-center gap-1">
                      <Building2 className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                      Claimed Organization:
                    </span>
                    {entities.map((ent, idx) => (
                      <span
                        key={idx}
                        className="font-medium px-2 py-0.5 rounded bg-background border border-border text-foreground"
                      >
                        {ent}
                      </span>
                    ))}
                  </div>
                )}
                {tactics.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="font-semibold text-muted-foreground flex items-center gap-1">
                      <Zap className="h-3.5 w-3.5 text-amber-500" aria-hidden="true" />
                      {isSecurity ? 'Social Engineering Tactics:' : 'Warning Signs Detected:'}
                    </span>
                    {tactics.map((tactic, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"
                      >
                        {TACTIC_LABELS[tactic] || tactic}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Code & Script Security Metadata (Phase 6.3) */}
          {(() => {
            const codeEvidence = (evidence || []).find(
              e => e.sourceName === 'Static Code & Script Security Engine' || (e.data && 'language' in e.data)
            );
            if (!codeEvidence && report.inputType !== 'code') return null;

            const language = (codeEvidence?.data?.language as string) || (report.inputType === 'code' ? 'Code' : null);
            if (!language) return null;

            const charCount = codeEvidence?.data?.characterCount as number | undefined;
            const truncated = codeEvidence?.data?.truncated as boolean | undefined;

            return (
              <div className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/30 px-3 py-2 text-xs">
                <div className="flex items-center gap-2">
                  <Code2 className="h-4 w-4 text-muted-foreground shrink-0" aria-hidden="true" />
                  <span className="font-semibold text-muted-foreground shrink-0">
                    {isSecurity ? 'Analyzed Code Language:' : 'Code Language:'}
                  </span>
                  <span className="font-mono text-xs font-semibold uppercase px-2 py-0.5 rounded bg-background border border-border text-foreground">
                    {language}
                  </span>
                  {truncated && (
                    <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                      Truncated (50k limit)
                    </span>
                  )}
                </div>
                {typeof charCount === 'number' && (
                  <span className="text-[11px] text-muted-foreground font-mono">
                    {charCount.toLocaleString()} chars
                  </span>
                )}
              </div>
            );
          })()}

          {/* Summary */}
          {summary && (
            <p className="text-xs text-muted-foreground leading-relaxed break-words [overflow-wrap:anywhere]">
              {enforceCautiousLanguage(summary)}
            </p>
          )}

          {/* Detected Indicators */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
              {presentation.findingsLabel || (isSecurity ? 'Technical Findings & Indicators' : 'What We Found')} ({findings.length})
            </h4>
            {sortedFindings.length > 0 ? (
              <ul className="space-y-1.5 list-none pl-0">
                {sortedFindings.map((f, i) => {
                  const lineNum = typeof f.metadata?.lineNumber === 'number' ? f.metadata.lineNumber : undefined;
                  const rawSnippet = typeof f.metadata?.snippet === 'string'
                    ? f.metadata.snippet
                    : typeof f.metadata?.redactedSnippet === 'string'
                    ? f.metadata.redactedSnippet
                    : typeof f.metadata?.evidenceSnippet === 'string'
                    ? f.metadata.evidenceSnippet
                    : undefined;
                  const snippet = sanitizeSnippetSafely(rawSnippet);
                  const secretClass = typeof f.metadata?.secretClass === 'string' ? f.metadata.secretClass : undefined;
                  const cat = categorizeFinding(f);
                  const catInfo = CATEGORY_META[cat];
                  const consolidatedFinding = f as Partial<ConsolidatedFinding>;
                  const targetEntity = consolidatedFinding.targetEntity;
                  const observationCount = consolidatedFinding.observationCount;
                  const sources = consolidatedFinding.sources || [];

                  return (
                    <li
                      key={i}
                      className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs flex flex-col gap-1.5"
                    >
                      <div className="flex items-center justify-between font-semibold text-foreground flex-wrap gap-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={cn('text-[10px] font-semibold px-1.5 py-0.5 rounded border', catInfo.colorClass)}>
                            {catInfo.label}
                          </span>
                          <span className="break-words [overflow-wrap:anywhere]">{enforceCautiousLanguage(f.title)}</span>
                          {targetEntity && (
                            <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-background border border-border text-foreground/80 shrink-0">
                              {sanitizeSnippetSafely(targetEntity, 40)}
                            </span>
                          )}
                          {typeof observationCount === 'number' && observationCount > 1 && (
                            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border/40 shrink-0">
                              {`${observationCount} signals consolidated`}
                            </span>
                          )}
                          {lineNum !== undefined && (
                            <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-background border border-border text-foreground/80 shrink-0">
                              Line {lineNum}
                            </span>
                          )}
                          {secretClass && (
                            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 shrink-0">
                              {secretClass}
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-background border border-border text-muted-foreground shrink-0">
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-muted-foreground leading-normal break-words [overflow-wrap:anywhere]">{enforceCautiousLanguage(f.description)}</p>
                      
                      {sources.length > 0 && (
                        <div className="flex items-center gap-1 flex-wrap text-[10px] text-muted-foreground pt-0.5">
                          <span className="font-semibold">Observed across:</span>
                          {sources.map((s, sIdx) => (
                            <span key={sIdx} className="px-1.5 py-0.2 rounded bg-background/80 border border-border/50 uppercase font-mono text-[9px]">
                              {s.origin.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      )}

                      {snippet && (
                        <div className="mt-0.5 font-mono text-[11px] bg-background/90 text-foreground/90 px-2.5 py-1.5 rounded border border-border/60 overflow-x-auto whitespace-pre">
                          <code>{String(snippet)}</code>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground italic pl-1">
                {riskLevel === 'unknown'
                  ? (summary || 'One or more attachments could not be loaded for analysis. Exercise caution with unverified files.')
                  : (presentation.emptyFindingsText || (isSecurity ? 'No anomalous threat signatures or vulnerable patterns detected.' : 'No suspicious indicators were detected in this message or link.'))}
              </p>
            )}
          </div>

          {/* External Threat Intelligence Evidence */}
          {(() => {
            const repEvidence = (evidence || []).filter(e => e.sourceType === 'reputation_provider');
            if (repEvidence.length === 0) return null;

            const repFinding = findings.find(f => f.type.startsWith('reputation_'));

            return (
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                  {presentation.telemetryLabel || (isSecurity ? 'Threat Intelligence & Reputation Feeds' : 'Safety Intelligence & Link Verification')} ({repEvidence.length})
                </h4>
                <ul className="space-y-1.5 list-none pl-0">
                  {repEvidence.map((ev, i) => {
                    const dStatus = (ev.data?.detectionStatus as string) || '';
                    const dConf = (ev.data?.confidence as string) || '';
                    return (
                      <li
                        key={i}
                        className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs flex flex-col gap-1"
                      >
                        <div className="flex items-center justify-between font-semibold text-foreground flex-wrap gap-1">
                          <span>{ev.label || ev.sourceName}</span>
                          <div className="flex items-center gap-1.5">
                            {dStatus && (
                              <span
                                className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                                  dStatus === 'malicious'
                                    ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                                    : dStatus === 'suspicious'
                                    ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                                    : dStatus === 'clean'
                                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                                    : 'bg-muted text-muted-foreground border border-border/40'
                                }`}
                              >
                                Status: {dStatus === 'clean' ? 'No Threat Match Found' : dStatus.charAt(0).toUpperCase() + dStatus.slice(1)}
                              </span>
                            )}
                            {dConf && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-muted text-muted-foreground border border-border/40">
                                Confidence: {dConf.charAt(0).toUpperCase() + dConf.slice(1)}
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-muted-foreground leading-normal break-words [overflow-wrap:anywhere]">{ev.description}</p>
                        {ev.snippet && (
                          <span className="font-mono text-[10px] text-muted-foreground/80 bg-background/80 px-2 py-1 rounded border border-border/40 break-all">
                            {sanitizeSnippetSafely(ev.snippet)}
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>

                {/* Multi-provider Consensus Summary */}
                {repFinding && repEvidence.length > 1 && (
                  <div className="rounded-lg border border-border/60 bg-muted/30 p-2 text-xs flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-medium text-foreground">
                      <span className="font-semibold">Consensus:</span>
                      <span className="text-muted-foreground">
                        {repFinding.type === 'reputation_disputed'
                          ? 'Disputed'
                          : repFinding.type === 'reputation_malicious'
                          ? 'Malicious'
                          : repFinding.type === 'reputation_clean'
                          ? 'No Threats Flagged'
                          : 'Suspicious'}
                      </span>
                    </div>
                    {typeof repFinding.metadata?.consensusScore === 'number' && (
                      <span className="text-[10px] text-muted-foreground font-mono">
                        Score: {repFinding.metadata.consensusScore > 0 ? `+${repFinding.metadata.consensusScore}` : repFinding.metadata.consensusScore}
                      </span>
                    )}
                  </div>
                )}
              </div>
            );
          })()}

          {/* Recommended Actions */}
          {recommendations.length > 0 && (
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                {presentation.actionsLabel || (isSecurity ? 'Remediation & Hardening Actions' : 'What You Should Do')}
              </h4>
              <ul className="space-y-1.5 list-none pl-0">
                {recommendations.map((r, i) => (
                  <li
                    key={i}
                    className="rounded-lg border border-border/60 bg-muted/40 p-2.5 text-xs"
                  >
                    <div className="font-semibold text-foreground flex items-center gap-1.5">
                      <span>{enforceCautiousLanguage(r.title)}</span>
                    </div>
                    <p className="text-muted-foreground mt-0.5 leading-normal">{enforceCautiousLanguage(r.description)}</p>
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
                <span>{presentation.limitationsLabel || (isSecurity ? 'Technical Scope & Analysis Boundaries' : 'Things to Keep in Mind')}</span>
              </div>
              <ul className="list-disc pl-4 space-y-0.5">
                {limitations.map((lim, idx) => (
                  <li key={idx}>{enforceCautiousLanguage(lim)}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
