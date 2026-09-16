import type { GoogleSheetsExportRow, ExportableSecurityReport } from './types';
import { hashUserId } from './crypto';
import { redactSensitiveText } from '@/lib/safety/redaction';

const FORBIDDEN_HOST_REGEX = /^(localhost|127\..*|10\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[01])\..*|169\.254\..*|0\.0\.0\.0|::1|fe80::.*|.*\.local)$/i;

export function sanitizeDomain(rawDomainOrUrl: string): string | null {
  if (!rawDomainOrUrl || typeof rawDomainOrUrl !== 'string') return null;
  const trimmed = rawDomainOrUrl.trim();
  if (!trimmed) return null;
  try {
    const hasScheme = /^https?:\/\//i.test(trimmed);
    const parsed = new URL(hasScheme ? trimmed : 'http://' + trimmed);
    let host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    host = host.replace(/\.+$/, '');
    if (FORBIDDEN_HOST_REGEX.test(host)) return null;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

export class GoogleSheetsExportSanitizer {
  public static readonly MAX_CONCERN_LENGTH = 300;

  public static sanitize(
    report: ExportableSecurityReport,
    userId: string,
    themeSlug?: string
  ): GoogleSheetsExportRow {
    const user_id_hash = hashUserId(userId);
    const rawConcern = (report as { primaryConcern?: string }).primaryConcern || (report as { summary?: string }).summary || 'Security analysis completed.';
    let primary_concern = redactSensitiveText(rawConcern);
    if (primary_concern.length > this.MAX_CONCERN_LENGTH) {
      primary_concern = primary_concern.substring(0, this.MAX_CONCERN_LENGTH - 3) + '...';
    }
    const candidateDomains = new Set<string>();
    if (Array.isArray((report as { affectedEntities?: unknown[] }).affectedEntities)) {
      for (const ent of (report as { affectedEntities?: string[] }).affectedEntities || []) {
        const clean = sanitizeDomain(ent);
        if (clean) candidateDomains.add(clean);
      }
    }
    if (Array.isArray(report.findings)) {
      for (const f of report.findings) {
        if (f && typeof f === 'object' && 'targetEntity' in f && typeof f.targetEntity === 'string') {
          const clean = sanitizeDomain(f.targetEntity);
          if (clean) candidateDomains.add(clean);
        }
      }
    }
    const domains_involved = Array.from(candidateDomains).slice(0, 10).join(';');
    const coverageList: string[] = [];
    const domainsInvolvedList = (report as { domainsInvolved?: unknown[] }).domainsInvolved;
    if (Array.isArray(domainsInvolvedList) && domainsInvolvedList.length > 0) {
      coverageList.push(...domainsInvolvedList.map((d: unknown) => String(d).toLowerCase()));
    } else if (Array.isArray((report as { analyzerSummaries?: unknown[] }).analyzerSummaries)) {
      coverageList.push(...((report as { analyzerSummaries?: unknown[] }).analyzerSummaries || []).map((s: unknown) => String(s).split(' ')[0].toLowerCase()));
    } else if (Array.isArray((report as { analyzerResults?: unknown[] }).analyzerResults)) {
      coverageList.push(...((report as { analyzerResults?: { analyzerType?: string }[] }).analyzerResults || []).map(a => String(a.analyzerType || '').toLowerCase()).filter(Boolean));
    }
    const analyzer_coverage = Array.from(new Set(coverageList)).slice(0, 10).join(';');
    const finding_count = Array.isArray(report.findings) ? report.findings.length : 0;
    const recommendation_count = Array.isArray(report.recommendations) ? report.recommendations.length : 0;
    const r = report as Record<string, unknown>;
    const reportCreatedAt = typeof r.createdAt === 'string' ? r.createdAt : new Date().toISOString();
    const reportRiskScore = typeof r.score === 'number' ? Math.max(0, Math.min(100, Math.round(r.score))) : 0;

    return {
      timestamp: reportCreatedAt,
      analysis_id: (typeof r.id === 'string' ? r.id : (typeof r.analysisId === 'string' ? r.analysisId : '')),
      user_id_hash,
      input_type: (typeof r.inputType === 'string' ? r.inputType : 'url') as import('@/lib/safety/types').SafetyInputType,
      theme: (themeSlug || 'general').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 30),
      risk_level: (typeof r.riskLevel === 'string' ? r.riskLevel : 'unknown') as import('@/lib/safety/types').RiskLevel,
      risk_score: reportRiskScore,
      confidence_level: (typeof r.confidenceLevel === 'string' ? r.confidenceLevel : 'medium') as import('@/lib/safety/types').ConfidenceLevel,
      primary_concern,
      domains_involved,
      finding_count,
      recommendation_count,
      analyzer_coverage,
      status: (typeof r.status === 'string' ? r.status : 'completed') as import('@/lib/safety/types').AnalysisStatus,
      created_at: reportCreatedAt,
    };
  }

  public static toRowArray(row: GoogleSheetsExportRow): (string | number)[] {
    return [
      row.timestamp,
      row.analysis_id,
      row.user_id_hash,
      row.input_type,
      row.theme,
      row.risk_level.toUpperCase(),
      row.risk_score,
      row.confidence_level.toUpperCase(),
      row.primary_concern,
      row.domains_involved,
      row.finding_count,
      row.recommendation_count,
      row.analyzer_coverage,
      row.status.toUpperCase(),
      row.created_at,
    ];
  }

  public static getHeaders(): string[] {
    return [
      'timestamp',
      'analysis_id',
      'user_id_hash',
      'input_type',
      'theme',
      'risk_level',
      'risk_score',
      'confidence_level',
      'primary_concern',
      'domains_involved',
      'finding_count',
      'recommendation_count',
      'analyzer_coverage',
      'status',
      'created_at',
    ];
  }
}
