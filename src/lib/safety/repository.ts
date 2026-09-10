import { createClient } from '@/lib/supabase/server';
import { SafetyReport } from './types';
import { redactDataRecord, redactSensitiveText } from './redaction';

export interface PersistedSafetyAnalysis {
  id: string;
  conversation_id: string | null;
  message_id: string | null;
  user_id: string;
  input_type: string;
  risk_level: string;
  confidence_level: string;
  score: number | null;
  summary: string;
  created_at: string;
}

/**
 * Server-only repository for persisting and querying safety analyses in Supabase.
 * Respects Row-Level Security (RLS) using the authenticated user from the SSR session.
 */
export class SafetyRepository {
  /**
   * Persists a deterministic safety analysis report and its related findings,
   * evidence, and recommendations. All persisted data is strictly redacted first.
   */
  static async saveAnalysis(
    report: SafetyReport,
    conversationId?: string,
    messageId?: string
  ): Promise<string | null> {
    try {
      const supabase = await createClient();
      const {
        data: { user },
        error: authError,
      } = await supabase.auth.getUser();

      if (authError || !user) {
        // Safe degrade for unauthenticated or test contexts
        return null;
      }

      // 1. Insert main analysis record
      const { data: analysis, error: analysisError } = await supabase
        .from('safety_analyses')
        .insert({
          conversation_id: conversationId || null,
          message_id: messageId || null,
          user_id: user.id,
          input_type: report.inputType,
          risk_level: report.riskLevel,
          confidence_level: report.confidenceLevel,
          score: report.score ?? null,
          summary: redactSensitiveText(report.summary),
        })
        .select('id')
        .single();

      if (analysisError || !analysis) {
        console.error('Failed to persist safety analysis:', analysisError);
        return null;
      }

      const analysisId = analysis.id;

      // 2. Persist findings
      if (report.findings.length > 0) {
        const findingRows = report.findings.map(f => ({
          analysis_id: analysisId,
          type: f.type,
          title: f.title,
          description: redactSensitiveText(f.description),
          severity: f.severity,
          confidence: f.confidence,
        }));

        const { error: findingsError } = await supabase
          .from('safety_findings')
          .insert(findingRows);

        if (findingsError) {
          console.error('Failed to persist safety findings:', findingsError);
        }
      }

      // 3. Persist evidence
      if (report.evidence.length > 0) {
        const evidenceRows = report.evidence.map(ev => ({
          analysis_id: analysisId,
          evidence_type: ev.sourceType,
          label: ev.label || ev.sourceName,
          snippet: ev.snippet ? redactSensitiveText(ev.snippet) : null,
          data: ev.data ? (redactDataRecord(ev.data) as unknown as import('@/types/database').Json) : null,
        }));

        const { error: evidenceError } = await supabase
          .from('safety_evidence')
          .insert(evidenceRows);

        if (evidenceError) {
          console.error('Failed to persist safety evidence:', evidenceError);
        }
      }

      // 4. Persist recommendations
      if (report.recommendations.length > 0) {
        const recRows = report.recommendations.map(r => ({
          analysis_id: analysisId,
          action: r.action,
          title: r.title,
          description: r.description,
          priority: r.priority,
        }));

        const { error: recsError } = await supabase
          .from('safety_recommendations')
          .insert(recRows);

        if (recsError) {
          console.error('Failed to persist safety recommendations:', recsError);
        }
      }

      return analysisId;
    } catch (err) {
      console.error('Unexpected error in SafetyRepository.saveAnalysis:', err);
      return null;
    }
  }

  /**
   * Retrieves a safety analysis and its findings by ID for the authenticated user.
   */
  static async getAnalysis(analysisId: string): Promise<PersistedSafetyAnalysis | null> {
    try {
      const supabase = await createClient();
      const { data, error } = await supabase
        .from('safety_analyses')
        .select('*')
        .eq('id', analysisId)
        .single();

      if (error) {
        return null;
      }

      return data as unknown as PersistedSafetyAnalysis;
    } catch {
      return null;
    }
  }
}
