import crypto from 'crypto';
import { ThemeAnalyzer, ThemeContext } from '../../engine';
import { Message, Attachment } from '@/lib/ai/types';
import { SafetyService } from '@/lib/safety/service';
import { SafetyThemeContextFacts } from './types';
import {
  SafetyInput,
  SafetyReport,
  Finding,
  Evidence,
  AnalyzerResult,
  Recommendation,
  SafetyInputType,
} from '@/lib/safety/types';
import { RiskEngine } from '@/lib/safety/risk-engine';
import { UrlAnalyzer } from '@/lib/safety/analyzers/url-analyzer';
import {
  isTextAnalyzableAttachment,
  isPdfAttachment,
  isImageAttachment,
  loadAttachmentContent,
} from '@/lib/attachments';
import { imageEngine } from '@/lib/safety/image';

const urlAnalyzer = new UrlAnalyzer();

/**
 * Extracts and deduplicates URLs from text content, capped at 3 URLs.
 */
function extractUrlsFromContent(text: string): string[] {
  if (!text) return [];
  const urlRegex = /https?:\/\/[^\s<>"'`]+/gi;
  const matches = text.match(urlRegex) || [];
  const uniqueUrls = new Set<string>();

  for (const raw of matches) {
    // Strip trailing punctuation
    const clean = raw.replace(/[.,;:!?)\]}>]+$/, '');
    if (clean.length > 8) {
      uniqueUrls.add(clean);
      if (uniqueUrls.size >= 3) break;
    }
  }

  return Array.from(uniqueUrls);
}

export class SafetySecurityAnalyzer implements ThemeAnalyzer {
  async analyze(input: string, history: Message[]): Promise<Partial<ThemeContext>> {
    // 1. Locate the active user message
    let targetUserMessage: Message | null = null;
    for (let i = history.length - 1; i >= 0; i--) {
      if (history[i].role === 'user') {
        targetUserMessage = history[i];
        break;
      }
    }

    const attachments: Attachment[] = (targetUserMessage?.metadata?.attachments || []).slice(0, 3);
    const sourceContext = history.length > 0 ? 'conversation_turn' : 'direct_prompt';

    // 2. Fast-path: If no attachments exist, analyze prompt text directly
    if (attachments.length === 0) {
      const report = await SafetyService.analyze({
        rawContent: input,
        sourceContext,
      });

      return this.buildContextResult(report);
    }

    // 3. Attachment-aware pipeline
    const reports: SafetyReport[] = [];
    const failedAttachments: string[] = [];
    let hasPdf = false;

    // A. Analyze each attachment safely
    for (const att of attachments) {
      if (isPdfAttachment(att)) {
        hasPdf = true;
        reports.push(this.buildPdfReport(att));
        continue;
      }

      if (isImageAttachment(att)) {
        try {
          const imageReport = await imageEngine.analyzeAttachment(att);
          if (imageReport.status === 'failed') {
            failedAttachments.push(att.original_name || 'image');
          }
          reports.push(imageReport);
        } catch (imgErr: unknown) {
          const errorMsg = imgErr instanceof Error ? imgErr.message : 'Image inspection error';
          const filename = att.original_name || 'image';
          failedAttachments.push(filename);
          reports.push(imageEngine.buildFailedReport(
            crypto.randomUUID(),
            filename,
            `Image "${filename}" could not be retrieved: ${errorMsg}`,
            new Date().toISOString(),
            errorMsg
          ));
        }
        continue;
      }

      if (isTextAnalyzableAttachment(att)) {
        try {
          const loaded = await loadAttachmentContent(att);

          const mappedSafetyType: SafetyInputType =
            loaded.type === 'code'
              ? 'code'
              : loaded.type === 'html'
              ? 'website'
              : 'document';

          const attachmentInput: SafetyInput = {
            rawContent: loaded.content,
            filename: loaded.filename,
            mimeType: loaded.mimeType,
            type: mappedSafetyType,
            sourceContext: 'attachment',
            metadata: {
              attachmentId: att.id,
              originalName: loaded.filename,
              publicId: loaded.publicId,
              size: loaded.rawSizeBytes,
            },
          };

          const report = await SafetyService.analyze(attachmentInput);

          // Check for URLs embedded within the document/code content
          const embeddedUrls = extractUrlsFromContent(loaded.content);
          if (embeddedUrls.length > 0) {
            for (const url of embeddedUrls) {
              try {
                const urlResult = await urlAnalyzer.analyze({
                  rawContent: url,
                  type: 'url',
                  sourceContext: 'embedded_document_url',
                });
                if (urlResult.findings.length > 0) {
                  report.findings.push(...urlResult.findings);
                  report.evidence.push(...urlResult.evidence);
                  report.analyzerResults.push(urlResult);
                }
              } catch {
                // Ignore single embedded URL failure
              }
            }

            // Re-evaluate risk if extra URL findings were discovered
            if (embeddedUrls.length > 0) {
              const reeval = RiskEngine.evaluate(report.findings, report.analyzerResults);
              report.riskLevel = reeval.riskLevel;
              report.score = reeval.score;
              report.recommendations = reeval.recommendations;
            }
          }

          reports.push(report);
        } catch (err: unknown) {
          const errorMsg = err instanceof Error ? err.message : 'Unknown load error';
          const filename = att.original_name || 'attachment';
          failedAttachments.push(filename);

          const failedReport: SafetyReport = {
            analysisId: crypto.randomUUID(),
            inputType: 'file',
            status: 'failed',
            riskLevel: 'unknown',
            confidenceLevel: 'low',
            score: 0,
            summary: `Attachment "${filename}" could not be retrieved for inspection: ${errorMsg}`,
            findings: [],
            evidence: [],
            recommendations: [
              {
                action: 'proceed_with_caution',
                title: 'Exercise Caution With Unverified Files',
                description: `Inspection for "${filename}" could not be completed. Treat this file with caution.`,
                priority: 'high',
              },
            ],
            limitations: [`Attachment "${filename}" could not be loaded: ${errorMsg}`],
            analyzerResults: [
              {
                analyzerId: 'attachment-loader',
                analyzerType: 'file',
                status: 'failed',
                confidence: 'low',
                findings: [],
                evidence: [],
                error: errorMsg,
                limitations: [`Attachment "${filename}" could not be retrieved.`],
              },
            ],
            createdAt: new Date().toISOString(),
          };

          reports.push(failedReport);
        }
      }
    }

    // B. If user supplied accompanying prompt text, analyze it as well
    if (input && input.trim().length > 0) {
      const promptReport = await SafetyService.analyze({
        rawContent: input,
        sourceContext,
      });
      // If there are findings in the prompt text, include the prompt report
      if (promptReport.findings.length > 0 || reports.length === 0) {
        reports.push(promptReport);
      }
    }

    // C. Consolidate results into a single authoritative report
    const finalReport = this.consolidateReports(reports, failedAttachments, hasPdf, attachments.length);
    return this.buildContextResult(finalReport);
  }

  private buildPdfReport(att: Attachment): SafetyReport {
    const filename = att.original_name || 'document.pdf';
    return {
      analysisId: crypto.randomUUID(),
      inputType: 'document',
      status: 'completed',
      riskLevel: 'low',
      confidenceLevel: 'medium',
      score: 0,
      summary: `Attached PDF document "${filename}" detected. Content inspection is processed via document-level conversation streaming.`,
      findings: [],
      evidence: [],
      recommendations: [
        {
          action: 'proceed_with_caution',
          title: 'Verify Document Source',
          description: 'Ensure attached documents are received from trusted senders before relying on sensitive instructions.',
          priority: 'low',
        },
      ],
      limitations: [
        'PDF content inspection is processed via document-level conversation streaming. Deterministic static rule analysis is not supported for binary PDF files.',
      ],
      analyzerResults: [
        {
          analyzerId: 'pdf-document-handler',
          analyzerType: 'document',
          status: 'partial',
          confidence: 'medium',
          findings: [],
          evidence: [],
          limitations: ['Binary PDF requires multimodal document stream processing.'],
        },
      ],
      createdAt: new Date().toISOString(),
    };
  }

  private consolidateReports(
    reports: SafetyReport[],
    failedAttachments: string[],
    hasPdf: boolean,
    totalAttachments: number
  ): SafetyReport {
    if (reports.length === 0) {
      return {
        analysisId: crypto.randomUUID(),
        inputType: 'message',
        status: 'completed',
        riskLevel: 'low',
        confidenceLevel: 'medium',
        score: 0,
        summary: 'No analyzable attachments or indicators found.',
        findings: [],
        evidence: [],
        recommendations: [],
        limitations: [],
        analyzerResults: [],
        createdAt: new Date().toISOString(),
      };
    }

    if (reports.length === 1 && failedAttachments.length === 0) {
      return reports[0];
    }

    const allFindings: Finding[] = [];
    const allEvidence: Evidence[] = [];
    const allAnalyzerResults: AnalyzerResult[] = [];
    const allLimitations: string[] = [];
    const allRecommendations: Recommendation[] = [];
    let dominantInputType: SafetyInputType = 'message';

    for (const rep of reports) {
      if (rep.inputType === 'code') dominantInputType = 'code';
      else if (dominantInputType !== 'code' && rep.inputType === 'document') dominantInputType = 'document';
      else if (dominantInputType !== 'code' && dominantInputType !== 'document' && rep.inputType === 'website') dominantInputType = 'website';
      else if (dominantInputType !== 'code' && dominantInputType !== 'document' && dominantInputType !== 'website' && rep.inputType === 'image') dominantInputType = 'image';

      allFindings.push(...rep.findings);
      allEvidence.push(...rep.evidence);
      allAnalyzerResults.push(...rep.analyzerResults);
      allLimitations.push(...rep.limitations);
      allRecommendations.push(...rep.recommendations);
    }

    // Deduplicate recommendations by title
    const seenTitles = new Set<string>();
    const uniqueRecommendations = allRecommendations.filter(r => {
      if (seenTitles.has(r.title)) return false;
      seenTitles.add(r.title);
      return true;
    });

    const hasFailures = failedAttachments.length > 0;
    const allFailed = hasFailures && allFindings.length === 0;

    const evaluation = RiskEngine.evaluate(allFindings, allAnalyzerResults);

    let finalRiskLevel = evaluation.riskLevel;
    let finalConfidence = evaluation.confidenceLevel;
    let status: 'completed' | 'failed' = 'completed';

    if (allFailed) {
      finalRiskLevel = 'unknown';
      finalConfidence = 'low';
      status = 'failed';
    }

    let summary: string;
    if (allFailed) {
      summary = `The attachment${failedAttachments.length > 1 ? 's' : ''} (${failedAttachments.join(', ')}) could not be retrieved for inspection. Exercise caution with unverified files.`;
    } else if (allFindings.length > 0) {
      const topSev = allFindings.some(f => f.severity === 'critical')
        ? 'critical'
        : allFindings.some(f => f.severity === 'high')
        ? 'high'
        : 'medium';
      summary = `Identified ${allFindings.length} technical finding${allFindings.length > 1 ? 's' : ''} with ${topSev.toUpperCase()} severity across attached content.`;
      if (hasFailures) {
        summary += ` Note: ${failedAttachments.join(', ')} could not be retrieved.`;
      }
    } else if (dominantInputType === 'image') {
      const imageRep = reports.find(r => r.inputType === 'image');
      summary = imageRep?.summary || 'Image inspection completed with no Stage 7.2 structural or textual issues detected.';
    } else if (hasPdf) {
      summary = `Attached document${totalAttachments > 1 ? 's' : ''} detected. Deep inspection is processed via conversation document streaming.`;
    } else {
      summary = 'No anomalous threat patterns or vulnerable signatures identified in the inspected attachments.';
    }

    return {
      analysisId: crypto.randomUUID(),
      inputType: dominantInputType,
      status,
      riskLevel: finalRiskLevel,
      confidenceLevel: finalConfidence,
      score: evaluation.score,
      summary,
      findings: allFindings,
      evidence: allEvidence,
      recommendations: uniqueRecommendations,
      limitations: Array.from(new Set(allLimitations)),
      analyzerResults: allAnalyzerResults,
      createdAt: new Date().toISOString(),
    };
  }

  private buildContextResult(report: SafetyReport): Partial<ThemeContext> {
    const facts: SafetyThemeContextFacts = {
      inputType: report.inputType,
      riskLevel: report.riskLevel,
      confidenceLevel: report.confidenceLevel,
      findingCount: report.findings.length,
      report,
    };

    return {
      intent: 'safety_check',
      entities: [report.inputType],
      facts: facts as unknown as Record<string, unknown>,
      metadata: {
        analysisId: report.analysisId,
        score: report.score,
      },
    };
  }
}
