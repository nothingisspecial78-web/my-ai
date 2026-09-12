/**
 * Multi-Input Security Orchestrator (Stage 8.4)
 *
 * Coordinates existing intelligence engines (URL, Scam, Code, Image, OCR, QR,
 * Visual Scam, Authenticity) into a unified, deterministic, and dependency-respecting pipeline.
 *
 * STRICT INVARIANTS:
 * 1. SINGLE SCORING AUTHORITY: RiskEngine remains the absolute, single authority on score & risk level.
 *    The orchestrator performs ZERO arithmetic, weighting, averaging, or threshold adjustments.
 * 2. NO DUPLICATE WORK: Shared execution caches ensure identical URLs, code blocks, images, or texts
 *    are analyzed exactly ONCE and reused everywhere.
 * 3. NO RECURSIVE LOOPS: Explicit staging with visited sets prevents circular analyzer delegation.
 * 4. DEPENDENCY RESPECT: Prerequisite analyzers (e.g. image loading, OCR, QR) complete before dependent
 *    analyzers (visual scam, authenticity, delegated URL analysis) are executed.
 * 5. ERROR ISOLATION: A failure in one analyzer (e.g. OCR failure, unreadable QR) is captured as a bounded
 *    limitation/analyzer error and never crashes the pipeline or invalidates other findings.
 * 6. PRIVACY REDACTION: Secrets, passwords, Wi-Fi credentials, OTPAuth payloads, and GPS coordinates
 *    are deeply redacted before report presentation.
 * 7. EXECUTION SAFETY: Zero code execution, zero eval, zero Function, zero VM, zero child_process,
 *    zero arbitrary HTTP fetching, and zero DNS resolution.
 */

import crypto from 'crypto';
import type {
  Finding,
  Evidence,
  AnalyzerResult,
  SafetyInputType,
  SafetyInput,
} from '../types';
import type { Attachment } from '@/lib/ai/types';
import type {
  UnifiedSecurityReport,
  MultiInputTarget,
  OrchestrationResult,
  OrchestrationExecutionOptions,
} from './types';
import { UrlIntelligenceEngine, UrlIntelligenceResult } from '../url';
import { UrlNormalizer } from '../url/normalizer';
import { ScamEngine, ScamAnalysisResult } from '../scam';
import { CodeEngine, CodeAnalysisResult } from '../code';
import {
  loadImageContent,
  isImageAttachment,
  isPdfAttachment,
  isTextAnalyzableAttachment,
  loadAttachmentContent,
  LoadedImageContent,
} from '@/lib/attachments';
import { imageEngine } from '../image';
import { extractVisualOcr, extractUrlsFromText } from '../image/ocr';
import { analyzeImageQrCodes } from '../image/qr';
import type { SanitizedOcrResult, SanitizedQrAnalysisResult } from '../image/types';
import { analyzeVisualScamSignals } from '../image/scam';
import { analyzeVisualAuthenticity } from '../image/authenticity';
import { InputClassifier } from '../analyzers/input-classifier';
import { UnifiedReportBuilder } from './report';

// Bounding constants
export const MAX_ORCHESTRATOR_TEXT_CHARS = 50_000;
export const MAX_ORCHESTRATOR_ATTACHMENTS = 3;
export const MAX_ORCHESTRATOR_URLS = 15;
export const MAX_ORCHESTRATOR_URLS_PER_TEXT = 10;
export const MAX_ORCHESTRATOR_URLS_PER_IMAGE = 5;

/**
 * Multi-Input Security Orchestrator.
 */
export class SecurityOrchestrator {
  /**
   * Primary entry point: orchestrates multi-input security analysis and returns
   * the authoritative UnifiedSecurityReport.
   */
  static async orchestrate(
    target: string | SafetyInput | MultiInputTarget,
    options?: OrchestrationExecutionOptions
  ): Promise<UnifiedSecurityReport> {
    const detailed = await this.orchestrateDetailed(target, options);
    return detailed.report;
  }

  /**
   * Detailed orchestration entry point returning the UnifiedSecurityReport along with
   * execution telemetry, contributing analyzers, and deduplication statistics.
   */
  static async orchestrateDetailed(
    target: string | SafetyInput | MultiInputTarget,
    options?: OrchestrationExecutionOptions
  ): Promise<OrchestrationResult> {
    const startTime = Date.now();

    // 1. Normalize Target Input
    let rawText = '';
    let attachments: Attachment[] = [];
    let inputTypeHint: SafetyInputType | undefined;
    let sourceContext = 'direct_prompt';
    let callerMetadata: Record<string, unknown> = {};
    let execOptions: OrchestrationExecutionOptions = { ...options };

    if (typeof target === 'string') {
      rawText = target;
    } else if ('rawContent' in target && typeof target.rawContent === 'string') {
      // SafetyInput format
      rawText = target.rawContent;
      inputTypeHint = target.type;
      sourceContext = target.sourceContext || 'direct_prompt';
      callerMetadata = target.metadata || {};
    } else {
      // MultiInputTarget format
      const multi = target as MultiInputTarget;
      rawText = multi.text || '';
      attachments = multi.attachments || [];
      inputTypeHint = multi.inputType;
      sourceContext = multi.sourceContext || 'direct_prompt';
      callerMetadata = multi.metadata || {};
      execOptions = { ...multi.options, ...options };
    }

    // Apply strict bounds
    rawText = rawText.slice(0, execOptions.maxTextLength || MAX_ORCHESTRATOR_TEXT_CHARS);
    attachments = attachments.slice(0, execOptions.maxAttachments || MAX_ORCHESTRATOR_ATTACHMENTS);

    // 2. Shared Caches for Deduplication within this Execution Run
    const urlCache = new Map<string, UrlIntelligenceResult>();
    const scamTextCache = new Map<string, ScamAnalysisResult>();
    const codeCache = new Map<string, CodeAnalysisResult>();
    const imageCache = new Map<string, boolean>();

    const allFindings: Finding[] = [];
    const allEvidence: Evidence[] = [];
    const allAnalyzerResults: AnalyzerResult[] = [];
    const allLimitations: string[] = [];
    const contributingAnalyzers = new Set<string>();

    let duplicateUrlsSkipped = 0;
    let urlsAnalyzed = 0;
    let errorsEncountered = 0;

    /**
     * Shared URL analysis helper ensuring each unique normalized URL is inspected exactly ONCE.
     */
    async function analyzeUrlOnce(
      candidateUrl: string,
      originContext: string
    ): Promise<UrlIntelligenceResult | null> {
      if (!candidateUrl || typeof candidateUrl !== 'string') return null;

      const norm = UrlNormalizer.normalize(candidateUrl);
      const cacheKey = (norm.isValid && norm.normalizedUrl)
        ? norm.normalizedUrl
        : candidateUrl.trim().toLowerCase();

      if (urlCache.has(cacheKey)) {
        duplicateUrlsSkipped++;
        return urlCache.get(cacheKey)!;
      }

      if (urlsAnalyzed >= (execOptions.maxUrls || MAX_ORCHESTRATOR_URLS)) {
        if (!allLimitations.includes('URL analysis count reached maximum limit for a single submission.')) {
          allLimitations.push('URL analysis count reached maximum limit for a single submission.');
        }
        return null;
      }

      try {
        const urlResult = await UrlIntelligenceEngine.analyze(candidateUrl, {
          sourceContext: originContext,
          enableReputation: !execOptions.skipReputation,
        });
        urlsAnalyzed++;
        urlCache.set(cacheKey, urlResult);
        contributingAnalyzers.add('url_intelligence');

        for (const f of urlResult.findings) {
          allFindings.push({
            ...f,
            metadata: {
              ...f.metadata,
              sourceContext: originContext,
              url: norm.normalizedUrl || candidateUrl,
            },
          });
        }
        for (const e of urlResult.evidence) {
          allEvidence.push(e);
        }
        for (const l of urlResult.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }
        allAnalyzerResults.push({
          analyzerId: `url-intelligence-${cacheKey.slice(0, 40)}`,
          analyzerType: 'url',
          status: 'success',
          confidence: urlResult.confidence,
          findings: urlResult.findings,
          evidence: urlResult.evidence,
          limitations: urlResult.limitations,
        });

        return urlResult;
      } catch (err: unknown) {
        errorsEncountered++;
        const errMsg = err instanceof Error ? err.message : 'URL analysis failed';
        allLimitations.push(`URL inspection for "${candidateUrl.slice(0, 50)}" was unavailable: ${errMsg}`);
        allAnalyzerResults.push({
          analyzerId: `url-intelligence-${cacheKey.slice(0, 40)}`,
          analyzerType: 'url',
          status: 'failed',
          confidence: 'low',
          findings: [],
          evidence: [],
          error: errMsg,
          limitations: [`URL analysis unavailable: ${errMsg}`],
        });
        return null;
      }
    }

    /**
     * Shared Scam analysis helper ensuring identical text segments are inspected once.
     */
    async function analyzeScamTextOnce(
      textToAnalyze: string,
      originContext: string
    ): Promise<ScamAnalysisResult | null> {
      if (!textToAnalyze || typeof textToAnalyze !== 'string' || !textToAnalyze.trim()) return null;
      if (execOptions.skipScam) return null;

      const textKey = crypto.createHash('sha256').update(textToAnalyze.trim().slice(0, 10000)).digest('hex').slice(0, 16);
      if (scamTextCache.has(textKey)) {
        return scamTextCache.get(textKey)!;
      }

      // Sanitize URLs out of text passed to ScamEngine so ScamEngine does not initiate
      // redundant, uncached UrlIntelligenceEngine requests outside the orchestrator.
      const sanitizedTextForScam = textToAnalyze.replace(/https?:\/\/[^\s<>"'`{}|\\^~[\]]+/gi, '[LINK]');

      try {
        const scamResult = await ScamEngine.analyze(sanitizedTextForScam);
        scamTextCache.set(textKey, scamResult);
        contributingAnalyzers.add('scam_engine');

        for (const f of scamResult.findings) {
          allFindings.push({
            ...f,
            metadata: {
              ...f.metadata,
              sourceContext: originContext,
            },
          });
        }
        for (const e of scamResult.evidence) {
          allEvidence.push(e);
        }
        for (const l of scamResult.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }
        allAnalyzerResults.push({
          analyzerId: `scam-engine-${originContext}-${textKey}`,
          analyzerType: 'scam',
          status: 'success',
          confidence: scamResult.confidence,
          findings: scamResult.findings,
          evidence: scamResult.evidence,
          limitations: scamResult.limitations,
        });

        return scamResult;
      } catch (err: unknown) {
        errorsEncountered++;
        const errMsg = err instanceof Error ? err.message : 'Scam analysis failed';
        allLimitations.push(`Scam message analysis encountered an error: ${errMsg}`);
        allAnalyzerResults.push({
          analyzerId: `scam-engine-${originContext}`,
          analyzerType: 'scam',
          status: 'failed',
          confidence: 'low',
          findings: [],
          evidence: [],
          error: errMsg,
          limitations: [`Scam analysis error: ${errMsg}`],
        });
        return null;
      }
    }

    /**
     * Shared Code analysis helper ensuring identical code blocks are inspected once.
     */
    async function analyzeCodeOnce(
      codeToAnalyze: string,
      codeFilename?: string,
      originContext: string = 'code_block'
    ): Promise<CodeAnalysisResult | null> {
      if (!codeToAnalyze || typeof codeToAnalyze !== 'string' || !codeToAnalyze.trim()) return null;

      const codeKey = crypto
        .createHash('sha256')
        .update((codeFilename || '') + ':' + codeToAnalyze.trim().slice(0, 20000))
        .digest('hex')
        .slice(0, 16);

      if (codeCache.has(codeKey)) {
        return codeCache.get(codeKey)!;
      }

      try {
        const codeResult = await CodeEngine.analyze(codeToAnalyze, codeFilename);
        codeCache.set(codeKey, codeResult);
        contributingAnalyzers.add('code_engine');

        for (const f of codeResult.findings) {
          allFindings.push({
            ...f,
            metadata: {
              ...f.metadata,
              sourceContext: originContext,
              filename: codeFilename,
            },
          });
        }
        for (const e of codeResult.evidence) {
          allEvidence.push(e);
        }
        for (const l of codeResult.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }
        allAnalyzerResults.push({
          analyzerId: `code-engine-${codeKey}`,
          analyzerType: 'code_security',
          status: 'success',
          confidence: codeResult.confidence,
          findings: codeResult.findings,
          evidence: codeResult.evidence,
          limitations: codeResult.limitations,
        });

        // Check for embedded URLs in code
        if (codeResult.embeddedUrls && codeResult.embeddedUrls.length > 0) {
          for (const url of codeResult.embeddedUrls.slice(0, 5)) {
            await analyzeUrlOnce(url, 'code_embedded_url');
          }
        }

        return codeResult;
      } catch (err: unknown) {
        errorsEncountered++;
        const errMsg = err instanceof Error ? err.message : 'Code analysis failed';
        allLimitations.push(`Code security inspection encountered an error: ${errMsg}`);
        allAnalyzerResults.push({
          analyzerId: `code-engine-${codeKey}`,
          analyzerType: 'code_security',
          status: 'failed',
          confidence: 'low',
          findings: [],
          evidence: [],
          error: errMsg,
          limitations: [`Code analysis error: ${errMsg}`],
        });
        return null;
      }
    }

    // 3. Process Text Input (if present)
    let classifiedType: SafetyInputType | undefined;
    if (rawText && rawText.trim().length > 0) {
      classifiedType = inputTypeHint || InputClassifier.classify({
        rawContent: rawText,
        type: inputTypeHint,
        metadata: callerMetadata,
      });

      const extractedTextUrls = extractUrlsFromText(rawText).slice(0, MAX_ORCHESTRATOR_URLS_PER_TEXT);

      if (classifiedType === 'url') {
        await analyzeUrlOnce(rawText.trim(), 'direct_prompt');
      } else if (classifiedType === 'code') {
        await analyzeCodeOnce(rawText, undefined, 'user_text');
        for (const url of extractedTextUrls) {
          await analyzeUrlOnce(url, 'user_text');
        }
      } else {
        // Message / Scam / Social Engineering
        for (const url of extractedTextUrls) {
          await analyzeUrlOnce(url, 'user_text');
        }
        await analyzeScamTextOnce(rawText, 'user_text');
      }
    }

    // 4. Process Attachments (Multi-Attachment, up to 3)
    for (const att of attachments) {
      // 4A. PDF Attachments
      if (isPdfAttachment(att)) {
        contributingAnalyzers.add('pdf_handler');
        allLimitations.push(
          `PDF content inspection for "${att.original_name || 'document.pdf'}" is processed via document-level conversation streaming. Deterministic static rule analysis is not supported for binary PDF files.`
        );
        allAnalyzerResults.push({
          analyzerId: `pdf-handler-${att.original_name || 'document'}`,
          analyzerType: 'document',
          status: 'partial',
          confidence: 'medium',
          findings: [],
          evidence: [],
          limitations: ['Binary PDF requires multimodal document stream processing.'],
        });
        continue;
      }

      // 4B. Image Attachments (JPEG, PNG, WEBP)
      if (isImageAttachment(att)) {
        const imageKey = att.public_id || att.url || att.id || att.original_name || 'image';
        if (imageCache.has(imageKey)) {
          continue; // Prevent duplicate execution on same image
        }
        imageCache.set(imageKey, true);

        let loaded: LoadedImageContent;
        try {
          loaded = await loadImageContent(att, { cloudName: (callerMetadata?.cloudName as string) || undefined });
        } catch (imgErr: unknown) {
          errorsEncountered++;
          const errMsg = imgErr instanceof Error ? imgErr.message : 'Image load error';
          allLimitations.push(`Image "${att.original_name || 'image'}" could not be retrieved: ${errMsg}`);
          allAnalyzerResults.push({
            analyzerId: `image-loader-${att.original_name || 'image'}`,
            analyzerType: 'image',
            status: 'failed',
            confidence: 'low',
            findings: [],
            evidence: [],
            error: errMsg,
            limitations: [`Image retrieval failed: ${errMsg}`],
          });
          continue;
        }

        // Structural validation
        const structural = imageEngine.evaluateLoadedImage(loaded, att.original_name || 'image');
        for (const f of structural.findings) {
          allFindings.push({
            ...f,
            metadata: {
              ...f.metadata,
              attachmentName: att.original_name,
              attachmentId: att.id,
            },
          });
        }
        for (const e of structural.evidence) {
          allEvidence.push(e);
        }
        allAnalyzerResults.push({
          analyzerId: `image-structural-${att.original_name || 'image'}`,
          analyzerType: 'image',
          status: structural.status === 'completed' ? 'success' : 'failed',
          confidence: structural.confidenceLevel,
          findings: structural.findings,
          evidence: structural.evidence,
          limitations: structural.limitations,
        });
        contributingAnalyzers.add('image_structural');

        // Concurrently run OCR and QR (independent analyzers)
        let ocrResult: SanitizedOcrResult | undefined;
        let qrAnalysis:
          | { qrResult: SanitizedQrAnalysisResult; findings: Finding[]; evidence: Evidence[]; limitations: string[] }
          | undefined;

        const isOcrConfigured = !execOptions.skipOcr && (Boolean(process.env.GEMINI_API_KEY?.trim()) || Boolean(process.env.VITEST));

        const [ocrTask, qrTask] = await Promise.allSettled([
          isOcrConfigured ? extractVisualOcr(loaded, { timeoutMs: execOptions.timeoutMs }) : Promise.resolve(undefined),
          !execOptions.skipQr ? analyzeImageQrCodes(loaded) : Promise.resolve(undefined),
        ]);

        if (ocrTask.status === 'fulfilled' && ocrTask.value) {
          ocrResult = ocrTask.value;
          contributingAnalyzers.add('image_ocr');
          if (ocrResult.status === 'unavailable') {
            allLimitations.push(...(ocrResult.limitations.length > 0 ? ocrResult.limitations : ['Visual OCR extraction was unavailable.']));
          } else {
            allEvidence.push({
              id: crypto.randomUUID(),
              sourceType: 'image_analysis',
              sourceName: 'Gemini Vision OCR',
              label: 'Visual Text & Layout Extraction',
              description: ocrResult.hasText
                ? `Extracted ${ocrResult.lineCount} lines (${ocrResult.characterCount} chars) from ${att.original_name || 'image'}.`
                : `No readable alphanumeric text detected in ${att.original_name || 'image'}.`,
              data: {
                hasText: ocrResult.hasText,
                characterCount: ocrResult.characterCount,
                lineCount: ocrResult.lineCount,
                isScreenshot: ocrResult.visualContext.isScreenshot,
                detectedAppType: ocrResult.visualContext.detectedAppType,
                attachmentName: att.original_name,
              },
              snippet: ocrResult.hasText ? ocrResult.sanitizedText.slice(0, 200) : undefined,
              isAiGenerated: true,
              createdAt: new Date().toISOString(),
            });
          }
        } else if (ocrTask.status === 'rejected') {
          errorsEncountered++;
          const ocrErrMsg = ocrTask.reason instanceof Error ? ocrTask.reason.message : 'OCR failure';
          allLimitations.push(`Visual OCR failed for "${att.original_name || 'image'}": ${ocrErrMsg}`);
          if (!allLimitations.includes(ocrErrMsg)) {
            allLimitations.push(ocrErrMsg);
          }
        }

        if (qrTask.status === 'fulfilled' && qrTask.value) {
          qrAnalysis = qrTask.value;
          contributingAnalyzers.add('image_qr');
          for (const f of qrAnalysis.findings) {
            allFindings.push({
              ...f,
              metadata: {
                ...f.metadata,
                attachmentName: att.original_name,
                attachmentId: att.id,
              },
            });
          }
          for (const e of qrAnalysis.evidence) {
            allEvidence.push(e);
          }
          for (const l of qrAnalysis.limitations) {
            if (!allLimitations.includes(l)) allLimitations.push(l);
          }
        } else if (qrTask.status === 'rejected') {
          errorsEncountered++;
          const qrErrMsg = qrTask.reason instanceof Error ? qrTask.reason.message : 'QR failure';
          allLimitations.push(`QR inspection failed for "${att.original_name || 'image'}": ${qrErrMsg}`);
        }

        // Run Visual Scam and Authenticity heuristics (dependent on OCR & QR outputs)
        if (!execOptions.skipScam) {
          try {
            const visualScam = await analyzeVisualScamSignals(loaded, ocrResult, qrAnalysis?.qrResult);
            contributingAnalyzers.add('image_visual_scam');
            for (const f of visualScam.findings) {
              allFindings.push({
                ...f,
                metadata: {
                  ...f.metadata,
                  attachmentName: att.original_name,
                  attachmentId: att.id,
                },
              });
            }
            for (const e of visualScam.evidence) {
              allEvidence.push(e);
            }
          } catch (scamErr: unknown) {
            errorsEncountered++;
            const scamErrMsg = scamErr instanceof Error ? scamErr.message : 'Visual scam error';
            allLimitations.push(`Visual scam analysis error: ${scamErrMsg}`);
          }
        }

        if (!execOptions.skipAuthenticity) {
          try {
            const authResult = await analyzeVisualAuthenticity(loaded, ocrResult);
            contributingAnalyzers.add('image_authenticity');
            if (!allLimitations.includes('Absence of manipulation signals is not proof of authenticity.')) {
              allLimitations.push('Absence of manipulation signals is not proof of authenticity.');
            }
            for (const f of authResult.findings) {
              allFindings.push({
                ...f,
                metadata: {
                  ...f.metadata,
                  attachmentName: att.original_name,
                  attachmentId: att.id,
                },
              });
            }
            for (const e of authResult.evidence) {
              allEvidence.push(e);
            }
            for (const l of authResult.limitations) {
              if (!allLimitations.includes(l)) allLimitations.push(l);
            }
          } catch (authErr: unknown) {
            errorsEncountered++;
            const authErrMsg = authErr instanceof Error ? authErr.message : 'Authenticity error';
            allLimitations.push(`Authenticity inspection was unavailable: ${authErrMsg}`);
          }
        }

        // Delegate OCR & QR extracted URLs to URL Intelligence (using shared cache)
        if (ocrResult?.extractedUrls && ocrResult.extractedUrls.length > 0) {
          for (const url of ocrResult.extractedUrls.slice(0, MAX_ORCHESTRATOR_URLS_PER_IMAGE)) {
            await analyzeUrlOnce(url, 'ocr_text');
          }
        }

        if (qrAnalysis?.qrResult.delegatedUrls && qrAnalysis.qrResult.delegatedUrls.length > 0) {
          for (const url of qrAnalysis.qrResult.delegatedUrls.slice(0, MAX_ORCHESTRATOR_URLS_PER_IMAGE)) {
            const urlRes = await analyzeUrlOnce(url, 'qr_code');
            // Quishing Detection: if destination is high or critical, flag quishing finding
            if (urlRes && (urlRes.riskLevel === 'critical' || urlRes.riskLevel === 'high')) {
              allFindings.push({
                id: crypto.randomUUID(),
                type: 'phishing_indicator',
                severity: urlRes.riskLevel,
                confidence: 'high',
                title: 'Suspected Quishing Vector (QR Target Deemed Malicious)',
                description: `QR code in "${att.original_name || 'image'}" redirects to a high-risk destination (${url}).`,
                metadata: {
                  url,
                  isQr: true,
                  quishingDetected: true,
                  attachmentName: att.original_name,
                  attachmentId: att.id,
                },
              });
            }
          }
        }

        // Delegate OCR text to ScamEngine
        if (ocrResult?.sanitizedText && ocrResult.sanitizedText.trim().length > 0) {
          await analyzeScamTextOnce(ocrResult.sanitizedText, 'ocr_text');
        }

        continue;
      }

      // 4C. Text & Document Attachments
      if (isTextAnalyzableAttachment(att)) {
        try {
          const loadedDoc = await loadAttachmentContent(att);
          contributingAnalyzers.add('document_loader');

          if (loadedDoc.type === 'code') {
            await analyzeCodeOnce(loadedDoc.content, loadedDoc.filename, 'attachment');
          } else {
            await analyzeScamTextOnce(loadedDoc.content, 'attachment');
            const docUrls = extractUrlsFromText(loadedDoc.content).slice(0, 5);
            for (const url of docUrls) {
              await analyzeUrlOnce(url, 'attachment_url');
            }
          }
        } catch (docErr: unknown) {
          errorsEncountered++;
          const docErrMsg = docErr instanceof Error ? docErr.message : 'Document load error';
          allLimitations.push(`Attachment "${att.original_name || 'document'}" could not be loaded: ${docErrMsg}`);
          allAnalyzerResults.push({
            analyzerId: `document-loader-${att.original_name || 'doc'}`,
            analyzerType: 'file',
            status: 'failed',
            confidence: 'low',
            findings: [],
            evidence: [],
            error: docErrMsg,
            limitations: [`Document retrieval failed: ${docErrMsg}`],
          });
        }
      }
    }

    // 5. Determine Dominant Input Type
    let dominantInputType: SafetyInputType = 'message';
    if (inputTypeHint) {
      dominantInputType = inputTypeHint;
    } else if (attachments.some(a => isImageAttachment(a))) {
      dominantInputType = 'image';
    } else if (classifiedType === 'code') {
      dominantInputType = 'code';
    } else if (classifiedType === 'url') {
      dominantInputType = 'url';
    } else if (attachments.some(a => isPdfAttachment(a) || isTextAnalyzableAttachment(a))) {
      dominantInputType = 'document';
    } else {
      dominantInputType = classifiedType || 'message';
    }

    // 6. Build the Unified Security Report
    // Passing findings and evidence to UnifiedReportBuilder automatically:
    // - Consolidates findings and evidence via Stage 8.2 FindingConsolidator
    // - Evaluates authoritative risk via RiskEngine (sole authority)
    // - Generates deterministic ID, primary concern, summary, and recommendations
    // - Applies privacy guarantees and deep analyzerResults sanitization
    const report = UnifiedReportBuilder.build({
      inputType: dominantInputType,
      findings: allFindings,
      evidence: allEvidence,
      analyzerResults: allAnalyzerResults,
      limitations: allLimitations,
      sourceContext,
      status: 'completed',
    });

    const durationMs = Date.now() - startTime;

    return {
      report,
      contributingAnalyzers: Array.from(contributingAnalyzers),
      executionStats: {
        durationMs,
        attachmentsProcessed: attachments.length,
        urlsAnalyzed,
        duplicateUrlsSkipped,
        errorsEncountered,
      },
    };
  }
}
