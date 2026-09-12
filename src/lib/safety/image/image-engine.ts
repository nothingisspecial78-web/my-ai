import crypto from 'crypto';
import { Attachment } from '@/lib/ai/types';
import {
  SafetyReport,
  Finding,
  Evidence,
  Recommendation,
  AnalyzerResult,
} from '@/lib/safety/types';
import { loadImageContent, isImageAttachment, LoadedImageContent } from '@/lib/attachments/loader';
import { UrlIntelligenceEngine } from '@/lib/safety/url';
import { ScamEngine, ScamAnalysisResult } from '@/lib/safety/scam';
import { RiskEngine } from '@/lib/safety/risk-engine';
import {
  ImageEngineResult,
  SanitizedOcrResult,
  SanitizedQrAnalysisResult,
  SanitizedVisualScamResult,
  SanitizedAuthenticityResult,
} from './types';
import { extractVisualOcr, OcrOptions } from './ocr';
import { analyzeImageQrCodes } from './qr';
import { analyzeVisualScamSignals } from './scam';
import { analyzeVisualAuthenticity } from './authenticity';

// Constants for Stage 7.1 dimension safety limits
export const MAX_SAFE_IMAGE_DIMENSION = 16384; // 16K pixels max per side
export const MAX_SAFE_IMAGE_PIXELS = 64_000_000; // 64 megapixels decompression ceiling

export interface ImageAnalysisOptions extends OcrOptions {
  cloudName?: string;
  skipOcr?: boolean;
  skipQr?: boolean;
  skipScam?: boolean;
  skipAuthenticity?: boolean;
}


export class ImageEngine {
  /**
   * Primary entry point for analyzing an image attachment.
   * Produces a fully normalized SafetyReport conforming to RiskEngine and UI contracts.
   */
  async analyzeAttachment(
    attachment: Attachment,
    options?: ImageAnalysisOptions
  ): Promise<SafetyReport> {
    const filename = attachment?.original_name || 'image';
    const analysisId = crypto.randomUUID();
    const now = new Date().toISOString();

    // 1. Validate attachment presence
    if (!attachment) {
      return this.buildFailedReport(
        analysisId,
        filename,
        'No image attachment provided for analysis.',
        now
      );
    }

    // 2. Validate attachment classification
    if (!isImageAttachment(attachment)) {
      return this.buildFailedReport(
        analysisId,
        filename,
        `Attachment "${filename}" is not a recognized or supported image format (JPEG, PNG, WEBP).`,
        now
      );
    }

    // 3. Load image content safely via bounded reader
    let loaded: LoadedImageContent;
    try {
      loaded = await loadImageContent(attachment, options);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown image retrieval error';
      return this.buildFailedReport(
        analysisId,
        filename,
        `Image "${filename}" could not be retrieved or validated: ${errorMsg}`,
        now,
        errorMsg
      );
    }

    // 4. Perform Stage 7.1 deterministic structural analysis
    const structuralResult = this.evaluateLoadedImage(loaded, filename);

    const allFindings: Finding[] = [...structuralResult.findings];
    const allEvidence: Evidence[] = [...structuralResult.evidence];
    const allRecommendations: Recommendation[] = [...structuralResult.recommendations];
    const allLimitations: string[] = [...structuralResult.limitations];
    const analyzerResults: AnalyzerResult[] = [
      {
        analyzerId: 'image-engine-7.1',
        analyzerType: 'image',
        status: structuralResult.status === 'completed' ? 'success' : 'failed',
        confidence: structuralResult.confidenceLevel,
        findings: structuralResult.findings,
        evidence: structuralResult.evidence,
        limitations: structuralResult.limitations,
      },
    ];

    let ocrResult: SanitizedOcrResult | undefined;
    const isOcrConfigured = !options?.skipOcr && Boolean(process.env.GEMINI_API_KEY?.trim() || options?.apiKey || options?.client);

    let precomputedScamResult: ScamAnalysisResult | undefined;

    // 5. Stage 7.2: Structured Visual OCR & Visual Context Extraction
    if (isOcrConfigured) {
      try {
        ocrResult = await extractVisualOcr(loaded, options);

        if (ocrResult.status === 'unavailable') {
          if (ocrResult.limitations.length > 0) {
            allLimitations.push(...ocrResult.limitations);
          } else {
            allLimitations.push('Visual OCR extraction was unavailable or timed out.');
          }
        } else {
          // Record OCR extraction evidence
          allEvidence.push({
            id: crypto.randomUUID(),
            sourceType: 'image_analysis',
            sourceName: 'Gemini Vision OCR (Stage 7.2)',
            label: 'Visual Text & Layout Extraction',
            description: ocrResult.hasText
              ? `Extracted ${ocrResult.lineCount} line${ocrResult.lineCount === 1 ? '' : 's'} (${ocrResult.characterCount} chars)${ocrResult.truncated ? ' [truncated]' : ''}.${ocrResult.visualContext.isScreenshot ? ' Layout exhibits screenshot characteristics.' : ''}${ocrResult.visualContext.detectedAppType ? ` Detected UI style: ${ocrResult.visualContext.detectedAppType}.` : ''}`
              : 'No readable alphanumeric text detected in visual media.',
            data: {
              hasText: ocrResult.hasText,
              characterCount: ocrResult.characterCount,
              lineCount: ocrResult.lineCount,
              truncated: ocrResult.truncated,
              isScreenshot: ocrResult.visualContext.isScreenshot,
              detectedAppType: ocrResult.visualContext.detectedAppType,
              suspiciousVisualCues: ocrResult.visualContext.suspiciousVisualCues,
              possibleManipulationCues: ocrResult.visualContext.possibleManipulationCues,
              extractedUrls: ocrResult.extractedUrls,
            },
            snippet: ocrResult.hasText ? ocrResult.sanitizedText.slice(0, 200) : undefined,
            isAiGenerated: true,
            createdAt: now,
          });

          // 6. Delegate Extracted URLs to Phase 6.1 URL Intelligence Engine
          if (ocrResult.extractedUrls.length > 0) {
            for (const url of ocrResult.extractedUrls) {
              try {
                const urlRes = await UrlIntelligenceEngine.analyze(url);
                for (const f of urlRes.findings) {
                  allFindings.push(f);
                }
                for (const e of urlRes.evidence) {
                  allEvidence.push(e);
                }
                for (const l of urlRes.limitations) {
                  if (!allLimitations.includes(l)) allLimitations.push(l);
                }
                analyzerResults.push({
                  analyzerId: `url-intelligence-ocr-${url}`,
                  analyzerType: 'url',
                  status: 'success',
                  confidence: urlRes.confidence,
                  findings: urlRes.findings,
                  evidence: urlRes.evidence,
                  limitations: urlRes.limitations,
                });
              } catch {
                // Safe tolerance: URL provider failure does not abort image analysis
              }
            }
          }

          // 7. Delegate Sanitized OCR Text to Phase 6.2 ScamEngine
          if (ocrResult.hasText && ocrResult.sanitizedText.trim().length > 0) {
            try {
              const scamRes = await ScamEngine.analyze(ocrResult.sanitizedText);
              precomputedScamResult = scamRes;
              for (const f of scamRes.findings) {
                // Deduplicate with existing findings
                if (!allFindings.some(existing => existing.type === f.type && existing.title === f.title)) {
                  allFindings.push(f);
                }
              }
              for (const e of scamRes.evidence) {
                allEvidence.push(e);
              }
              for (const r of scamRes.recommendations) {
                allRecommendations.push(r);
              }
              for (const l of scamRes.limitations) {
                if (!allLimitations.includes(l)) allLimitations.push(l);
              }
              analyzerResults.push({
                analyzerId: 'scam-engine-ocr',
                analyzerType: 'scam',
                status: 'success',
                confidence: scamRes.confidence,
                findings: scamRes.findings,
                evidence: scamRes.evidence,
                limitations: scamRes.limitations,
              });
            } catch {
              // Safe tolerance: ScamEngine failure does not abort image analysis
            }
          }
        }
      } catch (ocrErr: unknown) {
        const errorMsg = ocrErr instanceof Error ? ocrErr.message : 'OCR failure';
        allLimitations.push(`Visual OCR extraction was unavailable: ${errorMsg}`);
      }
    }

    // 8. Stage 7.3: Pure-JS QR Intelligence & Quishing Defense
    let qrAnalysisResult: SanitizedQrAnalysisResult | undefined;
    if (!options?.skipQr) {
      try {
        const qrAnalysis = await analyzeImageQrCodes(loaded);
        qrAnalysisResult = qrAnalysis.qrResult;

        for (const f of qrAnalysis.findings) {
          if (!allFindings.some(existing => existing.type === f.type && existing.title === f.title)) {
            allFindings.push(f);
          }
        }
        for (const e of qrAnalysis.evidence) {
          allEvidence.push(e);
        }
        for (const l of qrAnalysis.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }

        // Delegate QR URLs to Phase 6.1 (deduplicating with any OCR extracted URLs)
        const existingAnalyzedUrls = new Set<string>(ocrResult?.extractedUrls || []);
        for (const url of qrAnalysis.qrResult.delegatedUrls) {
          if (existingAnalyzedUrls.has(url)) continue;
          existingAnalyzedUrls.add(url);
          try {
            const urlRes = await UrlIntelligenceEngine.analyze(url);

            // Quishing Detection: if destination is high or critical, flag quishing finding
            if (urlRes.riskLevel === 'critical' || urlRes.riskLevel === 'high') {
              allFindings.push({
                id: crypto.randomUUID(),
                type: 'phishing_indicator',
                severity: urlRes.riskLevel,
                confidence: 'high',
                title: 'Quishing (QR Phishing) Detected',
                description: `QR code resolves to a high-risk or malicious web destination: ${urlRes.verdict}`,
              });
            }

            for (const f of urlRes.findings) {
              if (!allFindings.some(existing => existing.type === f.type && existing.title === f.title)) {
                allFindings.push(f);
              }
            }
            for (const e of urlRes.evidence) {
              allEvidence.push(e);
            }
            for (const l of urlRes.limitations) {
              if (!allLimitations.includes(l)) allLimitations.push(l);
            }
            analyzerResults.push({
              analyzerId: `url-intelligence-qr-${url}`,
              analyzerType: 'url',
              status: 'success',
              confidence: urlRes.confidence,
              findings: urlRes.findings,
              evidence: urlRes.evidence,
              limitations: urlRes.limitations,
            });
          } catch {
            // Safe tolerance: URL provider failure does not abort image analysis
          }
        }

        if (qrAnalysis.qrResult.detectedCount > 0) {
          analyzerResults.push({
            analyzerId: 'image-engine-7.3-qr',
            analyzerType: 'image',
            status: 'success',
            confidence: 'high',
            findings: qrAnalysis.findings,
            evidence: qrAnalysis.evidence,
            limitations: qrAnalysis.limitations,
          });
        }
      } catch (qrErr: unknown) {
        const errorMsg = qrErr instanceof Error ? qrErr.message : 'QR analysis error';
        allLimitations.push(`QR code detection was unavailable: ${errorMsg}`);
      }
    }

    // 9. Stage 7.4: Scam Screenshot & Visual Fraud Intelligence
    let visualScamResult: SanitizedVisualScamResult | undefined;
    if (!options?.skipScam) {
      try {
        visualScamResult = await analyzeVisualScamSignals(
          loaded,
          ocrResult,
          qrAnalysisResult,
          { scamResult: precomputedScamResult }
        );

        for (const f of visualScamResult.findings) {
          if (!allFindings.some(existing => existing.type === f.type && existing.title === f.title)) {
            allFindings.push(f);
          }
        }
        for (const e of visualScamResult.evidence) {
          allEvidence.push(e);
        }
        for (const r of visualScamResult.recommendations) {
          allRecommendations.push(r);
        }
        for (const l of visualScamResult.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }

        if (visualScamResult.signals.length > 0 || visualScamResult.isScreenshot) {
          analyzerResults.push({
            analyzerId: 'image-engine-7.4-scam',
            analyzerType: 'scam',
            status: 'success',
            confidence: visualScamResult.signals.some(s => s.severity === 'critical' || s.severity === 'high')
              ? 'high'
              : 'medium',
            findings: visualScamResult.findings,
            evidence: visualScamResult.evidence,
            limitations: visualScamResult.limitations,
          });
        }
      } catch (scamErr: unknown) {
        const errorMsg = scamErr instanceof Error ? scamErr.message : 'Visual scam analysis error';
        allLimitations.push(`Visual scam analysis was unavailable: ${errorMsg}`);
      }
    }

    // 10. Stage 7.5: Visual Authenticity & Manipulation Heuristics
    let authenticityResult: SanitizedAuthenticityResult | undefined;
    if (!options?.skipAuthenticity) {
      try {
        authenticityResult = analyzeVisualAuthenticity(
          loaded,
          ocrResult,
          { skipMetadataScan: false }
        );

        for (const f of authenticityResult.findings) {
          if (!allFindings.some(existing => existing.type === f.type && existing.title === f.title)) {
            allFindings.push(f);
          }
        }
        for (const e of authenticityResult.evidence) {
          allEvidence.push(e);
        }
        for (const r of authenticityResult.recommendations) {
          allRecommendations.push(r);
        }
        for (const l of authenticityResult.limitations) {
          if (!allLimitations.includes(l)) allLimitations.push(l);
        }

        if (authenticityResult.signals.length > 0) {
          analyzerResults.push({
            analyzerId: 'image-engine-7.5-authenticity',
            analyzerType: 'image_ai',
            status: 'success',
            confidence: authenticityResult.signals.some(s => s.confidence === 'medium') ? 'medium' : 'low',
            findings: authenticityResult.findings,
            evidence: authenticityResult.evidence,
            limitations: authenticityResult.limitations,
          });
        }
      } catch (authErr: unknown) {
        const errorMsg = authErr instanceof Error ? authErr.message : 'Authenticity analysis error';
        allLimitations.push(`Authenticity inspection was unavailable: ${errorMsg}`);
      }
    }

    // 11. Authoritative Deterministic Scoring & Risk Level via RiskEngine
    const evaluation = RiskEngine.evaluate(allFindings, analyzerResults);

    // Deduplicate recommendations by title
    const seenTitles = new Set<string>();
    const uniqueRecommendations = allRecommendations.filter(r => {
      if (seenTitles.has(r.title)) return false;
      seenTitles.add(r.title);
      return true;
    });

    // Deduplicate limitations
    const uniqueLimitations = Array.from(new Set(allLimitations));

    // Determine calibrated summary
    let summary: string;
    if (allFindings.length > 0) {
      const topFinding = allFindings.find(f => f.severity === 'critical')
        || allFindings.find(f => f.severity === 'high')
        || allFindings.find(f => f.severity === 'medium')
        || allFindings[0];

      summary = `Visual media analysis detected ${allFindings.length} security finding${allFindings.length > 1 ? 's' : ''}: ${topFinding.title}.`;
    } else if (qrAnalysisResult && qrAnalysisResult.detectedCount > 0) {
      summary = `Image inspection and QR decoding completed with no security threats detected (${qrAnalysisResult.detectedCount} QR code${qrAnalysisResult.detectedCount === 1 ? '' : 's'}).`;
    } else if (ocrResult?.status === 'unavailable') {
      summary = 'Image inspection completed with no structural issues detected. Visual text extraction was unavailable.';
    } else if (ocrResult?.hasText) {
      summary = 'Visual inspection and text extraction completed with no security threats detected.';
    } else if (ocrResult?.status === 'empty') {
      summary = 'Image inspection completed with no Stage 7.2 structural or textual issues detected.';
    } else {
      summary = 'Image inspection completed with no Stage 7.1 structural issues detected.';
    }


    return {
      analysisId,
      inputType: 'image',
      status: 'completed',
      riskLevel: evaluation.riskLevel,
      confidenceLevel: ocrResult?.status === 'unavailable' && allFindings.length === 0
        ? 'low'
        : (isOcrConfigured ? evaluation.confidenceLevel : structuralResult.confidenceLevel),
      score: evaluation.score,
      summary,
      findings: allFindings,
      evidence: allEvidence,
      recommendations: uniqueRecommendations.length > 0 ? uniqueRecommendations : evaluation.recommendations,
      limitations: uniqueLimitations,
      analyzerResults,
      createdAt: now,
    };
  }

  /**
   * Internal pure evaluator for loaded image buffer metadata.
   */
  evaluateLoadedImage(loaded: LoadedImageContent, filename: string): ImageEngineResult {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const recommendations: Recommendation[] = [];
    const limitations: string[] = [
      'Stage 7.1 foundation scan: visual OCR, QR decoding, and semantic scam analysis are scheduled for subsequent stages.',
      'Absence of structural flags is not an endorsement of authenticity or safety.',
    ];

    let isDecompressionRisk = false;
    const width = loaded.width;
    const height = loaded.height;

    // Check dimensions if available
    if (width !== undefined && height !== undefined) {
      const totalPixels = width * height;
      if (
        width > MAX_SAFE_IMAGE_DIMENSION ||
        height > MAX_SAFE_IMAGE_DIMENSION ||
        totalPixels > MAX_SAFE_IMAGE_PIXELS
      ) {
        isDecompressionRisk = true;
        findings.push({
          id: crypto.randomUUID(),
          type: 'metadata_anomaly',
          severity: 'medium',
          title: 'Excessive Image Dimensions (Potential Decompression Risk)',
          description: `Image declares extreme dimensions (${width}x${height}, ${Math.round(totalPixels / 1_000_000)}MP), which may cause memory exhaustion or decompression failure.`,
          confidence: 'high',
          metadata: {
            width,
            height,
            totalPixels,
            format: loaded.format,
          },
        });
        recommendations.push({
          action: 'proceed_with_caution',
          title: 'Handle Large Media With Care',
          description: 'This image has unusually large dimensions that could lead to client or server memory strain.',
          priority: 'medium',
        });
      }
    } else {
      limitations.push('Image dimensions could not be deterministically determined from image header markers.');
    }

    // Evidence object with safe metadata
    evidence.push({
      id: crypto.randomUUID(),
      sourceType: 'image_analysis',
      sourceName: 'ImageEngine (Stage 7.1 Foundation)',
      description: `Loaded image format: ${loaded.format.toUpperCase()}, Size: ${Math.round(loaded.rawSizeBytes / 1024)} KB${width && height ? `, Dimensions: ${width}x${height}` : ''}.`,
      data: {
        filename,
        format: loaded.format,
        mimeType: loaded.mimeType,
        sizeBytes: loaded.rawSizeBytes,
        width: width ?? null,
        height: height ?? null,
        magicBytesValid: loaded.magicBytesValid,
        isDecompressionRisk,
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    const hasFindings = findings.length > 0;
    const riskLevel = hasFindings ? 'medium' : 'low';
    const score = hasFindings ? 10 : 0;
    const confidenceLevel = 'medium';

    const summary = hasFindings
      ? `Structural analysis detected potential anomalies in attached image "${filename}".`
      : 'Image inspection completed with no Stage 7.1 structural issues detected.';

    return {
      status: 'completed',
      riskLevel,
      confidenceLevel,
      score,
      summary,
      findings,
      evidence,
      recommendations,
      limitations,
      metadata: {
        filename,
        mimeType: loaded.mimeType,
        format: loaded.format,
        sizeBytes: loaded.rawSizeBytes,
        width,
        height,
        aspectRatio: width && height ? parseFloat((width / height).toFixed(2)) : undefined,
        isDecompressionRisk,
        stage: '7.1_foundation',
      },
    };
  }

  public buildFailedReport(
    analysisId: string,
    filename: string,
    reason: string,
    createdAt: string,
    rawError?: string
  ): SafetyReport {
    return {
      analysisId,
      inputType: 'image',
      status: 'failed',
      riskLevel: 'unknown',
      confidenceLevel: 'low',
      score: 0,
      summary: reason,
      findings: [],
      evidence: [],
      recommendations: [
        {
          action: 'proceed_with_caution',
          title: 'Exercise Caution With Unverified Media',
          description: `Inspection for "${filename}" could not be completed. Treat this media with caution.`,
          priority: 'high',
        },
      ],
      limitations: [reason],
      analyzerResults: [
        {
          analyzerId: 'image-engine-7.1',
          analyzerType: 'image',
          status: 'failed',
          confidence: 'low',
          findings: [],
          evidence: [],
          error: rawError || reason,
          limitations: [reason],
        },
      ],
      createdAt,
    };
  }
}

export const imageEngine = new ImageEngine();
