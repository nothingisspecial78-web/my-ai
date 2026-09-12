/**
 * Visual Authenticity & Manipulation Heuristics (Stage 7.5)
 * 
 * Deterministic structural inspection and safe metadata parsing to detect
 * possible synthetic-image indicators, photo manipulation tags, and metadata anomalies.
 * 
 * STRICT INVARIANTS:
 * 1. EPISTEMIC HUMILITY: Never claim that an image is definitely AI-generated or fake.
 *    Never claim that metadata proves authenticity.
 * 2. OBSERVATIONAL VOCABULARY: Use "possible manipulation indicators",
 *    "possible synthetic-image indicators", "metadata anomaly", "requires verification".
 * 3. PRIVACY GUARANTEE: GPS coordinates and device serial numbers are NEVER exposed
 *    or logged; coordinates are scrubbed.
 * 4. PURE DETERMINISTIC INSPECTION: Zero fetch, zero DNS, zero child_process, zero eval.
 * 5. SOLE SCORING AUTHORITY: RiskEngine is the sole authority on score and risk level.
 * 6. BOUNDED PERFORMANCE: Pure-JS buffer inspection capped to safe marker ceilings.
 */

import crypto from 'crypto';
import {
  Finding,
  Evidence,
  Recommendation,
  ConfidenceLevel,
} from '@/lib/safety/types';
import { LoadedImageContent } from '@/lib/attachments/loader';
import { redactSensitiveText } from '@/lib/safety/redaction';
import {
  SanitizedOcrResult,
  AuthenticitySignal,
  SanitizedMetadataSummary,
  SanitizedAuthenticityResult,
} from './types';

export interface AuthenticityOptions {
  skipMetadataScan?: boolean;
}

// Generative AI software markers in EXIF / XMP / PNG chunks
const AI_GENERATOR_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'DALL-E', pattern: /\b(?:dall[-\s]?e|dall[-\s]?e\s*[23])\b/i },
  { name: 'Midjourney', pattern: /\b(?:midjourney|midjourney\s*v\d+)\b/i },
  { name: 'Stable Diffusion', pattern: /\b(?:stable\s*diffusion|stablediffusion|sdxl|sd\s*[12]\.\d)\b/i },
  { name: 'Automatic1111 / ComfyUI', pattern: /\b(?:automatic1111|comfyui|invokeai|novelai|novel-ai)\b/i },
  { name: 'Adobe Firefly', pattern: /\b(?:adobe\s*firefly|firefly)\b/i },
  { name: 'Generative Model', pattern: /\b(?:bing\s*image\s*creator|craiyon|diffusers)\b/i },
];

// Parameter strings commonly embedded by generation web UIs
const AI_PARAMETER_PATTERNS = [
  /\b(?:steps:\s*\d+|sampler:\s*[\w+]+|cfg\s*scale:\s*[\d.]+|seed:\s*\d+)\b/i,
  /\b(?:model\s*hash:\s*[a-f0-9]+|denoising\s*strength:\s*[\d.]+)\b/i,
  /\bnegative\s*prompt:\s*[\w\s,]+/i,
];

// Photo manipulation software signatures
const PHOTO_MANIPULATION_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'Adobe Photoshop', pattern: /\b(?:adobe\s+photoshop|photoshop\s+(?:cc|cs\d*))\b/i },
  { name: 'GIMP', pattern: /\b(?:gimp|gnu\s+image\s+manipulation\s+program)\b/i },
  { name: 'Canva / Online Editor', pattern: /\b(?:canva|pixlr|affinity\s+photo|corel\s*paint)\b/i },
];

// Standard generative AI canvas resolutions (width x height)
const KNOWN_SYNTHETIC_RESOLUTIONS = new Set<string>([
  '512x512',
  '768x768',
  '1024x1024',
  '2048x2048',
  '1152x896',
  '896x1152',
  '1216x832',
  '832x1216',
  '1344x768',
  '768x1344',
  '1536x640',
  '640x1536',
]);

/**
 * Safely parses metadata and structural markers from JPEG image buffer.
 */
function parseJpegMetadata(buffer: Buffer): SanitizedMetadataSummary {
  const summary: SanitizedMetadataSummary = {
    hasExif: false,
    hasXmp: false,
    hasSoftwareTag: false,
    hasGpsData: false,
    dimensionsConsistent: true,
    suspiciousChunks: [],
  };

  if (!buffer || buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) {
    return summary;
  }

  let offset = 2;
  const maxScanLength = Math.min(buffer.length, 128 * 1024); // Scan up to first 128KB
  let dqtCount = 0;

  while (offset + 4 <= maxScanLength) {
    if (buffer[offset] !== 0xff) {
      break; // Corrupted marker boundary
    }

    const marker = buffer[offset + 1];
    // Stop scanning at Start of Scan (SOS) or End of Image (EOI)
    if (marker === 0xda || marker === 0xd9) {
      break;
    }

    const length = buffer.readUInt16BE(offset + 2);
    if (length < 2 || offset + 2 + length > buffer.length) {
      summary.suspiciousChunks.push(`Truncated or malformed JPEG marker (0xFF${marker.toString(16).toUpperCase()})`);
      break;
    }

    const markerData = buffer.subarray(offset + 4, offset + 2 + length);

    // APP1: EXIF or XMP
    if (marker === 0xe1) {
      const headerStr = markerData.subarray(0, 32).toString('latin1');
      if (headerStr.startsWith('Exif\0\0')) {
        summary.hasExif = true;
        scanExifStringContent(markerData, summary);
      } else if (headerStr.includes('http://ns.adobe.com/xap/1.0/')) {
        summary.hasXmp = true;
        scanXmpContent(markerData, summary);
      }
    }

    // COM: Comment marker
    if (marker === 0xfe) {
      const commentStr = markerData.toString('utf8', 0, Math.min(markerData.length, 2048));
      scanCommentContent(commentStr, summary);
    }

    // DQT: Define Quantization Table
    if (marker === 0xdb) {
      dqtCount++;
    }

    offset += 2 + length;
  }

  if (dqtCount > 4) {
    summary.suspiciousChunks.push(`Unusual number of quantization tables (${dqtCount} DQT markers)`);
  }

  return summary;
}

/**
 * Safely parses metadata chunks from PNG image buffer.
 */
function parsePngMetadata(buffer: Buffer): SanitizedMetadataSummary {
  const summary: SanitizedMetadataSummary = {
    hasExif: false,
    hasXmp: false,
    hasSoftwareTag: false,
    hasGpsData: false,
    dimensionsConsistent: true,
    suspiciousChunks: [],
  };

  if (
    !buffer ||
    buffer.length < 8 ||
    buffer[0] !== 0x89 ||
    buffer[1] !== 0x50 ||
    buffer[2] !== 0x4e ||
    buffer[3] !== 0x47
  ) {
    return summary;
  }

  let offset = 8;
  const maxOffset = Math.min(buffer.length, 128 * 1024);

  while (offset + 8 <= maxOffset) {
    const chunkLength = buffer.readUInt32BE(offset);
    const chunkType = buffer.toString('ascii', offset + 4, offset + 8);

    if (offset + 12 + chunkLength > buffer.length) {
      summary.suspiciousChunks.push(`Truncated PNG chunk (${chunkType})`);
      break;
    }

    const chunkData = buffer.subarray(offset + 8, offset + 8 + chunkLength);

    if (chunkType === 'tEXt' || chunkType === 'iTXt') {
      const text = chunkData.toString('latin1', 0, Math.min(chunkData.length, 4096));
      scanCommentContent(text, summary);
    } else if (chunkType === 'eXIf') {
      summary.hasExif = true;
      scanExifStringContent(chunkData, summary);
    }

    if (chunkType === 'IEND') {
      break;
    }

    offset += 12 + chunkLength;
  }

  return summary;
}

/**
 * Safely parses metadata from WEBP image buffer.
 */
function parseWebpMetadata(buffer: Buffer): SanitizedMetadataSummary {
  const summary: SanitizedMetadataSummary = {
    hasExif: false,
    hasXmp: false,
    hasSoftwareTag: false,
    hasGpsData: false,
    dimensionsConsistent: true,
    suspiciousChunks: [],
  };

  if (!buffer || buffer.length < 12) return summary;

  let offset = 12;
  const maxOffset = Math.min(buffer.length, 128 * 1024);

  while (offset + 8 <= maxOffset) {
    const chunkType = buffer.toString('ascii', offset, offset + 4);
    const chunkSize = buffer.readUInt32LE(offset + 4);

    if (offset + 8 + chunkSize > buffer.length) {
      if (chunkType === 'EXIF' || chunkType === 'XMP ') {
        summary.suspiciousChunks.push(`Truncated WEBP chunk (${chunkType.trim()})`);
      }
      break;
    }

    const chunkData = buffer.subarray(offset + 8, offset + 8 + chunkSize);

    if (chunkType === 'EXIF') {
      summary.hasExif = true;
      scanExifStringContent(chunkData, summary);
    } else if (chunkType === 'XMP ') {
      summary.hasXmp = true;
      scanXmpContent(chunkData, summary);
    }

    offset += 8 + chunkSize + (chunkSize % 2); // WEBP chunks are padded to even boundaries
  }

  return summary;
}

/**
 * Internal helper to scan ASCII/UTF-8 content of EXIF blocks.
 * Extracts software, cameras, dates, and scrubs GPS data.
 */
function scanExifStringContent(data: Buffer, summary: SanitizedMetadataSummary): void {
  const text = data.toString('latin1', 0, Math.min(data.length, 8192));

  // Check for GPS tags (GPSInfo, GPSLatitude, etc.)
  if (/\b(?:GPS|GPSLatitude|GPSLongitude|GPSPosition|GPSAltitude)\b/i.test(text)) {
    summary.hasGpsData = true;
  }

  // Check for AI software
  for (const sig of AI_GENERATOR_SIGNATURES) {
    if (sig.pattern.test(text)) {
      summary.hasSoftwareTag = true;
      summary.software = sig.name;
      break;
    }
  }

  // Check for Editing software
  if (!summary.software) {
    for (const edit of PHOTO_MANIPULATION_SIGNATURES) {
      if (edit.pattern.test(text)) {
        summary.hasSoftwareTag = true;
        summary.software = edit.name;
        break;
      }
    }
  }

  // Check for camera make
  const makeMatch = text.match(/\b(?:Canon|Nikon|Sony|Apple|Samsung|Google|Fujifilm|Panasonic|Olympus)\b/i);
  if (makeMatch) {
    summary.cameraMake = makeMatch[0];
  }

  // Check for future dates
  const dateMatch = text.match(/\b(20\d\d)[:\-](\d\d)[:\-](\d\d)\b/);
  if (dateMatch) {
    const year = parseInt(dateMatch[1], 10);
    const currentYear = new Date().getFullYear();
    if (year > currentYear + 1) {
      summary.suspiciousChunks.push(`Anomalous capture date in future (${dateMatch[0]})`);
    }
  }
}

/**
 * Internal helper to scan XMP XML content.
 */
function scanXmpContent(data: Buffer, summary: SanitizedMetadataSummary): void {
  const xml = data.toString('utf8', 0, Math.min(data.length, 8192));

  if (/\b(?:GPSLatitude|GPSLongitude|GPSPosition)\b/i.test(xml)) {
    summary.hasGpsData = true;
  }

  for (const sig of AI_GENERATOR_SIGNATURES) {
    if (sig.pattern.test(xml)) {
      summary.hasSoftwareTag = true;
      summary.software = sig.name;
      return;
    }
  }

  for (const edit of PHOTO_MANIPULATION_SIGNATURES) {
    if (edit.pattern.test(xml)) {
      summary.hasSoftwareTag = true;
      summary.software = edit.name;
      return;
    }
  }
}

/**
 * Internal helper to scan generic comment or text chunks.
 */
function scanCommentContent(text: string, summary: SanitizedMetadataSummary): void {
  for (const sig of AI_GENERATOR_SIGNATURES) {
    if (sig.pattern.test(text)) {
      summary.hasSoftwareTag = true;
      summary.software = sig.name;
      return;
    }
  }

  for (const param of AI_PARAMETER_PATTERNS) {
    if (param.test(text)) {
      summary.hasSoftwareTag = true;
      summary.software = 'Generative AI Parameters';
      return;
    }
  }

  for (const edit of PHOTO_MANIPULATION_SIGNATURES) {
    if (edit.pattern.test(text)) {
      summary.hasSoftwareTag = true;
      summary.software = edit.name;
      return;
    }
  }
}

/**
 * Primary entry point for Stage 7.5: Visual Authenticity & Manipulation Heuristics.
 */
export function analyzeVisualAuthenticity(
  loaded: LoadedImageContent,
  ocrResult?: SanitizedOcrResult,
  options?: AuthenticityOptions
): SanitizedAuthenticityResult {
  const findings: Finding[] = [];
  const evidence: Evidence[] = [];
  const recommendations: Recommendation[] = [];
  const signals: AuthenticitySignal[] = [];
  const limitations: string[] = [];

  // 1. Safe metadata extraction based on format
  let metadata: SanitizedMetadataSummary = {
    hasExif: false,
    hasXmp: false,
    hasSoftwareTag: false,
    hasGpsData: false,
    dimensionsConsistent: true,
    suspiciousChunks: [],
  };

  if (!options?.skipMetadataScan && loaded?.buffer) {
    try {
      if (loaded.format === 'jpeg') {
        metadata = parseJpegMetadata(loaded.buffer);
      } else if (loaded.format === 'png') {
        metadata = parsePngMetadata(loaded.buffer);
      } else if (loaded.format === 'webp') {
        metadata = parseWebpMetadata(loaded.buffer);
      }
    } catch {
      limitations.push('Image metadata inspection could not be completed deterministically.');
    }
  }

  // 2. Dimension and Aspect Ratio Inspection
  const width = loaded.width;
  const height = loaded.height;
  let matchesSyntheticCanvas = false;
  let resolutionString = '';

  if (typeof width === 'number' && typeof height === 'number') {
    resolutionString = `${width}x${height}`;
    if (KNOWN_SYNTHETIC_RESOLUTIONS.has(resolutionString)) {
      matchesSyntheticCanvas = true;
    }
  }

  // 3. Evaluate AI Generator Signatures (Synthetic Indicators)
  const hasAiSoftware = metadata.hasSoftwareTag && metadata.software && (
    AI_GENERATOR_SIGNATURES.some(s => s.name === metadata.software) ||
    metadata.software === 'Generative AI Parameters'
  );

  let hasSyntheticIndicators = Boolean(hasAiSoftware);

  if (hasAiSoftware) {
    signals.push({
      type: 'possible_ai_generated',
      findingType: 'possible_ai_generated',
      severity: 'medium',
      confidence: 'medium',
      title: 'Possible Synthetic or AI-Generated Image Indicators',
      description: `Image metadata includes software signatures or generation parameters associated with ${metadata.software}. This is an observational indicator; requires independent verification.`,
      evidenceSnippet: metadata.software,
      dedupKey: 'possible_ai_generated::software_signature',
    });
  } else if (matchesSyntheticCanvas && (ocrResult?.visualContext?.possibleManipulationCues?.length ?? 0) > 0) {
    // Dimension match correlated with visual layout cues
    hasSyntheticIndicators = true;
    signals.push({
      type: 'possible_ai_generated',
      findingType: 'possible_ai_generated',
      severity: 'low',
      confidence: 'low',
      title: 'Possible Synthetic Media Indicators (Resolution & Visual Artifacts)',
      description: `Image dimensions (${resolutionString}) match common generative model canvas sizes, accompanied by observed visual inconsistencies. This is an observational signal only.`,
      dedupKey: 'possible_ai_generated::dimension_correlation',
    });
  }

  // 4. Evaluate Image Manipulation & Editing Indicators
  const isPhotoEditor = metadata.hasSoftwareTag && metadata.software && PHOTO_MANIPULATION_SIGNATURES.some(s => s.name === metadata.software);
  const visualCues = ocrResult?.visualContext?.possibleManipulationCues || [];
  const hasManipulationIndicators = Boolean(isPhotoEditor || visualCues.length > 0);

  if (isPhotoEditor) {
    signals.push({
      type: 'possible_manipulation',
      findingType: 'possible_manipulation',
      severity: 'low',
      confidence: 'medium',
      title: 'Possible Image Modification Indicators',
      description: `Metadata indicates processing by digital editing software (${metadata.software}). Digital editing alone does not imply deceptive intent.`,
      evidenceSnippet: metadata.software,
      dedupKey: `possible_manipulation::editor_${metadata.software}`,
    });
  }

  if (visualCues.length > 0) {
    signals.push({
      type: 'possible_manipulation',
      findingType: 'possible_manipulation',
      severity: 'low',
      confidence: 'low',
      title: 'Potential Visual Inconsistencies Observed',
      description: `Visual inspection observed minor layout irregularities: ${visualCues.join(', ')}. Visual layout cues alone cannot confirm image manipulation.`,
      dedupKey: 'possible_manipulation::visual_cues',
    });
  }

  // 5. Evaluate Inconsistent Metadata or Structural Anomalies
  // E.g. Camera profile present alongside generative AI software tag
  if (metadata.cameraMake && hasAiSoftware) {
    signals.push({
      type: 'metadata_anomaly',
      findingType: 'metadata_anomaly',
      severity: 'medium',
      confidence: 'medium',
      title: 'Inconsistent Image Metadata Profile',
      description: `Image metadata declares physical camera hardware (${metadata.cameraMake}) alongside generative AI software markers (${metadata.software}).`,
      dedupKey: 'metadata_anomaly::conflicting_hardware_software',
    });
  }

  // Chunks flagged as suspicious/truncated/future dates
  for (const anomaly of metadata.suspiciousChunks) {
    signals.push({
      type: 'metadata_anomaly',
      findingType: 'metadata_anomaly',
      severity: 'medium',
      confidence: 'medium',
      title: 'Image Metadata Structure Anomaly',
      description: anomaly,
      dedupKey: `metadata_anomaly::${anomaly.slice(0, 40)}`,
    });
  }

  // 6. Privacy Protection: GPS Metadata Handling
  if (metadata.hasGpsData) {
    signals.push({
      type: 'metadata_anomaly',
      findingType: 'metadata_anomaly',
      severity: 'info',
      confidence: 'medium',
      title: 'GPS Geolocation Metadata Present (Coordinates Redacted)',
      description: 'Image metadata contains embedded GPS coordinate markers. Geolocation coordinates have been redacted to protect user privacy.',
      dedupKey: 'metadata_anomaly::gps_privacy_protection',
    });

    recommendations.push({
      action: 'proceed_with_caution',
      title: 'Review Geolocation Privacy Before Sharing',
      description: 'Consider stripping embedded GPS location tags before sharing personal images publicly.',
      priority: 'low',
    });
  }

  // 7. Deduplicate signals by dedupKey
  const uniqueSignalMap = new Map<string, AuthenticitySignal>();
  for (const sig of signals) {
    if (!uniqueSignalMap.has(sig.dedupKey)) {
      uniqueSignalMap.set(sig.dedupKey, sig);
    }
  }
  const deduplicatedSignals = Array.from(uniqueSignalMap.values());

  // 8. Build Evidence Object (when metadata or signals are present)
  const hasInterestingMetadata =
    deduplicatedSignals.length > 0 ||
    metadata.hasExif ||
    metadata.hasXmp ||
    metadata.hasSoftwareTag ||
    metadata.hasGpsData ||
    Boolean(metadata.cameraMake) ||
    metadata.suspiciousChunks.length > 0;

  let evidenceId: string | undefined;

  if (hasInterestingMetadata) {
    evidenceId = crypto.randomUUID();
    const now = new Date().toISOString();

    evidence.push({
      id: evidenceId,
      sourceType: 'image_analysis',
      sourceName: 'Authenticity & Manipulation Heuristics (Stage 7.5)',
      label: 'Image Authenticity & Structure Inspection',
      description: deduplicatedSignals.length > 0
        ? `Identified ${deduplicatedSignals.length} structural or authenticity observation${deduplicatedSignals.length === 1 ? '' : 's'}.${metadata.software ? ` Software tag: ${metadata.software}.` : ''}${metadata.hasGpsData ? ' GPS markers present (redacted).' : ''}`
        : 'Metadata inspection completed with no manipulation or synthetic markers detected.',
      data: {
        hasExif: metadata.hasExif,
        hasXmp: metadata.hasXmp,
        hasSoftwareTag: metadata.hasSoftwareTag,
        software: metadata.software,
        cameraMake: metadata.cameraMake,
        hasGpsData: metadata.hasGpsData,
        resolution: resolutionString || null,
        matchesSyntheticCanvas,
        suspiciousChunks: metadata.suspiciousChunks,
        visualCues,
      },
      isAiGenerated: false,
      createdAt: now,
    });
  }

  // 9. Build Findings from signals
  for (const sig of deduplicatedSignals) {
    findings.push({
      id: crypto.randomUUID(),
      type: sig.findingType,
      severity: sig.severity,
      title: sig.title,
      description: sig.description,
      confidence: sig.confidence as ConfidenceLevel,
      evidenceIds: evidenceId ? [evidenceId] : [],
      metadata: {
        signalType: sig.type,
        evidenceSnippet: sig.evidenceSnippet ? redactSensitiveText(sig.evidenceSnippet) : undefined,
      },
    });
  }

  // 10. Build Proportional Recommendations
  if (hasSyntheticIndicators) {
    recommendations.push({
      action: 'proceed_with_caution',
      title: 'Verify Authenticity of Visual Media',
      description: 'If this image is presented as factual or photojournalistic evidence, seek corroborating photographic sources or raw original camera files.',
      priority: 'medium',
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      action: 'proceed_with_caution',
      title: 'Standard Digital Vigilance',
      description: deduplicatedSignals.length > 0
        ? 'Review image provenance carefully before relying on visual evidence.'
        : 'No manipulation or synthetic image markers were identified. Note that absence of metadata is common and not proof of authenticity.',
      priority: 'low',
    });
  }

  // 11. Epistemic Limitations
  if (!metadata.hasExif && !metadata.hasXmp) {
    limitations.push(
      'No embedded EXIF or XMP metadata found; absence of metadata is common in web-optimized images and is not an indicator of manipulation.'
    );
  }

  limitations.push(
    'Authenticity heuristics analyze observable metadata, dimensions, and layout. They do not constitute definitive proof of human or synthetic origin.'
  );

  const status: SanitizedAuthenticityResult['status'] =
    deduplicatedSignals.some(s => s.severity === 'medium') ? 'suspicious' : 'clean';

  return {
    status,
    hasSyntheticIndicators,
    hasManipulationIndicators,
    signals: deduplicatedSignals,
    findings,
    evidence,
    metadataSummary: metadata,
    recommendations,
    limitations,
  };
}
