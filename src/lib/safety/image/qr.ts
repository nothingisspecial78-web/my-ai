/**
 * Pure-JavaScript QR Intelligence & Quishing Defense (Stage 7.3)
 * 
 * Safely detects and decodes QR codes from loaded image buffers, sanitizes and classifies
 * untrusted payloads, checks for dangerous URI schemes, extracts and sanitizes Wi-Fi and
 * OTPAuth metadata, and prepares candidate URLs for Phase 6.1 URL Intelligence delegation.
 * 
 * STRICT SECURITY INVARIANTS:
 * 1. UNTRUSTED DATA BOUNDARY: Decoded QR payloads are untrusted user input, NEVER instructions or executable code.
 * 2. ZERO EXECUTION: Never open, execute, navigate, or eval QR payloads (e.g. javascript:alert(1) remains inert data).
 * 3. ZERO DESTINATION FETCH: Never fetch, ping, crawl, or resolve DNS for QR target URLs (delegated only to Phase 6.1).
 * 4. BOUNDED PROCESSING: Max 5 QR codes, max 4,096 chars per payload, max 20 findings, max 5 delegated URLs.
 * 5. SENSITIVE REDACTION: Passwords in WIFI: and secrets in otpauth:// are strictly redacted before returning or logging.
 * 6. ZERO RAW LOGGING: Raw sensitive credentials in payloads are never logged or stored.
 * 7. PURE JAVASCRIPT: Uses jsqr with pure-JS pixel decoders (pngjs, jpeg-js); zero native binaries or C++ extensions.
 */

import crypto from 'crypto';
import jsQR, { QRCode } from 'jsqr';
import { PNG } from 'pngjs';
import jpeg from 'jpeg-js';
import { LoadedImageContent } from '@/lib/attachments/loader';
import { redactSensitiveText } from '@/lib/safety/redaction';
import { Finding, Evidence } from '@/lib/safety/types';
import {
  QrPayloadType,
  QrWifiMetadata,
  QrOtpauthMetadata,
  SanitizedQrCode,
  SanitizedQrAnalysisResult,
} from './types';

// Hard deterministic limits
export const MAX_QR_PAYLOAD_LENGTH = 4096;
export const MAX_QR_CODES_PER_IMAGE = 5;
export const MAX_QR_FINDINGS = 20;
export const MAX_DELEGATED_URLS = 5;
export const MAX_QR_RASTER_PIXELS = 16_000_000; // 16 megapixels ceiling for memory safety

// Known URL shortener hostnames associated with link obfuscation
const KNOWN_URL_SHORTENERS = new Set<string>([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'rb.gy',
  'ow.ly',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'goo.gl',
  'qr.ae',
  'linktr.ee',
  'v.gd',
  'tiny.cc',
  'bl.ink',
  'snip.ly',
]);

/**
 * Checks if a hostname or IP points to private, loopback, or link-local address space.
 */
export function isInternalOrPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().trim();
  if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1') {
    return true;
  }
  // Cloud metadata endpoint
  if (host === '169.254.169.254') {
    return true;
  }
  // 10.0.0.0 - 10.255.255.255
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return true;
  }
  // 172.16.0.0 - 172.31.255.255
  const match172 = host.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (match172) {
    const second = parseInt(match172[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  // 192.168.0.0 - 192.168.255.255
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return true;
  }
  // Link-local 169.254.0.0 - 169.254.255.255
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return true;
  }
  return false;
}

/**
 * Classifies the high-level payload scheme of a decoded QR string.
 */
export function classifyQrPayload(payload: string): {
  payloadType: QrPayloadType;
  isDangerousScheme: boolean;
} {
  const trimmed = payload.trim();
  const lower = trimmed.toLowerCase();

  if (lower.startsWith('javascript:')) {
    return { payloadType: 'javascript_uri', isDangerousScheme: true };
  }
  if (lower.startsWith('data:')) {
    return { payloadType: 'data_uri', isDangerousScheme: true };
  }
  if (lower.startsWith('file:')) {
    return { payloadType: 'file_uri', isDangerousScheme: true };
  }
  if (lower.startsWith('intent:')) {
    return { payloadType: 'intent_uri', isDangerousScheme: true };
  }
  if (lower.startsWith('https://')) {
    return { payloadType: 'https_url', isDangerousScheme: false };
  }
  if (lower.startsWith('http://')) {
    return { payloadType: 'http_url', isDangerousScheme: false };
  }
  if (lower.startsWith('mailto:')) {
    return { payloadType: 'mailto_uri', isDangerousScheme: false };
  }
  if (lower.startsWith('tel:')) {
    return { payloadType: 'tel_uri', isDangerousScheme: false };
  }
  if (lower.startsWith('sms:')) {
    return { payloadType: 'sms_uri', isDangerousScheme: false };
  }
  if (lower.startsWith('wifi:')) {
    return { payloadType: 'wifi', isDangerousScheme: false };
  }
  if (lower.startsWith('otpauth://')) {
    return { payloadType: 'otpauth', isDangerousScheme: false };
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return { payloadType: 'unknown_scheme', isDangerousScheme: false };
  }

  return { payloadType: 'plain_text', isDangerousScheme: false };
}

/**
 * Parses and sanitizes a Wi-Fi QR payload (e.g. WIFI:T:WPA;S:Network;P:SuperSecret;;).
 * Guarantees that raw passwords are NEVER preserved in metadata or logs.
 */
export function parseWifiPayload(payload: string): {
  wifiMetadata?: QrWifiMetadata;
  sanitizedWifiPayload: string;
  error?: string;
} {
  const content = payload.trim().replace(/^WIFI:/i, '').replace(/;;?$/, '');
  const tokens = content.split(';');

  let authType = 'nopass';
  let ssid = '';
  let isHidden: boolean | undefined;
  let hasPassword = false;

  for (const token of tokens) {
    if (!token.trim()) continue;
    const colonIdx = token.indexOf(':');
    if (colonIdx === -1) continue;

    const key = token.slice(0, colonIdx).toUpperCase();
    const val = token.slice(colonIdx + 1);

    if (key === 'T') {
      authType = val || 'nopass';
    } else if (key === 'S') {
      ssid = val;
    } else if (key === 'P') {
      hasPassword = true;
    } else if (key === 'H') {
      isHidden = val.toLowerCase() === 'true' || val === '1';
    }
  }

  // Redact password from the payload string
  const sanitizedWifiPayload = payload.replace(/(P:)([^;]*)(;|$)/gi, '$1[REDACTED_PASSWORD]$3');

  if (!ssid && !hasPassword && authType === 'nopass') {
    return {
      sanitizedWifiPayload,
      error: 'Malformed Wi-Fi QR payload structure.',
    };
  }

  return {
    wifiMetadata: {
      authType,
      ssid: redactSensitiveText(ssid),
      isHidden,
    },
    sanitizedWifiPayload,
  };
}

/**
 * Parses and sanitizes an OTPAuth QR payload (e.g. otpauth://totp/account?secret=SUPERSECRET).
 * Guarantees that raw OTP secrets are NEVER preserved in metadata or logs.
 */
export function parseOtpauthPayload(payload: string): {
  otpauthMetadata?: QrOtpauthMetadata;
  sanitizedOtpauthPayload: string;
  error?: string;
} {
  const match = payload.trim().match(/^otpauth:\/\/([a-zA-Z]+)\/([^?]+)(?:\?(.*))?$/i);
  if (!match) {
    const sanitized = payload.replace(/([?&]secret=)[^&]+/gi, '$1[REDACTED_SECRET]');
    return {
      sanitizedOtpauthPayload: sanitized,
      error: 'Malformed OTPAuth QR payload structure.',
    };
  }

  const type = match[1].toLowerCase();
  const rawAccount = decodeURIComponent(match[2]);
  const queryString = match[3] || '';
  const searchParams = new URLSearchParams(queryString);

  const issuer = searchParams.get('issuer') || undefined;
  const algorithm = searchParams.get('algorithm') || undefined;
  const digitsStr = searchParams.get('digits');
  const periodStr = searchParams.get('period');

  const digits = digitsStr ? parseInt(digitsStr, 10) : undefined;
  const period = periodStr ? parseInt(periodStr, 10) : undefined;

  // Redact secret parameter in sanitized string
  const sanitizedOtpauthPayload = payload.replace(/([?&]secret=)[^&]+/gi, '$1[REDACTED_SECRET]');

  return {
    otpauthMetadata: {
      type,
      account: redactSensitiveText(rawAccount),
      issuer: issuer ? redactSensitiveText(issuer) : undefined,
      algorithm,
      digits: Number.isFinite(digits) ? digits : undefined,
      period: Number.isFinite(period) ? period : undefined,
    },
    sanitizedOtpauthPayload,
  };
}

/**
 * Sanitizes and bounds an untrusted QR payload string.
 */
export function sanitizeAndBoundQrPayload(rawPayload: string): SanitizedQrCode {
  const id = crypto.randomUUID();
  let text = rawPayload || '';
  let truncated = false;

  if (text.length > MAX_QR_PAYLOAD_LENGTH) {
    text = text.slice(0, MAX_QR_PAYLOAD_LENGTH);
    truncated = true;
  }

  const { payloadType, isDangerousScheme } = classifyQrPayload(text);

  let sanitizedPayload = text;
  let delegatedUrl: string | undefined;
  let wifiMetadata: QrWifiMetadata | undefined;
  let otpauthMetadata: QrOtpauthMetadata | undefined;
  let hasEmbeddedCredentials = false;

  if (payloadType === 'wifi') {
    const wifiRes = parseWifiPayload(text);
    sanitizedPayload = wifiRes.sanitizedWifiPayload;
    wifiMetadata = wifiRes.wifiMetadata;
  } else if (payloadType === 'otpauth') {
    const otpRes = parseOtpauthPayload(text);
    sanitizedPayload = otpRes.sanitizedOtpauthPayload;
    otpauthMetadata = otpRes.otpauthMetadata;
  } else if (payloadType === 'https_url' || payloadType === 'http_url') {
    try {
      const parsedUrl = new URL(text);
      // Redact embedded user credentials in URL authority
      if (parsedUrl.username || parsedUrl.password) {
        hasEmbeddedCredentials = true;
        parsedUrl.username = '';
        parsedUrl.password = '';
      }
      const safeUrlBase = redactSensitiveText(parsedUrl.toString());
      sanitizedPayload = hasEmbeddedCredentials
        ? safeUrlBase.replace('://', '://[REDACTED_USER]:[REDACTED_PASSWORD]@')
        : safeUrlBase;
      delegatedUrl = safeUrlBase;
    } catch {
      if (text.includes('@') && (text.startsWith('http://') || text.startsWith('https://'))) {
        hasEmbeddedCredentials = true;
      }
      sanitizedPayload = redactSensitiveText(text);
      delegatedUrl = sanitizedPayload;
    }
  } else {
    sanitizedPayload = redactSensitiveText(text);
  }

  return {
    id,
    rawPayload: sanitizedPayload, // raw is never stored unredacted
    sanitizedPayload,
    payloadType,
    characterCount: sanitizedPayload.length,
    truncated,
    delegatedUrl,
    wifiMetadata,
    otpauthMetadata,
    isDangerousScheme,
    hasEmbeddedCredentials,
  };
}

/**
 * Pure-JS image rasterizer into RGBA pixel buffers for jsQR.
 * Supports PNG and JPEG without native dependencies.
 */
export function decodeImageToRgba(loaded: LoadedImageContent): {
  data?: Uint8ClampedArray;
  width?: number;
  height?: number;
  error?: string;
} {
  // Immediate pre-rasterization boundary check on known dimensions
  if (loaded.width && loaded.height && (loaded.width * loaded.height > MAX_QR_RASTER_PIXELS)) {
    return { error: `Image dimensions (${loaded.width}x${loaded.height}) exceed pure-JS QR rasterization ceiling (16 MP); skipped.` };
  }

  const mime = loaded.mimeType;

  if (mime === 'image/png') {
    try {
      const png = PNG.sync.read(loaded.buffer);
      if (png.width * png.height > MAX_QR_RASTER_PIXELS) {
        return { error: `Image dimensions (${png.width}x${png.height}) exceed pure-JS QR rasterization ceiling (16 MP); skipped.` };
      }

      return {
        data: new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.byteLength),
        width: png.width,
        height: png.height,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Corrupt PNG';
      return { error: `Failed to rasterize PNG for QR scanning: ${msg}` };
    }
  }

  if (mime === 'image/jpeg') {
    try {
      const decoded = jpeg.decode(loaded.buffer, { useTArray: true });
      if (decoded.width * decoded.height > MAX_QR_RASTER_PIXELS) {
        return { error: `Image dimensions (${decoded.width}x${decoded.height}) exceed pure-JS QR rasterization ceiling (16 MP); skipped.` };
      }
      return {
        data: new Uint8ClampedArray(decoded.data.buffer, decoded.data.byteOffset, decoded.data.byteLength),
        width: decoded.width,
        height: decoded.height,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Corrupt JPEG';
      return { error: `Failed to rasterize JPEG for QR scanning: ${msg}` };
    }
  }

  if (mime === 'image/webp') {
    return { error: 'Direct pure-JS pixel rasterization for WEBP is not supported; skipped QR decoding.' };
  }

  return { error: `Unsupported image format (${mime}) for pure-JS QR decoding.` };
}

/**
 * Extracts a sub-rectangle pixel buffer from a full canvas.
 */
function extractSubregion(
  srcData: Uint8ClampedArray,
  srcW: number,
  srcH: number,
  x0: number,
  y0: number,
  w: number,
  h: number
): { data: Uint8ClampedArray; width: number; height: number } {
  const dstData = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) {
    const srcY = y0 + y;
    if (srcY >= srcH) break;
    const srcRowStart = (srcY * srcW + x0) * 4;
    const dstRowStart = y * w * 4;
    const rowLen = Math.min(w, srcW - x0) * 4;
    dstData.set(srcData.subarray(srcRowStart, srcRowStart + rowLen), dstRowStart);
  }
  return { data: dstData, width: w, height: h };
}

/**
 * Detects and decodes QR codes from loaded image content using pure-JS jsQR.
 * Handles single and multi-region candidate scanning, deduplication, and bounds.
 */
export function detectAndDecodeQrCodes(loaded: LoadedImageContent): {
  qrCodes: SanitizedQrCode[];
  limitations: string[];
} {
  const raster = decodeImageToRgba(loaded);
  if (raster.error || !raster.data || !raster.width || !raster.height) {
    return {
      qrCodes: [],
      limitations: raster.error ? [raster.error] : ['Unable to decode image pixels for QR detection.'],
    };
  }

  const { data, width, height } = raster;
  const detectedPayloads = new Set<string>();
  const qrCodes: SanitizedQrCode[] = [];

  // Helper to record unique payload
  const recordCandidate = (code: QRCode | null) => {
    if (!code || !code.data) return;
    const payload = code.data.trim();
    if (!payload || detectedPayloads.has(payload)) return;

    detectedPayloads.add(payload);
    qrCodes.push(sanitizeAndBoundQrPayload(payload));
  };

  // 1. Scan the entire canvas
  try {
    const fullScan = jsQR(data, width, height, { inversionAttempts: 'attemptBoth' });
    recordCandidate(fullScan);
  } catch {
    // jsQR failure on full canvas handled gracefully
  }

  // 2. If multiple QR codes possible and canvas is large enough, scan overlapping quadrants
  if (qrCodes.length < MAX_QR_CODES_PER_IMAGE && width >= 300 && height >= 300) {
    const halfW = Math.floor(width / 2);
    const halfH = Math.floor(height / 2);
    const overlapX = Math.floor(width * 0.1);
    const overlapY = Math.floor(height * 0.1);

    const regions = [
      // Top-Left
      { x: 0, y: 0, w: Math.min(width, halfW + overlapX), h: Math.min(height, halfH + overlapY) },
      // Top-Right
      { x: Math.max(0, halfW - overlapX), y: 0, w: width - Math.max(0, halfW - overlapX), h: Math.min(height, halfH + overlapY) },
      // Bottom-Left
      { x: 0, y: Math.max(0, halfH - overlapY), w: Math.min(width, halfW + overlapX), h: height - Math.max(0, halfH - overlapY) },
      // Bottom-Right
      { x: Math.max(0, halfW - overlapX), y: Math.max(0, halfH - overlapY), w: width - Math.max(0, halfW - overlapX), h: height - Math.max(0, halfH - overlapY) },
    ];

    for (const r of regions) {
      if (qrCodes.length >= MAX_QR_CODES_PER_IMAGE) break;
      try {
        const sub = extractSubregion(data, width, height, r.x, r.y, r.w, r.h);
        const tileScan = jsQR(sub.data, sub.width, sub.height, { inversionAttempts: 'attemptBoth' });
        recordCandidate(tileScan);
      } catch {
        // Tile scan error tolerance
      }
    }
  }

  return {
    qrCodes: qrCodes.slice(0, MAX_QR_CODES_PER_IMAGE),
    limitations: [],
  };
}

/**
 * Generates deterministic security findings from decoded QR codes.
 */
export function generateQrSecurityFindings(qrCodes: SanitizedQrCode[]): Finding[] {
  const findings: Finding[] = [];

  for (const qr of qrCodes) {
    if (findings.length >= MAX_QR_FINDINGS) break;

    // 1. Dangerous Scheme Findings
    if (qr.payloadType === 'javascript_uri') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'dangerous_function',
        severity: 'critical',
        confidence: 'high',
        title: 'Dangerous Executable JavaScript URI in QR Code',
        description: 'QR code contains an executable javascript: URI payload which poses immediate code execution or XSS risks if triggered.',
      });
    } else if (qr.payloadType === 'file_uri') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_qr',
        severity: 'high',
        confidence: 'high',
        title: 'Local Filesystem URI in QR Code',
        description: 'QR code contains a file: URI payload attempting to reference local filesystem resources.',
      });
    } else if (qr.payloadType === 'data_uri') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_qr',
        severity: 'medium',
        confidence: 'high',
        title: 'Embedded Data URI in QR Code',
        description: 'QR code contains an embedded data: URI which may deliver obfuscated content or client-side exploits.',
      });
    } else if (qr.payloadType === 'intent_uri') {
      findings.push({
        id: crypto.randomUUID(),
        type: 'suspicious_qr',
        severity: 'medium',
        confidence: 'high',
        title: 'Mobile Intent Redirection in QR Code',
        description: 'QR code contains an Android intent: URI which can trigger unauthorized app activities or intent redirection.',
      });
    }

    // 2. HTTP/HTTPS Quishing & URL Findings
    if (qr.payloadType === 'https_url' || qr.payloadType === 'http_url') {
      try {
        const urlObj = new URL(qr.sanitizedPayload);
        const host = urlObj.hostname.toLowerCase();

        // Insecure HTTP warning
        if (qr.payloadType === 'http_url') {
          findings.push({
            id: crypto.randomUUID(),
            type: 'insecure_protocol',
            severity: 'medium',
            confidence: 'high',
            title: 'Unencrypted HTTP Link in QR Code',
            description: `The QR code directs to an unencrypted HTTP destination (${host}), exposing data in transit to interception.`,
          });
        }

        // Private / Internal / Metadata IP Target
        if (isInternalOrPrivateHost(host)) {
          findings.push({
            id: crypto.randomUUID(),
            type: 'private_network_host',
            severity: 'critical',
            confidence: 'high',
            title: 'QR Code Targets Private Network or Cloud Metadata',
            description: `The QR code directs to a private internal network IP or cloud metadata service endpoint (${host}), posing SSRF and unauthorized network access risks.`,
          });
        }

        // URL Shortener Obfuscation
        if (KNOWN_URL_SHORTENERS.has(host)) {
          findings.push({
            id: crypto.randomUUID(),
            type: 'shortened_url',
            severity: 'medium',
            confidence: 'high',
            title: 'QR Code Links to URL Shortener',
            description: `The QR code links to a shortened URL (${host}) which conceals the final target destination from visual inspection.`,
          });
        }

        // Embedded credentials
        if (qr.hasEmbeddedCredentials || qr.sanitizedPayload.includes('[REDACTED_USER]') || qr.sanitizedPayload.includes('[REDACTED_PASSWORD]')) {
          findings.push({
            id: crypto.randomUUID(),
            type: 'credential_in_url',
            severity: 'high',
            confidence: 'high',
            title: 'Embedded Credentials in QR Destination',
            description: 'The QR code destination URL contains embedded authentication credentials or tokens.',
          });
        }
      } catch {
        // Safe tolerance for malformed URLs
      }
    }
  }

  return findings.slice(0, MAX_QR_FINDINGS);
}

/**
 * Primary high-level entry point for analyzing QR codes in an image attachment.
 */
export async function analyzeImageQrCodes(loaded: LoadedImageContent): Promise<{
  qrResult: SanitizedQrAnalysisResult;
  findings: Finding[];
  evidence: Evidence[];
  limitations: string[];
}> {
  const { qrCodes, limitations } = detectAndDecodeQrCodes(loaded);
  const detectedCount = qrCodes.length;
  const status: 'available' | 'empty' | 'unsupported' =
    detectedCount > 0 ? 'available' : limitations.length > 0 ? 'unsupported' : 'empty';

  // Collect unique delegated URLs (max 5)
  const delegatedUrlsSet = new Set<string>();
  for (const qr of qrCodes) {
    if (qr.delegatedUrl) {
      delegatedUrlsSet.add(qr.delegatedUrl);
      if (delegatedUrlsSet.size >= MAX_DELEGATED_URLS) break;
    }
  }
  const delegatedUrls = Array.from(delegatedUrlsSet);

  const qrResult: SanitizedQrAnalysisResult = {
    status,
    detectedCount,
    qrCodes,
    delegatedUrls,
    limitations,
  };

  const findings = generateQrSecurityFindings(qrCodes);
  const evidence: Evidence[] = [];
  const now = new Date().toISOString();

  if (detectedCount > 0) {
    evidence.push({
      id: crypto.randomUUID(),
      sourceType: 'image_analysis',
      sourceName: 'Pure-JS QR Intelligence (Stage 7.3)',
      label: 'QR Code Detection & Payload Inspection',
      description: `Detected ${detectedCount} QR code${detectedCount === 1 ? '' : 's'}. Payload types: ${qrCodes.map(q => q.payloadType).join(', ')}.`,
      data: {
        detectedCount,
        payloadTypes: qrCodes.map(q => q.payloadType),
        hasDangerousScheme: qrCodes.some(q => q.isDangerousScheme),
        hasQuishingRisk: findings.some(f => f.type === 'shortened_url' || f.type === 'private_network_host'),
        delegatedUrls,
      },
      snippet: qrCodes[0].sanitizedPayload.slice(0, 150),
      isAiGenerated: false,
      createdAt: now,
    });
  }

  return {
    qrResult,
    findings,
    evidence,
    limitations,
  };
}
