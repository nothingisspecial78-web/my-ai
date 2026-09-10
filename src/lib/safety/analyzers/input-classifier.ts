import { SafetyInput, SafetyInputType } from '../types';

/**
 * Classifies raw user input into an appropriate SafetyInputType.
 * Deterministic heuristic based on syntax, protocols, structure, and metadata.
 */
export class InputClassifier {
  private static URL_REGEX = /^(https?:\/\/|www\.)[^\s/$.?#].[^\s]*$/i;
  private static EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  private static EMAIL_HEADER_REGEX = /^(from:|to:|subject:|date:|received:)/im;
  
  // Code indicators
  private static CODE_INDICATORS = [
    /\bfunction\s*\(/,
    /\bconst\s+\w+\s*=/,
    /\blet\s+\w+\s*=/,
    /\bvar\s+\w+\s*=/,
    /\bimport\s+.*\s+from\b/,
    /\bexport\s+(default\s+)?(class|function|const|let)\b/,
    /\bdef\s+\w+\s*\(/,
    /\bclass\s+\w+[\s{:]/,
    /#include\s*<.*>/,
    /<\?php/,
    /\bSELECT\b.*\bFROM\b/i,
    /<\/?[a-z][\s\S]*>/i, // HTML
  ];

  static classify(input: SafetyInput): SafetyInputType {
    // 1. Explicit type provided in metadata or input
    if (input.type) {
      return input.type;
    }

    // 2. MIME type inspection
    if (input.mimeType) {
      if (input.mimeType.startsWith('image/')) {
        return 'image';
      }
      if (
        input.mimeType === 'application/pdf' ||
        input.mimeType.includes('officedocument') ||
        input.mimeType.includes('msword')
      ) {
        return 'document';
      }
    }

    // 3. Filename inspection
    if (input.filename) {
      const lower = input.filename.toLowerCase();
      if (/\.(jpg|jpeg|png|webp|gif|bmp|svg)$/.test(lower)) {
        return 'image';
      }
      if (/\.(pdf|docx|doc|pptx|xlsx|odt)$/.test(lower)) {
        return 'document';
      }
      if (/\.(js|ts|jsx|tsx|py|go|rs|c|cpp|java|php|rb|sh|sql|html|css)$/.test(lower)) {
        return 'code';
      }
    }

    const trimmed = input.rawContent.trim();

    // 4. URL detection (strict single-line URL or starting with http)
    if (this.URL_REGEX.test(trimmed) || /^https?:\/\//i.test(trimmed)) {
      return 'url';
    }

    // 5. Email address or raw email headers
    if (this.EMAIL_REGEX.test(trimmed) || this.EMAIL_HEADER_REGEX.test(trimmed)) {
      return 'email';
    }

    // 6. Code snippet detection
    let codeMatches = 0;
    for (const pattern of this.CODE_INDICATORS) {
      if (pattern.test(trimmed)) {
        codeMatches++;
      }
    }
    if (codeMatches >= 2 || (codeMatches === 1 && (trimmed.includes(';') || trimmed.includes('{')))) {
      return 'code';
    }

    // 7. QR detection if metadata specifies QR payload
    if (input.metadata?.isQr) {
      return 'qr';
    }

    // Default to message / content
    return 'message';
  }
}
