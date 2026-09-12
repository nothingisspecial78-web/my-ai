/**
 * Deterministic Secret & Credential Detector (Phase 6.3)
 * 
 * Scans code for vendor-specific API keys, private keys, database connection strings,
 * tokens, and generic secrets. Uses Shannon entropy and strict placeholder exclusions
 * to prevent false positives. Enforces immediate redaction on all detected secrets.
 */

import { ExtractedSecret, SecretClass } from './types';
import { FindingSeverity, ConfidenceLevel } from '../types';

export interface SecretPatternDefinition {
  secretClass: SecretClass;
  label: string;
  severity: FindingSeverity;
  confidence: ConfidenceLevel;
  regex: RegExp;
  isVendorSpecific?: boolean;
  requiresEntropy?: boolean;
  minEntropy?: number;
  minLength?: number;
  extractor?: (match: RegExpExecArray) => string | null;
}

export class SecretDetector {
  /**
   * Known dummy or placeholder values that should never be flagged as real secrets.
   */
  private static PLACEHOLDER_TERMS = [
    'your_api_key',
    'your_token',
    'your_secret',
    'your-api-key',
    'your-secret-key',
    'insert_key_here',
    'insert_token_here',
    'insert_secret_here',
    'my_secret_token',
    'my_api_key',
    'dummy_token',
    'example_secret',
    'example_key',
    'changeme',
    'placeholder',
    'todo',
    'test_token',
    'mock_secret',
    'sample_key',
    'api_key_value',
  ];

  /**
   * Environment variable read patterns that represent secure practices.
   */
  private static ENV_VAR_PATTERNS = [
    /\bprocess\.env\.[A-Z0-9_]+/i,
    /\bos\.environ(?:\.get)?\s*\(['"][^'"]+['"]\)/i,
    /\bos\.getenv\s*\(['"][^'"]+['"]\)/i,
    /\bgetenv\s*\(['"][^'"]+['"]\)/i,
    /\bSystem\.getenv\s*\(['"][^'"]+['"]\)/i,
    /\bconfig\s*\(['"][^'"]+['"]\)/i,
    /\bsecrets\.[A-Z0-9_]+/i,
  ];

  /**
   * Vendor-specific and structured secret signatures.
   * Linear-time non-backtracking regular expressions.
   */
  private static SECRET_DEFINITIONS: SecretPatternDefinition[] = [
    // 1. AWS Access Key ID
    {
      secretClass: 'aws_access_key',
      label: 'AWS Access Key ID',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    },
    // 2. AWS Secret Access Key (associated assignment)
    {
      secretClass: 'aws_secret_key',
      label: 'AWS Secret Access Key',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /(?:\baws_secret_access_key|\bsecret_access_key|\baws_secret|\bawsSecretAccessKey|\bawsSecret)\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]/gi,
      extractor: m => m[1],
    },
    // 3. GitHub Personal Access Tokens (Classic & Fine-grained)
    {
      secretClass: 'github_token',
      label: 'GitHub Personal Access Token',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g,
    },
    // 4. RSA / EC / DSA / OpenSSH Private Keys
    {
      secretClass: 'private_key',
      label: 'Cryptographic Private Key Header',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----/g,
    },
    // 5. Stripe Live API Key
    {
      secretClass: 'stripe_key',
      label: 'Stripe Live API Key',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b([sr]k_live_[0-9a-zA-Z]{24,})\b/g,
    },
    // 6. OpenAI & Anthropic API Keys
    {
      secretClass: 'openai_key',
      label: 'OpenAI API Key',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(sk-proj-[a-zA-Z0-9_-]{40,}|sk-[a-zA-Z0-9]{40,})\b/g,
    },
    {
      secretClass: 'anthropic_key',
      label: 'Anthropic API Key',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(sk-ant-[a-zA-Z0-9_-]{40,})\b/g,
    },
    // 7. Google Cloud / Gemini API Key
    {
      secretClass: 'google_api_key',
      label: 'Google Cloud / Gemini API Key',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(AIza[0-9A-Za-z-_]{30,35})\b/g,
    },
    // 8. Database Connection URIs with credentials
    {
      secretClass: 'database_uri',
      label: 'Database Connection String with Credentials',
      severity: 'critical',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_.~%-]+:(?:(?!\$\{)[^@\s/]{3,})@[a-zA-Z0-9_.~%-]+/g,
    },
    // 9. Slack / Discord Webhooks & Tokens
    {
      secretClass: 'slack_token',
      label: 'Slack Token',
      severity: 'high',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,}-[0-9a-zA-Z]{10,})\b/g,
    },
    {
      secretClass: 'discord_webhook',
      label: 'Discord Webhook URL',
      severity: 'high',
      confidence: 'high',
      isVendorSpecific: true,
      regex: /\bhttps:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,}\b/g,
    },
    // 10. Hardcoded Bearer Tokens
    {
      secretClass: 'bearer_token',
      label: 'Hardcoded Bearer Authentication Token',
      severity: 'high',
      confidence: 'high',
      regex: /['"`]Bearer\s+([a-zA-Z0-9_\-\.]{25,})['"`]/gi,
      extractor: m => m[1],
      requiresEntropy: true,
      minEntropy: 3.2,
    },
    // 11. JSON Web Tokens (JWT)
    {
      secretClass: 'jwt_token',
      label: 'JSON Web Token (JWT)',
      severity: 'high',
      confidence: 'medium',
      regex: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
    },
    // 12. Generic Secret Assignments (requires strict entropy and placeholder filtering)
    {
      secretClass: 'generic_secret',
      label: 'Hardcoded Generic Secret Token',
      severity: 'high',
      confidence: 'medium',
      regex: /(?:\bapi[_-]?key|\bsecret|\btoken|\bpassword|\bpasswd|\bauth[_-]?token|\baccess[_-]?token)\s*[:=]\s*['"`]([^'"`\s]{16,})['"`]/gi,
      extractor: m => m[1],
      requiresEntropy: true,
      minEntropy: 3.4,
      minLength: 16,
    },
  ];

  /**
   * Computes the Shannon entropy of a string (in bits per character).
   */
  static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const frequencies = new Map<string, number>();
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }
    let entropy = 0;
    const len = str.length;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Determines if a candidate string is an obvious placeholder or dummy value.
   */
  static isPlaceholder(value: string): boolean {
    const lower = value.toLowerCase();
    
    // Check against known placeholder terms
    for (const term of this.PLACEHOLDER_TERMS) {
      if (lower.includes(term)) return true;
    }

    // Check if string is composed entirely of a single repeated character (e.g. 'xxxxxxxxx')
    if (/^(.)\1+$/.test(value)) return true;

    // Check if purely sequential or trivial test numbers
    if (/^1234567890+$/.test(value) || /^abcdef+$/i.test(value)) return true;

    return false;
  }

  /**
   * Redacts sensitive secret text immediately.
   */
  static redact(rawSecret: string, secretClass: SecretClass): string {
    if (!rawSecret) return '[REDACTED]';

    switch (secretClass) {
      case 'aws_access_key':
        return rawSecret.length > 4 ? `${rawSecret.substring(0, 4)}[REDACTED_AWS_KEY]` : '[REDACTED_AWS_KEY]';
      case 'aws_secret_key':
        return '[REDACTED_AWS_SECRET_KEY]';
      case 'github_token':
        return rawSecret.startsWith('gh') ? `${rawSecret.substring(0, 4)}[REDACTED_GITHUB_TOKEN]` : '[REDACTED_GITHUB_TOKEN]';
      case 'private_key':
        return '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]';
      case 'stripe_key':
        return rawSecret.length > 7 ? `${rawSecret.substring(0, 7)}[REDACTED_STRIPE_KEY]` : '[REDACTED_STRIPE_KEY]';
      case 'openai_key':
        return rawSecret.length > 7 ? `${rawSecret.substring(0, 7)}[REDACTED_OPENAI_KEY]` : '[REDACTED_OPENAI_KEY]';
      case 'anthropic_key':
        return rawSecret.length > 7 ? `${rawSecret.substring(0, 7)}[REDACTED_ANTHROPIC_KEY]` : '[REDACTED_ANTHROPIC_KEY]';
      case 'google_api_key':
        return rawSecret.length > 4 ? `${rawSecret.substring(0, 4)}[REDACTED_GOOGLE_KEY]` : '[REDACTED_GOOGLE_KEY]';
      case 'database_uri':
        return rawSecret.replace(/(:)([^@\s/]+)(@)/, '$1[REDACTED_PASSWORD]$3');
      case 'slack_token':
        return '[REDACTED_SLACK_TOKEN]';
      case 'discord_webhook':
        return rawSecret.replace(/\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, '/api/webhooks/[REDACTED_DISCORD_WEBHOOK]');
      case 'bearer_token':
        return 'Bearer [REDACTED_BEARER_TOKEN]';
      case 'jwt_token':
        return 'eyJ[REDACTED_JWT_TOKEN]';
      default:
        return '[REDACTED_SECRET]';
    }
  }

  /**
   * Scans content and returns all validated, redacted secrets.
   */
  static detect(content: string): ExtractedSecret[] {
    const secrets: ExtractedSecret[] = [];
    const seenSecrets = new Set<string>();

    // Calculate line offsets for line-number reporting
    const lines = content.split('\n');
    const getLineNumber = (index: number): number => {
      let currentLen = 0;
      for (let i = 0; i < lines.length; i++) {
        currentLen += lines[i].length + 1; // +1 for newline
        if (index < currentLen) return i + 1;
      }
      return lines.length;
    };

    for (const def of this.SECRET_DEFINITIONS) {
      def.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = def.regex.exec(content)) !== null) {
        const rawValue = def.extractor ? def.extractor(match) : match[1] || match[0];
        if (!rawValue) continue;

        // Skip if this exact value or location was already captured
        const dedupKey = `${def.secretClass}:${match.index}`;
        if (seenSecrets.has(dedupKey)) continue;

        // Check if matching context is an environment variable lookup
        const matchStart = match.index;
        const lineText = lines[getLineNumber(matchStart) - 1] || '';
        let isEnvLookup = false;
        for (const envRegex of this.ENV_VAR_PATTERNS) {
          if (envRegex.test(lineText)) {
            isEnvLookup = true;
            break;
          }
        }
        if (isEnvLookup) continue;

        // Check placeholder filter
        if (this.isPlaceholder(rawValue)) continue;

        // Check entropy requirements if specified (vendor-specific patterns take precedence)
        if (def.requiresEntropy && !def.isVendorSpecific) {
          if (def.minLength && rawValue.length < def.minLength) continue;
          const entropy = this.calculateShannonEntropy(rawValue);
          const threshold = def.minEntropy ?? 3.2;
          if (entropy < threshold) continue;
        }

        seenSecrets.add(dedupKey);
        const lineNumber = getLineNumber(match.index);
        const redactedValue = this.redact(rawValue, def.secretClass);

        secrets.push({
          secretClass: def.secretClass,
          label: def.label,
          redactedValue,
          lineNumber,
          severity: def.severity,
          confidence: def.confidence,
        });
      }
    }

    return secrets;
  }
}
