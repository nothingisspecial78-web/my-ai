/**
 * Bounded Artifact & Contact Extractors (Phase 6.2)
 * 
 * Safely extracts URLs, phone numbers, and email addresses from untrusted text.
 * Strictly enforces bounded limits and linear-time regexes to prevent ReDoS / DoS.
 */

import { ExtractedContacts } from './types';

export const MAX_RAW_TEXT_LENGTH = 20_000;
export const MAX_EXTRACTED_URLS = 10;
export const MAX_EXTRACTED_PHONES = 20;
export const MAX_EXTRACTED_EMAILS = 20;

export class ContactExtractor {
  /**
   * Safe URL extraction regex with bounded matching.
   * Matches http(s):// or www. links.
   */
  private static URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'`\x00-\x1f\x7f-\x9f]+/gi;

  /**
   * Safe email extraction regex with bounded component lengths.
   */
  private static EMAIL_REGEX = /[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}/g;

  /**
   * Phone number pattern:
   * Supports:
   * - International: +91 98765 43210, +919876543210, +1 (555) 123-4567, +44 20 7946 0958
   * - National: 09876543210, 98765 43210, 9876543210
   * - Delimited: 98765-43210, 555-0199
   */
  private static PHONE_REGEX = /(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,5}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{4,6}\b/g;

  /**
   * Sanitizes and bounds raw text before parsing.
   */
  static sanitizeInput(rawText: string): string {
    if (!rawText || typeof rawText !== 'string') return '';
    // Strip zero-width characters and control chars (except standard whitespace/newlines)
    const sanitized = rawText
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
    if (sanitized.length > MAX_RAW_TEXT_LENGTH) {
      return sanitized.slice(0, MAX_RAW_TEXT_LENGTH);
    }
    return sanitized;
  }

  /**
   * Extracts unique URLs from text up to MAX_EXTRACTED_URLS.
   */
  static extractUrls(text: string): string[] {
    if (!text) return [];
    const bounded = this.sanitizeInput(text);
    const matches = bounded.match(this.URL_REGEX) || [];
    const unique = new Set<string>();

    for (const raw of matches) {
      // Strip trailing punctuation often caught in natural prose
      const clean = raw.replace(/[.,;:!?)\]}>"'`]+$/, '').trim();
      if (clean.length > 3) {
        unique.add(clean);
        if (unique.size >= MAX_EXTRACTED_URLS) break;
      }
    }

    return Array.from(unique);
  }

  /**
   * Extracts unique email addresses from text up to MAX_EXTRACTED_EMAILS.
   */
  static extractEmails(text: string): string[] {
    if (!text) return [];
    const bounded = this.sanitizeInput(text);
    const matches = bounded.match(this.EMAIL_REGEX) || [];
    const unique = new Set<string>();

    for (const raw of matches) {
      const clean = raw.replace(/[.,;:!?)\]}>"'`]+$/, '').trim().toLowerCase();
      if (clean.includes('@') && clean.includes('.')) {
        unique.add(clean);
        if (unique.size >= MAX_EXTRACTED_EMAILS) break;
      }
    }

    return Array.from(unique);
  }

  /**
   * Extracts unique phone numbers from text up to MAX_EXTRACTED_PHONES.
   * Filters out false positives like dates (2026/09/12), monetary figures (50000), or simple IDs.
   */
  static extractPhoneNumbers(text: string): string[] {
    if (!text) return [];
    const bounded = this.sanitizeInput(text);
    const matches = bounded.match(this.PHONE_REGEX) || [];
    const unique = new Set<string>();

    for (const raw of matches) {
      const clean = raw.trim().replace(/[.,;:!?]+$/, '');
      const digitsOnly = clean.replace(/\D/g, '');

      // Phone numbers generally have 10 to 15 digits (including country code)
      // Ignore short numbers, dates like 2026, or pure 4-digit codes
      if (digitsOnly.length >= 10 && digitsOnly.length <= 15) {
        // Exclude common date patterns: YYYYMMDD or DDMMYYYY
        if (digitsOnly.startsWith('202') && digitsOnly.length === 8) continue;
        
        unique.add(clean);
        if (unique.size >= MAX_EXTRACTED_PHONES) break;
      }
    }

    return Array.from(unique);
  }

  /**
   * Extracts all contacts in a single bounded pass.
   */
  static extractAll(text: string): ExtractedContacts {
    return {
      urls: this.extractUrls(text),
      emails: this.extractEmails(text),
      phoneNumbers: this.extractPhoneNumbers(text),
    };
  }
}
