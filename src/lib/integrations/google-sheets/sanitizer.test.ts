import { describe, it, expect } from 'vitest';
import { GoogleSheetsExportSanitizer, sanitizeDomain } from './sanitizer';
import type { UnifiedSecurityReport } from '@/lib/safety/unified/types';

describe('Google Sheets Privacy Sanitizer', () => {
  describe('sanitizeDomain', () => {
    it('extracts and normalizes valid public domains', () => {
      expect(sanitizeDomain('https://evil-phish.com/login?token=secret')).toBe('evil-phish.com');
      expect(sanitizeDomain('HTTP://SUB.EXAMPLE.CO.UK/path')).toBe('sub.example.co.uk');
      expect(sanitizeDomain('paypal-update.com.')).toBe('paypal-update.com');
    });

    it('blocks localhost and loopback addresses', () => {
      expect(sanitizeDomain('localhost')).toBeNull();
      expect(sanitizeDomain('http://localhost:3000/test')).toBeNull();
      expect(sanitizeDomain('127.0.0.1')).toBeNull();
      expect(sanitizeDomain('http://127.0.0.1:8080')).toBeNull();
      expect(sanitizeDomain('::1')).toBeNull();
      expect(sanitizeDomain('http://[::1]/')).toBeNull();
    });

    it('blocks RFC 1918 private network IPs and link-local', () => {
      expect(sanitizeDomain('192.168.1.1')).toBeNull();
      expect(sanitizeDomain('http://192.168.0.254/router')).toBeNull();
      expect(sanitizeDomain('10.0.0.1')).toBeNull();
      expect(sanitizeDomain('172.16.0.1')).toBeNull();
      expect(sanitizeDomain('172.31.255.255')).toBeNull();
      expect(sanitizeDomain('169.254.169.254')).toBeNull();
    });

    it('blocks .local internal mDNS hostnames', () => {
      expect(sanitizeDomain('printer.local')).toBeNull();
      expect(sanitizeDomain('http://nas.local/admin')).toBeNull();
    });

    it('returns null for empty or invalid inputs', () => {
      expect(sanitizeDomain('')).toBeNull();
      expect(sanitizeDomain('not a valid host @@@')).toBeNull();
    });
  });

  describe('GoogleSheetsExportSanitizer.sanitize', () => {
    const sampleReport: UnifiedSecurityReport = {
      id: 'analysis-test-001',
      inputType: 'url',
      status: 'completed',
      riskLevel: 'high',
      score: 85,
      confidenceLevel: 'high',
      primaryConcern: 'Detected credential harvesting form mimicking Bank of America.',
      summary: 'High risk phishing site detected.',
      findings: [
        {
          id: 'f-1',
          type: 'phishing',
          severity: 'critical',
          title: 'Fake Login Form',
          description: 'Login form found targeting credentials.',
          confidence: 'high',
          source: 'heuristic',
          targetEntity: 'https://fake-boa-login.com/secure',
        },
      ],
      evidence: [],
      recommendations: [
        {
          action: 'do_not_click',
          title: 'Do not proceed',
          description: 'Do not enter credentials on this page.',
          priority: 'high',
        },
      ],
      limitations: ['WHOIS data unavailable'],
      domainsInvolved: ['url', 'phishing'],
    };

    it('correctly maps structured report to sanitized export row', () => {
      const row = GoogleSheetsExportSanitizer.sanitize(sampleReport, 'user-123', 'security-checkup');

      expect(row.analysis_id).toBe('analysis-test-001');
      expect(row.user_id_hash.length).toBe(16);
      expect(row.input_type).toBe('url');
      expect(row.theme).toBe('security-checkup');
      expect(row.risk_level).toBe('high');
      expect(row.risk_score).toBe(85);
      expect(row.confidence_level).toBe('high');
      expect(row.domains_involved).toContain('fake-boa-login.com');
      expect(row.finding_count).toBe(1);
      expect(row.recommendation_count).toBe(1);
      expect(row.analyzer_coverage).toBe('url;phishing');
    });

    it('truncates primary concern to MAX_CONCERN_LENGTH (300 chars)', () => {
      const longConcern = 'A'.repeat(500);
      const report = { ...sampleReport, primaryConcern: longConcern };
      const row = GoogleSheetsExportSanitizer.sanitize(report, 'user-123');

      expect(row.primary_concern.length).toBeLessThanOrEqual(300);
      expect(row.primary_concern.endsWith('...')).toBe(true);
    });

    it('redacts sensitive secrets and API keys from primary concern', () => {
      const secretConcern = 'User submitted Bearer ya29.a0AfH6SMD_secret and sk-proj-1234567890abcdef1234567890 for verification.';
      const report = { ...sampleReport, primaryConcern: secretConcern };
      const row = GoogleSheetsExportSanitizer.sanitize(report, 'user-123');

      expect(row.primary_concern).not.toContain('ya29.a0AfH6SMD_secret');
      expect(row.primary_concern).not.toContain('sk-proj-1234567890abcdef1234567890');
    });

    it('handles reports with missing optional fields safely', () => {
      const minimalReport = {
        id: 'min-1',
        riskLevel: 'low',
        score: 10,
        confidenceLevel: 'medium',
      } as unknown as UnifiedSecurityReport;

      const row = GoogleSheetsExportSanitizer.sanitize(minimalReport, 'user-456');
      expect(row.analysis_id).toBe('min-1');
      expect(row.risk_level).toBe('low');
      expect(row.risk_score).toBe(10);
      expect(row.finding_count).toBe(0);
      expect(row.domains_involved).toBe('');
    });

    it('toRowArray matches getHeaders length and order', () => {
      const row = GoogleSheetsExportSanitizer.sanitize(sampleReport, 'user-123');
      const rowArray = GoogleSheetsExportSanitizer.toRowArray(row);
      const headers = GoogleSheetsExportSanitizer.getHeaders();

      expect(rowArray.length).toBe(headers.length);
      expect(headers.length).toBe(15);
      expect(headers[0]).toBe('timestamp');
      expect(headers[1]).toBe('analysis_id');
      expect(headers[2]).toBe('user_id_hash');
      expect(headers[5]).toBe('risk_level');
      expect(rowArray[5]).toBe('HIGH');
    });
  });

  describe('Adversarial Secret & PII Injection Defenses', () => {
    it('guarantees zero raw passwords or tokens reach the final row array', () => {
      const passwordSample = 'password123!@#';
      const adversarialReport = {
        id: 'adv-001',
        primaryConcern: `Credential leak observed with password = ${passwordSample} and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-o-k-e-n`,
        affectedEntities: ['http://192.168.1.1/admin', 'evil-phish.com'],
        findings: [
          {
            id: 'f-leak',
            targetEntity: 'http://localhost:8080/internal',
          },
        ],
      } as unknown as UnifiedSecurityReport;

      const row = GoogleSheetsExportSanitizer.sanitize(adversarialReport, 'user-adversary');
      const rowArray = GoogleSheetsExportSanitizer.toRowArray(row);
      const stringifiedRow = JSON.stringify(rowArray);

      expect(stringifiedRow).not.toContain('192.168.1.1');
      expect(stringifiedRow).not.toContain('localhost');
      expect(stringifiedRow).not.toContain('eyJhbGciOiJIUzI1Ni');
      expect(stringifiedRow).toContain('evil-phish.com');
    });
  });
});
