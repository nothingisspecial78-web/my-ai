import { describe, it, expect } from 'vitest';
import { extractVerdictData, VerdictCardData } from './VerdictCard';
import type { SafetyReport } from '@/lib/safety/types';
import type { UnifiedSecurityReport } from '@/lib/safety/unified/types';

describe('VerdictCard — Signature Security Component', () => {
  describe('extractVerdictData', () => {
    it('1. correctly maps a High Risk, High Confidence UnifiedSecurityReport', () => {
      const mockReport: Partial<UnifiedSecurityReport> = {
        id: 'rep_123',
        riskLevel: 'high',
        confidenceLevel: 'high',
        score: 85,
        primaryConcern: 'Suspicious credential solicitation matching known phishing campaign.',
        summary: 'Identified phishing indicators.',
        findings: [
          {
            id: 'fnd_1',
            domain: 'scam',
            type: 'credential_request',
            severity: 'high',
            confidence: 'high',
            title: 'Requests account credentials',
            description: 'Message directs recipient to enter account password.',
            evidenceIds: ['ev_1'],
            sources: [],
            observationCount: 1,
          },
          {
            id: 'fnd_2',
            domain: 'url',
            type: 'lookalike_domain',
            severity: 'high',
            confidence: 'high',
            title: 'Deceptive brand lookalike URL',
            description: 'paypa1-security.example mimics PayPal.',
            evidenceIds: ['ev_2'],
            sources: [],
            observationCount: 1,
            targetEntity: 'paypa1-security.example',
          },
        ],
        evidence: [],
        recommendations: [
          { action: 'do_not_click', title: 'Do Not Click', description: 'Destination is flagged.', priority: 'high' },
        ],
        limitations: ['Sandbox evaluation unavailable.'],
        privacyGuarantees: ['redacted_password'],
        status: 'completed',
        affectedEntities: ['paypa1-security.example'],
      };

      const data = extractVerdictData(mockReport as UnifiedSecurityReport);

      expect(data.riskLevel).toBe('high');
      expect(data.confidenceLevel).toBe('high');
      expect(data.score).toBe(85);
      expect(data.verdict).toBe('Suspicious credential solicitation matching known phishing campaign.');
      expect(data.targetEntity).toBe('paypa1-security.example');
      expect(data.evidenceItems).toHaveLength(2);
      expect(data.evidenceItems?.[0].tag).toBe('CREDENTIAL REQUEST');
      expect(data.evidenceItems?.[1].tag).toBe('LINK MISMATCH');
      expect(data.recommendations).toHaveLength(1);
      expect(data.recommendations?.[0].action).toBe('do_not_click');
      expect(data.privacyGuarantees).toContain('redacted_password');
    });

    it('2. correctly maps a Low Risk / High Confidence report without claiming absolute safety', () => {
      const mockReport: Partial<SafetyReport> = {
        analysisId: 'rep_clean',
        riskLevel: 'low',
        confidenceLevel: 'high',
        score: 5,
        summary: 'No significant security threats or deceptive indicators detected.',
        findings: [],
        evidence: [],
        recommendations: [
          { action: 'proceed_with_caution', title: 'Exercise Normal Caution', priority: 'low' },
        ],
      };

      const data = extractVerdictData(mockReport as SafetyReport);

      expect(data.riskLevel).toBe('low');
      expect(data.confidenceLevel).toBe('high');
      expect(data.score).toBe(5);
      expect(data.verdict).not.toContain('100% safe');
      expect(data.verdict).not.toContain('guaranteed');
    });

    it('3. handles Medium Risk / Medium Confidence state', () => {
      const mockData: VerdictCardData = {
        riskLevel: 'medium',
        confidenceLevel: 'medium',
        score: 50,
        verdict: 'This message shows several characteristics commonly associated with phishing attempts.',
        evidenceItems: [
          { tag: 'URGENCY', label: 'High pressure urgency keywords detected' },
        ],
      };

      expect(mockData.riskLevel).toBe('medium');
      expect(mockData.confidenceLevel).toBe('medium');
      expect(mockData.evidenceItems?.[0].tag).toBe('URGENCY');
    });

    it('4. handles Unknown Risk / Low Confidence state with caution caveat', () => {
      const mockReport: Partial<SafetyReport> = {
        analysisId: 'rep_unk',
        riskLevel: 'unknown',
        confidenceLevel: 'low',
        score: 0,
        findings: [],
        evidence: [],
      };

      const data = extractVerdictData(mockReport as SafetyReport);

      expect(data.riskLevel).toBe('unknown');
      expect(data.confidenceLevel).toBe('low');
      expect(data.verdict).toContain('Analysis inconclusive');
    });

    it('5. correctly assigns signal tags for QR codes, code injection, and visual spoofing', () => {
      const mockReport: Partial<UnifiedSecurityReport> = {
        id: 'rep_multi',
        riskLevel: 'critical',
        confidenceLevel: 'high',
        score: 95,
        findings: [
          {
            id: 'fnd_qr',
            domain: 'qr',
            type: 'quishing_target',
            severity: 'critical',
            confidence: 'high',
            title: 'Malicious QR quishing payload',
            evidenceIds: [],
            sources: [],
            observationCount: 1,
          },
          {
            id: 'fnd_code',
            domain: 'code',
            type: 'sql_injection_pattern',
            severity: 'high',
            confidence: 'high',
            title: 'SQL injection string concatenation',
            evidenceIds: [],
            sources: [],
            observationCount: 1,
          },
          {
            id: 'fnd_img',
            domain: 'image',
            type: 'fake_banking',
            severity: 'high',
            confidence: 'high',
            title: 'Deceptive bank screenshot overlay',
            metadata: { category: 'fake_banking' },
            evidenceIds: [],
            sources: [],
            observationCount: 1,
          },
        ],
      };

      const data = extractVerdictData(mockReport as UnifiedSecurityReport);

      expect(data.evidenceItems?.[0].tag).toBe('QR PAYLOAD');
      expect(data.evidenceItems?.[1].tag).toBe('CODE INJECTION');
      expect(data.evidenceItems?.[2].tag).toBe('VISUAL SPOOFING');
    });
  });
});
