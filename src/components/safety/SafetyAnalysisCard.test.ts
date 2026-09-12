import React from 'react';
import { describe, it, expect } from 'vitest';
import { renderToString } from 'react-dom/server';
import { 
  SafetyAnalysisCard, 
  categorizeFinding, 
  enforceCautiousLanguage, 
  sanitizeSnippetSafely 
} from './SafetyAnalysisCard';
import { SafetyReport, Finding, Evidence } from '@/lib/safety/types';

function createMockReport(overrides?: Partial<SafetyReport>): SafetyReport {
  return {
    id: 'rep-test-1',
    inputType: 'image',
    status: 'completed',
    riskLevel: 'low',
    confidenceLevel: 'medium',
    score: 0,
    findings: [],
    evidence: [],
    recommendations: [],
    limitations: [],
    summary: 'Image inspection completed with no suspicious indicators detected.',
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('Stage 7.6: Unified Safety & Security Image Intelligence UI', () => {

  // =========================================================================
  // 1. Classification & Sanitization Unit Invariants
  // =========================================================================
  describe('A. Classification & Sanitization Invariants', () => {
    it('1. Categorizes findings into canonical Safety, Security, Authenticity, and Privacy categories', () => {
      expect(categorizeFinding({ type: 'threat_coercion', title: 'Extortion message' })).toBe('safety');
      expect(categorizeFinding({ type: 'phishing_indicator', title: 'Quishing link' })).toBe('security');
      expect(categorizeFinding({ type: 'possible_ai_generated', title: 'Synthetic markers' })).toBe('authenticity');
      expect(categorizeFinding({ type: 'metadata_anomaly', title: 'GPS coordinates embedded' })).toBe('privacy');
    });

    it('2. Enforces cautious language and prevents absolute claims in UI strings', () => {
      expect(enforceCautiousLanguage('This image is AI-generated')).toBe('has possible synthetic-image indicators');
      expect(enforceCautiousLanguage('This image is definitely fake')).toBe('shows possible manipulation indicators');
      expect(enforceCautiousLanguage('Confirmed AI image detected')).toBe('possible synthetic media indicators image detected');
      expect(enforceCautiousLanguage('Normal text')).toBe('Normal text');
    });

    it('3. Sanitizes sensitive snippets to strip coordinates, passwords, and OTPAuth secrets', () => {
      const dirty = 'Location: 37.7749, -122.4194 and GPSLatitude=37.7749 and WIFI:S:Home;P:SecretPass123; and otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP';
      const clean = sanitizeSnippetSafely(dirty);
      expect(clean).toBeDefined();
      expect(clean).not.toContain('37.7749, -122.4194');
      expect(clean).not.toContain('SecretPass123');
      expect(clean).not.toContain('JBSWY3DPEHPK3PXP');
      expect(clean).toContain('[COORDINATES REDACTED]');
      expect(clean).toContain('[REDACTED_PASSWORD]');
      expect(clean).toContain('[REDACTED_SECRET]');
    });
  });

  // =========================================================================
  // 2. Risk Level Presentation Tests
  // =========================================================================
  describe('B. Risk Level & Confidence Presentation', () => {
    it('4. Clean image result renders LOW RISK, score 0/100, and neutral summary', () => {
      const report = createMockReport();
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('LOW RISK');
      expect(html).toContain('0/100');
      expect(html).toContain('No immediate suspicious threat patterns identified.');
      expect(html).toContain('No suspicious indicators were detected in this message or link.');
    });

    it('5. Medium risk image renders MEDIUM RISK badge and elevated caution banner', () => {
      const report = createMockReport({
        riskLevel: 'medium',
        score: 35,
        findings: [
          {
            id: 'f-1',
            type: 'possible_manipulation',
            severity: 'medium',
            confidence: 'medium',
            title: 'Possible Image Modification Indicators',
            description: 'Processed by digital editing software.',
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('MEDIUM RISK');
      expect(html).toContain('35/100');
      expect(html).toContain('Elevated caution warranted');
    });

    it('6. High risk image renders HIGH RISK badge', () => {
      const report = createMockReport({
        riskLevel: 'high',
        score: 65,
        findings: [
          {
            id: 'f-2',
            type: 'threat_coercion',
            severity: 'high',
            confidence: 'high',
            title: 'Account Suspension Warning',
            description: 'Threatens permanent closure.',
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('HIGH RISK');
      expect(html).toContain('65/100');
    });

    it('7. Critical risk image renders CRITICAL RISK badge and red accents', () => {
      const report = createMockReport({
        riskLevel: 'critical',
        score: 95,
        findings: [
          {
            id: 'f-3',
            type: 'phishing_indicator',
            severity: 'critical',
            confidence: 'high',
            title: 'Malicious Quishing Attack Detected',
            description: 'QR resolves to credential harvesting site.',
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('CRITICAL RISK');
      expect(html).toContain('95/100');
    });

    it('8. Confidence displayed separately from risk level on both mobile and desktop', () => {
      const report = createMockReport({
        riskLevel: 'high',
        confidenceLevel: 'low',
        score: 55,
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      // Desktop
      expect(html).toContain('hidden sm:flex');
      expect(html).toContain('Confidence:');
      // Mobile
      expect(html).toContain('sm:hidden');
      expect(html).toContain('low');
    });
  });

  // =========================================================================
  // 3. Image Intelligence Telemetry Hub (Stages 7.1 - 7.5)
  // =========================================================================
  describe('C. Image Intelligence Telemetry Hub', () => {
    it('9. Stage 7.1 regression: Displays image structure, format, dimensions, and size', () => {
      const imageEvidence: Evidence = {
        id: 'ev-img',
        sourceType: 'image_analysis',
        sourceName: 'ImageEngine Foundation (Stage 7.1)',
        label: 'Image Structure',
        description: 'PNG 1920x1080',
        data: {
          format: 'png',
          width: 1920,
          height: 1080,
          rawSizeBytes: 1048576,
        },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({ evidence: [imageEvidence] });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Image Intelligence Overview');
      expect(html).toContain('Structure &amp; Format');
      expect(html).toContain('PNG');
      expect(html).toContain('1920×1080');
      expect(html).toContain('1.00 MB');
    });

    it('10. Stage 7.2 regression: Displays OCR extraction status, line count, character count, and safe snippet', () => {
      const ocrEvidence: Evidence = {
        id: 'ev-ocr',
        sourceType: 'image_analysis',
        sourceName: 'Gemini Vision OCR Extraction (Stage 7.2)',
        label: 'Visual OCR Text',
        description: 'Extracted text',
        snippet: 'Notice of Immediate Account Suspension. Log in to verify your identity.',
        data: {
          hasText: true,
          lineCount: 3,
          characterCount: 72,
          detectedAppType: 'banking_app',
          truncated: false,
        },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({ evidence: [ocrEvidence] });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Visual OCR Text');
      expect(html).toContain('Text Extracted');
      expect(html).toContain('3 lines');
      expect(html).toContain('72 chars');
      expect(html).toContain('Notice of Immediate Account Suspension');
    });

    it('11. Stage 7.3 regression: Displays QR detection count, payload types, and quishing warning safely', () => {
      const qrEvidence: Evidence = {
        id: 'ev-qr',
        sourceType: 'image_analysis',
        sourceName: 'QR Intelligence Engine (Stage 7.3)',
        label: 'QR Code Analysis',
        description: 'QR detected',
        snippet: 'https://secure-login.suspicious-domain.com/auth',
        data: {
          detectedCount: 1,
          payloadTypes: ['url_uri'],
          hasDangerousScheme: false,
          hasQuishingRisk: true,
        },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({
        riskLevel: 'high',
        evidence: [qrEvidence],
        findings: [
          {
            id: 'f-q',
            type: 'phishing_indicator',
            severity: 'high',
            confidence: 'high',
            title: 'Quishing (QR Phishing) Detected',
            description: 'QR code resolves to a malicious login portal.',
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('QR Intelligence');
      expect(html).toContain('1 Detected');
      expect(html).toContain('URL');
      expect(html).toContain('Quishing Threat');
      expect(html).toContain('https://secure-login.suspicious-domain.com/auth');
    });

    it('12. Stage 7.4 regression: Displays screenshot layout, fraud categories, and claimed organizations', () => {
      const scamEvidence: Evidence = {
        id: 'ev-scam',
        sourceType: 'content_analysis',
        sourceName: 'Visual Scam & Screenshot Fraud Engine (Stage 7.4)',
        label: 'Visual Media Context',
        description: 'Banking fraud screenshot',
        data: {
          isScreenshot: true,
          detectedCategories: ['fake_banking', 'account_suspension'],
          detectedAppType: 'banking_app',
          signalCount: 2,
          claimedEntities: ['Wells Fargo'],
          isEducational: false,
        },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({ evidence: [scamEvidence] });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Visual Media Context');
      expect(html).toContain('Screenshot Layout');
      expect(html).toContain('Banking Fraud Alert');
      expect(html).toContain('Account Suspension Warning');
      expect(html).toContain('Wells Fargo');
    });

    it('13. Stage 7.5 regression: Displays software tag, camera make, resolution, and GPS privacy warning', () => {
      const authEvidence: Evidence = {
        id: 'ev-auth',
        sourceType: 'image_analysis',
        sourceName: 'Authenticity & Manipulation Heuristics (Stage 7.5)',
        label: 'Authenticity & Provenance',
        description: 'Authenticity check',
        data: {
          software: 'Midjourney v6',
          cameraMake: 'Sony Alpha 7',
          resolution: '1024x1024',
          hasGpsData: true,
          hasSoftwareTag: true,
          matchesSyntheticCanvas: true,
        },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({
        evidence: [authEvidence],
        findings: [
          {
            id: 'f-ai',
            type: 'possible_ai_generated',
            severity: 'medium',
            confidence: 'medium',
            title: 'Possible Synthetic or AI-Generated Image Indicators',
            description: 'Contains Midjourney v6 signature.',
          },
          {
            id: 'f-gps',
            type: 'metadata_anomaly',
            severity: 'info',
            confidence: 'medium',
            title: 'GPS Geolocation Metadata Present (Coordinates Redacted)',
            description: 'GPS coordinate markers were scrubbed.',
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Media Authenticity &amp; Provenance');
      expect(html).toContain('Software: Midjourney v6');
      expect(html).toContain('Camera: Sony Alpha 7');
      expect(html).toContain('1024x1024');
      expect(html).toContain('GPS Present (Redacted)');
      expect(html).toContain('Authenticity heuristics evaluate observable metadata');
    });
  });

  // =========================================================================
  // 4. Privacy & Anti-Leakage Defense-in-Depth
  // =========================================================================
  describe('D. Privacy & Sensitive Data Protection', () => {
    it('14. Never renders raw GPS coordinates anywhere in the HTML', () => {
      const report = createMockReport({
        findings: [
          {
            id: 'f-gps',
            type: 'metadata_anomaly',
            severity: 'info',
            confidence: 'medium',
            title: 'GPS Geolocation Metadata Present (Coordinates Redacted)',
            description: 'Coordinates 37.7749, -122.4194 were detected.',
            metadata: {
              evidenceSnippet: 'GPSLatitude=37.7749N, GPSLongitude=122.4194W',
            },
          },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).not.toContain('37.7749N');
      expect(html).not.toContain('122.4194W');
      expect(html).toContain('[GPS DATA REDACTED]');
    });

    it('15. Never renders WiFi passwords or OTPAuth secrets from QR snippets', () => {
      const qrEvidence: Evidence = {
        id: 'ev-secret',
        sourceType: 'image_analysis',
        sourceName: 'QR Intelligence Engine (Stage 7.3)',
        label: 'QR Code',
        description: 'QR WiFi snippet',
        snippet: 'WIFI:S:MyNetwork;T:WPA;P:SuperSecretPassword123;;',
        data: { detectedCount: 1, payloadTypes: ['wifi'] },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({ evidence: [qrEvidence] });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).not.toContain('SuperSecretPassword123');
      expect(html).toContain('[REDACTED_PASSWORD]');
    });

    it('16. Truncates raw OCR dumps into concise bounded snippets', () => {
      const longText = 'A'.repeat(500);
      const ocrEvidence: Evidence = {
        id: 'ev-long',
        sourceType: 'image_analysis',
        sourceName: 'Gemini Vision OCR',
        label: 'OCR',
        description: 'Long OCR',
        snippet: longText,
        data: { hasText: true, characterCount: 500, lineCount: 10 },
        isAiGenerated: false,
        createdAt: new Date().toISOString(),
      };
      const report = createMockReport({ evidence: [ocrEvidence] });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).not.toContain(longText); // should not render entire 500 chars raw
    });
  });

  // =========================================================================
  // 5. Incomplete & Unavailable States
  // =========================================================================
  describe('E. Incomplete & Unavailable States', () => {
    it('17. Displays Analysis Incomplete warning banner when status is failed or risk is unknown', () => {
      const report = createMockReport({
        status: 'failed',
        riskLevel: 'unknown',
        summary: 'Cloudinary media stream timed out after 10000ms.',
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('ANALYSIS INCOMPLETE');
      expect(html).toContain('Analysis Incomplete');
      expect(html).toContain('Cloudinary media stream timed out');
    });
  });

  // =========================================================================
  // 6. Visual Hierarchy & Priority Ordering
  // =========================================================================
  describe('F. Visual Hierarchy & Primary Concern Callout', () => {
    it('18. Renders the Primary Concern featured callout for the most severe finding first', () => {
      const findings: Finding[] = [
        {
          id: 'f-low',
          type: 'metadata_anomaly',
          severity: 'low',
          confidence: 'low',
          title: 'Minor camera EXIF conflict',
          description: 'Minor date inconsistency',
        },
        {
          id: 'f-crit',
          type: 'phishing_indicator',
          severity: 'critical',
          confidence: 'high',
          title: 'Urgent Wire Transfer Scam Lure',
          description: 'Immediate financial theft lure.',
        },
      ];
      const report = createMockReport({
        riskLevel: 'critical',
        findings,
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Primary Concern');
      expect(html).toContain('Urgent Wire Transfer Scam Lure');
      expect(html).toContain('Security Threat');
    });

    it('19. Displays categorized indicator counts in the signal breakdown bar', () => {
      const report = createMockReport({
        findings: [
          { id: '1', type: 'threat_coercion', severity: 'high', confidence: 'high', title: 'Threat' },
          { id: '2', type: 'phishing_indicator', severity: 'high', confidence: 'high', title: 'Phishing' },
          { id: '3', type: 'possible_ai_generated', severity: 'medium', confidence: 'medium', title: 'AI' },
          { id: '4', type: 'metadata_anomaly', severity: 'info', confidence: 'medium', title: 'GPS present' },
        ],
      });
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('Signal Breakdown:');
      expect(html).toContain('Safety: 1');
      expect(html).toContain('Security: 1');
      expect(html).toContain('Authenticity: 1');
      expect(html).toContain('Privacy: 1');
    });
  });

  // =========================================================================
  // 7. Accessibility, Theming & Responsiveness
  // =========================================================================
  describe('G. Accessibility & Theming Semantics', () => {
    it('20. Accessibility attributes: region role, aria-labels, aria-expanded, aria-controls', () => {
      const report = createMockReport();
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).toContain('role="region"');
      expect(html).toContain('aria-label="Safety Checkup Result: LOW RISK"');
      expect(html).toContain('aria-expanded="true"');
      expect(html).toContain('aria-controls="safety-analysis-details"');
      expect(html).toContain('aria-hidden="true"');
    });

    it('21. Theme divergence: renders Security Inspection title in security-checkup theme', () => {
      const report = createMockReport();
      const html = renderToString(
        React.createElement(SafetyAnalysisCard, {
          report,
          themeSlug: 'security-checkup',
        })
      );

      expect(html).toContain('Security Inspection');
      expect(html).toContain('Deterministic score:');
    });

    it('22. Renders with semantic CSS tokens without hardcoded hex colors', () => {
      const report = createMockReport();
      const html = renderToString(React.createElement(SafetyAnalysisCard, { report }));

      expect(html).not.toMatch(/#[0-9a-fA-F]{6}/);
      expect(html).toContain('bg-card');
      expect(html).toContain('text-card-foreground');
    });
  });
});
