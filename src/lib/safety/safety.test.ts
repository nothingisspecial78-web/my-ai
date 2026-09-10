import { describe, it, expect } from 'vitest';
import {
  SafetyInputType,
  AnalyzerType,
  RiskLevel,
  ConfidenceLevel,
  Finding,
  Evidence,
  AiContentAssessment,
  ClaimVerificationStatus,
} from './types';
import { InputClassifier } from './analyzers/input-classifier';
import { RiskEngine } from './risk-engine';
import { SafetyService } from './service';

describe('Phase 4.6: Safety & Security Analysis Architecture', () => {

  // 1. Input Type Validation
  it('1. Validates supported safety input types', () => {
    const validTypes: SafetyInputType[] = [
      'url', 'message', 'email', 'image', 'screenshot',
      'document', 'file', 'qr', 'website', 'code', 'claim', 'social_post'
    ];
    expect(validTypes.length).toBe(12);

    expect(InputClassifier.classify({ rawContent: 'https://example.com' })).toBe('url');
    expect(InputClassifier.classify({ rawContent: 'Hello from mom, call me back' })).toBe('message');
    expect(InputClassifier.classify({ rawContent: 'user@example.com' })).toBe('email');
    expect(InputClassifier.classify({ rawContent: 'function test() { const a = 1; }' })).toBe('code');
    expect(InputClassifier.classify({ rawContent: 'some image', mimeType: 'image/png' })).toBe('image');
    expect(InputClassifier.classify({ rawContent: 'document content', filename: 'report.pdf' })).toBe('document');
  });

  // 2. Analyzer Type Validation
  it('2. Validates supported analyzer types', () => {
    const validAnalyzers: AnalyzerType[] = [
      'url', 'phishing', 'spam', 'scam', 'domain', 'redirect', 'qr',
      'image_ai', 'image_manipulation', 'document', 'file', 'email',
      'message', 'claim', 'code_security', 'website'
    ];
    expect(validAnalyzers).toContain('url');
    expect(validAnalyzers).toContain('scam');
    expect(validAnalyzers).toContain('code_security');
  });

  // 3. Risk Level and Confidence Level Validation
  it('3. Decouples risk level from confidence level', () => {
    const riskLevels: RiskLevel[] = ['low', 'medium', 'high', 'critical', 'unknown'];
    const confidenceLevels: ConfidenceLevel[] = ['low', 'medium', 'high'];

    expect(riskLevels).toContain('critical');
    expect(riskLevels).toContain('unknown');
    expect(confidenceLevels).not.toContain('critical'); // Confidence is NOT risk!
  });

  // 4. Finding and Evidence Relationship
  it('4. Creates structured findings linked to observable evidence', () => {
    const evidence: Evidence = {
      id: 'ev-1',
      sourceType: 'url_analysis',
      sourceName: 'URL Parser',
      description: 'Extracted hostname and protocol',
      data: { hostname: 'paypal-security-update.xyz', protocol: 'http:' },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    };

    const finding: Finding = {
      id: 'f-1',
      type: 'lookalike_domain',
      severity: 'high',
      title: 'Brand Impersonation in Domain',
      description: 'The domain mimics PayPal without official domain registration.',
      evidenceIds: [evidence.id],
      confidence: 'high',
    };

    expect(finding.evidenceIds).toContain('ev-1');
    expect(evidence.isAiGenerated).toBe(false);
  });

  // 5. Findings Remain Distinguishable from AI Explanations
  it('5. Distinguishes deterministic evidence from AI reasoning', () => {
    const deterministicEvidence: Evidence = {
      id: 'ev-det',
      sourceType: 'deterministic_rule',
      sourceName: 'Regex Pattern Matcher',
      description: 'Pattern matched OTP request keywords',
      data: { pattern: 'share your code' },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    };

    const aiEvidence: Evidence = {
      id: 'ev-ai',
      sourceType: 'ai_assessment',
      sourceName: 'Gemini Safety Reasoning',
      description: 'Model contextual interpretation of deceptive intent',
      data: { reasoning: 'Sender combines urgency with authority' },
      isAiGenerated: true,
      createdAt: new Date().toISOString(),
    };

    expect(deterministicEvidence.isAiGenerated).toBe(false);
    expect(aiEvidence.isAiGenerated).toBe(true);
  });

  // 6. Low-Risk Scenario
  it('6. Evaluates low-risk benign scenario without alarmist flags', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://google.com/search?q=weather',
      type: 'url',
    });

    expect(report.riskLevel).toBe('low');
    expect(report.score).toBeLessThanOrEqual(10);
    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(report.recommendations[0].action).toBe('no_action_needed');
  });

  // 7. High-Risk / Critical Scenario (Phishing / OTP theft)
  it('7. Evaluates critical risk when OTP solicitation is detected', async () => {
    const scamText = 'URGENT: Your bank account will be suspended in 24 hours. Reply with your one-time password OTP immediately to verify your identity.';
    const report = await SafetyService.analyze({
      rawContent: scamText,
      type: 'message',
    });

    expect(report.riskLevel).toBe('critical');
    expect(report.findings.some(f => f.type === 'otp_request')).toBe(true);
    expect(report.findings.some(f => f.type === 'urgency_language')).toBe(true);
    expect(report.recommendations.some(r => r.action === 'do_not_share_otp')).toBe(true);
  });

  // 8. High-Risk Scenario (Brand Impersonation & IP Hostname)
  it('8. Evaluates high risk for suspicious URL with brand spoofing', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'http://192.168.1.1/paypal/login?token=secret123',
      type: 'url',
    });

    expect(['high', 'critical']).toContain(report.riskLevel);
    expect(report.findings.some(f => f.type === 'ip_as_host')).toBe(true);
    expect(report.findings.some(f => f.type === 'lookalike_domain')).toBe(true);
    expect(report.findings.some(f => f.type === 'credential_in_url')).toBe(true);
    expect(report.recommendations.some(r => r.action === 'verify_domain')).toBe(true);
  });

  // 9. Code Security: Hardcoded Secrets & Dangerous Sinks
  it('9. Detects hardcoded secrets and dangerous code execution', async () => {
    const dangerousCode = `
      const API_KEY = "ghp_123456789012345678901234567890123456";
      function execute(userInput) {
        eval(userInput);
        db.query("SELECT * FROM users WHERE id = " + userInput);
      }
    `;

    const report = await SafetyService.analyze({
      rawContent: dangerousCode,
      type: 'code',
    });

    expect(['high', 'critical']).toContain(report.riskLevel);
    expect(report.findings.some(f => f.type === 'exposed_secret')).toBe(true);
    expect(report.findings.some(f => f.type === 'dangerous_function')).toBe(true);
    expect(report.findings.some(f => f.type === 'sql_injection_pattern')).toBe(true);
    expect(report.recommendations.some(r => r.action === 'rotate_exposed_secret')).toBe(true);
  });

  // 10. Unknown / Inconclusive Scenario
  it('10. Evaluates unknown scenario gracefully when input cannot be parsed', () => {
    const evalResult = RiskEngine.evaluate([], []);
    expect(evalResult.riskLevel).toBe('unknown');
    expect(evalResult.confidenceLevel).toBe('low');
    expect(evalResult.recommendations.some(r => r.action === 'proceed_with_caution')).toBe(true);
  });

  // 11. Uncertainty Preservation: No universal "safe=true" or "malicious=true"
  it('11. Preserves uncertainty and explicitly documents limitations', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://subdomain.example.xyz',
      type: 'url',
    });

    // Check that report does NOT contain an absolute boolean "is_safe: boolean" or "is_malicious: boolean"
    expect('is_safe' in report).toBe(false);
    expect('is_malicious' in report).toBe(false);

    // Universal limitation must always be present
    expect(report.limitations.some(l => l.includes('Absence of flags is not an absolute guarantee'))).toBe(true);
  });

  // 12. AI Content Detection Supports Probabilistic Assessment & Confidence
  it('12. Represents AI-generated content assessments probabilistically', () => {
    const possibleAssessments: AiContentAssessment[] = [
      'likely_ai_generated',
      'possibly_ai_generated',
      'no_strong_ai_signal',
      'unknown'
    ];
    expect((possibleAssessments as string[])).not.toContain('100%_ai_generated');
    expect((possibleAssessments as string[])).not.toContain('certified_human');
  });

  // 13. Claim Verification Supports Unverified / Disputed
  it('13. Supports nuanced claim verification states instead of binary truth', () => {
    const claimStatuses: ClaimVerificationStatus[] = [
      'verified',
      'likely_true',
      'unverified',
      'disputed',
      'likely_false',
      'unknown'
    ];
    expect(claimStatuses).toContain('unverified');
    expect(claimStatuses).toContain('disputed');
  });

  // 14. Recommendations are Structured and Proportional
  it('14. Produces structured, non-alarmist recommendations', () => {
    const finding: Finding = {
      id: 'f-1',
      type: 'suspicious_domain',
      severity: 'medium',
      title: 'Uncommon TLD',
      description: 'Domain uses uncommon TLD',
      confidence: 'medium',
    };

    const evalResult = RiskEngine.evaluate([finding], [{
      analyzerId: 'url-analyzer',
      analyzerType: 'url',
      status: 'success',
      confidence: 'medium',
      findings: [finding],
      evidence: [],
    }]);

    expect(evalResult.recommendations.length).toBeGreaterThan(0);
    for (const rec of evalResult.recommendations) {
      expect(rec.action).toBeDefined();
      expect(rec.title).toBeDefined();
      expect(rec.description).toBeDefined();
      expect(['low', 'medium', 'high']).toContain(rec.priority);
    }
  });

  // 15. Uploaded Content Treated as Untrusted
  it('15. Treats uploaded content strictly as data without executing it', async () => {
    // Malicious script payload injected in input
    const maliciousPayload = '<script>alert("xss")</script>; DROP TABLE users;';
    const report = await SafetyService.analyze({
      rawContent: maliciousPayload,
      filename: 'exploit.js',
    });

    // Content was analyzed safely without evaluating or crashing
    expect(report.status).toBe('completed');
    expect(report.inputType).toBe('code');
  });

  // 16. No Old طب النبي Logic Accidentally Used in Safety Analyzer
  it('16. Does not invoke or depend on Prophetic Medicine logic', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://security-verify-login.top/account',
      type: 'url',
    });

    // Check report for any accidental references to hadith or old domain
    const jsonStr = JSON.stringify(report);
    expect(jsonStr).not.toContain('tibb-al-nabi');
    expect(jsonStr).not.toContain('hadith');
    expect(jsonStr).not.toContain('Ibn Qayyim');
  });

  // 17. Formatting for Gemini Reasoning Layer
  it('17. Formats structured context for Gemini without hallucinations', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Urgent: Click here to claim your $10,000 lottery winnings!',
      type: 'message',
    });

    const geminiContext = SafetyService.formatForGemini(report);
    expect(geminiContext).toContain('=== SAFETY & SECURITY DETERMINISTIC ANALYSIS ===');
    expect(geminiContext).toContain('Assessed Risk Level: HIGH');
    expect(geminiContext).toContain('Actionable Recommendations:');
    expect(geminiContext).toContain('Do NOT invent external security vendor results');
  });
});
