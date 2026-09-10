import crypto from 'crypto';
import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
  Finding,
  Evidence,
  ConfidenceLevel,
} from '../types';
import { UrlAnalyzer } from './url-analyzer';
import { redactSensitiveText } from '../redaction';

/**
 * Deterministic Message, Email & Social Post Scam Analyzer.
 * Identifies social engineering patterns: urgency, OTP requests, fake authority, financial lures,
 * and extracts/analyzes any embedded links.
 */
export class MessageScamAnalyzer implements SafetyAnalyzer {
  readonly id = 'message-scam-analyzer';
  readonly type = 'scam' as const;
  readonly supportedInputTypes = ['message', 'email', 'social_post', 'claim'] as const;

  // Pattern categories (calibrated to minimize false alarms on benign casual text)
  private static URGENCY_PATTERNS = [
    /\b(immediately|act now|urgent|within (?:12|24|48) hours|final warning|final notice|last chance|action required)\b/i,
    /\baccount will be (?:suspended|closed|locked|terminated) today\b/i,
  ];

  private static THREAT_PATTERNS = [
    /\b(account (?:has been |is |will be )?(?:suspended|blocked|locked|terminated)|legal action|arrest warrant|court summons|penalty imposed)\b/i,
  ];

  private static OTP_PATTERNS = [
    /\b(one[-\s]?time[-\s]?password|otp|verification code|security code|2fa code)\b/i,
    /\b(share (?:your|the)? (?:code|pin|otp)|send (?:me|us)? (?:the|your)? (?:code|otp)|confirm your pin)\b/i,
  ];

  private static CREDENTIAL_PATTERNS = [
    /\b(verify your (?:password|account|identity|login)|update your (?:credentials|banking|login)|enter your (?:password|ssn|credentials))\b/i,
  ];

  private static FINANCIAL_REQUEST_PATTERNS = [
    /\b(send money|payment required|wire transfer|processing fee|paying a (?:processing )?fee|pay (?:a|the) fee|gift card|cryptocurrency transfer|bank details)\b/i,
  ];

  private static PRIZE_LURE_PATTERNS = [
    /\b(congratulations|you(?:'ve| have)? won|lottery prize|claim your (?:reward|prize|\$\d+|₹\d+)|selected as winner)\b/i,
  ];

  // Specific authority or institution spoofing context (avoids matching casual "my bank")
  private static AUTHORITY_PATTERNS = [
    /\b(your bank account|bank security|bank customer support|security team of (?:apple|google|microsoft|amazon|netflix))\b/i,
    /\b(internal revenue service|irs|income tax department|customs duty|fedex delivery|ups package|dhl shipment|usps parcel)\b/i,
  ];

  private static SECRECY_PATTERNS = [
    /\b(do not tell anyone|keep this confidential|between you and me|secret assignment|don't tell your family)\b/i,
  ];

  private urlAnalyzer = new UrlAnalyzer();

  canAnalyze(input: SafetyInput): boolean {
    if (input.type) {
      return (this.supportedInputTypes as readonly string[]).includes(input.type);
    }
    // Any multi-word message text can be analyzed for scam signals
    return typeof input.rawContent === 'string' && input.rawContent.trim().length > 8;
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const rawText = input.rawContent;
    const sanitizedText = redactSensitiveText(rawText);

    const evidenceId = crypto.randomUUID();
    evidence.push({
      id: evidenceId,
      sourceType: 'content_analysis',
      sourceName: 'Heuristic Content Pattern Matcher',
      description: 'Extracted semantic signals and keyword matches from message text',
      data: { textLength: rawText.length, preview: sanitizedText.substring(0, 120) },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    // 1. OTP / 2FA Solicitation
    let hasOtp = false;
    for (const pattern of MessageScamAnalyzer.OTP_PATTERNS) {
      if (pattern.test(rawText)) {
        hasOtp = true;
        break;
      }
    }
    if (hasOtp) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'otp_request',
        severity: 'high',
        title: 'Request for One-Time Password (OTP) or Verification Code',
        description: 'Legitimate institutions never request your OTP, PIN, or verification code via message.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 2. Direct Credential Solicitation
    let hasCredential = false;
    for (const pattern of MessageScamAnalyzer.CREDENTIAL_PATTERNS) {
      if (pattern.test(rawText)) {
        hasCredential = true;
        break;
      }
    }
    if (hasCredential) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'credential_request',
        severity: 'high',
        title: 'Account Verification / Credential Solicitation',
        description: 'The message pressures the recipient to enter or provide passwords or account login details.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 3. Artificial Urgency
    let hasUrgency = false;
    for (const pattern of MessageScamAnalyzer.URGENCY_PATTERNS) {
      if (pattern.test(rawText)) {
        hasUrgency = true;
        break;
      }
    }
    if (hasUrgency) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'urgency_language',
        severity: 'medium',
        title: 'Urgency Pressure Language',
        description: 'Artificial time limits ("immediately", "within 24 hours") are standard psychological pressure tactics.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 4. Threat Coercion (Account suspended, legal action)
    let hasThreat = false;
    for (const pattern of MessageScamAnalyzer.THREAT_PATTERNS) {
      if (pattern.test(rawText)) {
        hasThreat = true;
        break;
      }
    }
    if (hasThreat) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'threat_coercion',
        severity: 'medium',
        title: 'Account Suspension or Penalty Threat',
        description: 'The message warns of account suspension, closure, or legal enforcement to induce panic.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 5. Prize / Reward Lures
    let hasPrize = false;
    for (const pattern of MessageScamAnalyzer.PRIZE_LURE_PATTERNS) {
      if (pattern.test(rawText)) {
        hasPrize = true;
        break;
      }
    }
    if (hasPrize) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'prize_lure',
        severity: 'high',
        title: 'Unrealistic Prize or Lottery Reward Lure',
        description: 'Announcements of lottery winnings, unearned prizes, or guaranteed payouts correlate strongly with advance-fee scams.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 6. Financial Requests / Upfront Fees
    let hasFinancial = false;
    for (const pattern of MessageScamAnalyzer.FINANCIAL_REQUEST_PATTERNS) {
      if (pattern.test(rawText)) {
        hasFinancial = true;
        break;
      }
    }
    if (hasFinancial) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'financial_request',
        severity: 'high',
        title: 'Payment or Advance Fee Request',
        description: 'The communication requests money, processing fees, or wire transfers.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 7. Authority / Institutional Impersonation Context
    let hasAuthority = false;
    for (const pattern of MessageScamAnalyzer.AUTHORITY_PATTERNS) {
      if (pattern.test(rawText)) {
        hasAuthority = true;
        break;
      }
    }
    if (hasAuthority) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'authority_impersonation',
        severity: 'medium',
        title: 'Institutional or Support Impersonation Context',
        description: 'The message references banking security, postal couriers, or government agencies frequently spoofed in fraud campaigns.',
        evidenceIds: [evidenceId],
        confidence: 'medium',
      });
    }

    // 8. Secrecy Request
    for (const pattern of MessageScamAnalyzer.SECRECY_PATTERNS) {
      if (pattern.test(rawText)) {
        findings.push({
          id: crypto.randomUUID(),
          type: 'scam_indicator',
          severity: 'high',
          title: 'Request for Secrecy or Channel Bypass',
          description: 'The sender explicitly requests confidentiality or asks you not to verify with family or official contacts.',
          evidenceIds: [evidenceId],
          confidence: 'high',
        });
        break;
      }
    }

    // ----------------------------------------------------
    // 9. Embedded Link Extraction & Nested URL Analysis
    // ----------------------------------------------------
    const extractedUrls = rawText.match(/(?:https?:\/\/|www\.)[^\s<>"]+/gi) || [];
    for (const urlStr of extractedUrls) {
      try {
        const urlResult = await this.urlAnalyzer.analyze({
          type: 'url',
          rawContent: urlStr,
        });
        // Merge findings and evidence
        findings.push(...urlResult.findings);
        evidence.push(...urlResult.evidence);
      } catch {
        // Safe tolerance if an individual embedded URL cannot be analyzed
      }
    }

    const confidence: ConfidenceLevel = findings.length > 0 ? 'high' : 'medium';

    return {
      analyzerId: this.id,
      analyzerType: this.type,
      status: 'success',
      confidence,
      findings,
      evidence,
      limitations: [
        'Analysis is based on linguistic heuristics and observable pattern indicators.',
        'Legitimate communications may occasionally mention deadlines; context should always be evaluated carefully.',
        'No external phone number or email sender reputation database was queried.',
      ],
    };
  }
}
