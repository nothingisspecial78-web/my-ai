import crypto from 'crypto';
import { SafetyAnalyzer } from './base';
import {
  SafetyInput,
  AnalyzerResult,
  Finding,
  Evidence,
  ConfidenceLevel,
} from '../types';

/**
 * Deterministic Message, Email & Social Post Scam Analyzer.
 * Identifies social engineering patterns: urgency, OTP requests, fake authority, financial lures.
 */
export class MessageScamAnalyzer implements SafetyAnalyzer {
  readonly id = 'message-scam-analyzer';
  readonly type = 'scam' as const;
  readonly supportedInputTypes = ['message', 'email', 'social_post', 'claim'] as const;

  // Pattern categories
  private static URGENCY_PATTERNS = [
    /\b(immediately|act now|urgent|within (24|12|48) hours|account will be (suspended|closed|locked|terminated)|last chance|final notice)\b/i,
    /\b(arrest warrant|legal action|court summons|police department)\b/i,
  ];

  private static OTP_PATTERNS = [
    /\b(one[-\s]?time[-\s]?password|otp|verification code|security code|2fa code|confirm your pin)\b/i,
    /\b(share (your|the) (code|pin|otp)|send (me|us) (the|your) (code|otp))\b/i,
  ];

  private static CREDENTIAL_PATTERNS = [
    /\b(verify your (password|account|identity)|update your (credentials|banking|login)|enter your (ssn|social security|credit card))\b/i,
  ];

  private static FINANCIAL_LURE_PATTERNS = [
    /\b(won|winner|lottery|prize|claim your (reward|prize|\$\d+|₹\d+)|guaranteed returns?|make \$\d+ daily|no risk investment)\b/i,
    /\b(crypto investment opportunity|passive income guaranteed|congratulations you have been selected)\b/i,
  ];

  private static IMPERSONATION_PATTERNS = [
    /\b(internal revenue service|irs|income tax department|fedex delivery|ups package|dhl shipment|usps parcel|customs duty)\b/i,
    /\b(bank customer support|security team of (apple|google|microsoft|amazon|netflix))\b/i,
  ];

  private static SECRECY_PATTERNS = [
    /\b(do not tell anyone|keep this confidential|between you and me|secret assignment|don't tell your family)\b/i,
  ];

  canAnalyze(input: SafetyInput): boolean {
    if (input.type && (this.supportedInputTypes as readonly string[]).includes(input.type)) {
      return true;
    }
    // Any multi-word message text can be analyzed for scam signals
    return typeof input.rawContent === 'string' && input.rawContent.trim().length > 10;
  }

  async analyze(input: SafetyInput): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];
    const text = input.rawContent;

    const evidenceId = crypto.randomUUID();
    evidence.push({
      id: evidenceId,
      sourceType: 'content_analysis',
      sourceName: 'Heuristic Content Pattern Matcher',
      description: 'Extracted semantic signals and keyword matches from message text',
      data: { textLength: text.length },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    // 1. OTP / 2FA Solicitation (Critical Phishing / Scam Indicator)
    let hasOtp = false;
    for (const pattern of MessageScamAnalyzer.OTP_PATTERNS) {
      if (pattern.test(text)) {
        hasOtp = true;
        break;
      }
    }
    if (hasOtp) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'otp_request',
        severity: 'critical',
        title: 'Request for One-Time Password (OTP) or Verification Code',
        description: 'Legitimate institutions never ask you to share your OTP or verification code with third parties or via message.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 2. Direct Credential Solicitation
    let hasCredential = false;
    for (const pattern of MessageScamAnalyzer.CREDENTIAL_PATTERNS) {
      if (pattern.test(text)) {
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
        description: 'The message pressures the recipient to provide passwords, banking credentials, or personal identification.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 3. Artificial Urgency or Threat Language
    let hasUrgency = false;
    for (const pattern of MessageScamAnalyzer.URGENCY_PATTERNS) {
      if (pattern.test(text)) {
        hasUrgency = true;
        break;
      }
    }
    if (hasUrgency) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'urgency_language',
        severity: 'medium',
        title: 'High Urgency or Threat Pressure',
        description: 'Artificial time limits or threats of account suspension/legal action are standard psychological manipulation tactics.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 4. Unrealistic Financial Lures
    let hasFinancialLure = false;
    for (const pattern of MessageScamAnalyzer.FINANCIAL_LURE_PATTERNS) {
      if (pattern.test(text)) {
        hasFinancialLure = true;
        break;
      }
    }
    if (hasFinancialLure) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'financial_request',
        severity: 'high',
        title: 'Unrealistic Financial Incentive or Lottery Claim',
        description: 'Offers of guaranteed investment returns, unearned prize money, or lottery winnings strongly correlate with advance-fee scams.',
        evidenceIds: [evidenceId],
        confidence: 'high',
      });
    }

    // 5. Authority / Institution Impersonation
    let hasImpersonation = false;
    for (const pattern of MessageScamAnalyzer.IMPERSONATION_PATTERNS) {
      if (pattern.test(text)) {
        hasImpersonation = true;
        break;
      }
    }
    if (hasImpersonation) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'authority_impersonation',
        severity: 'medium',
        title: 'Delivery, Government, or Tech Support Impersonation Context',
        description: 'The message references government agencies, shipping couriers, or major tech companies commonly spoofed in fraud campaigns.',
        evidenceIds: [evidenceId],
        confidence: 'medium',
      });
    }

    // 6. Secrecy Request
    for (const pattern of MessageScamAnalyzer.SECRECY_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({
          id: crypto.randomUUID(),
          type: 'scam_indicator',
          severity: 'high',
          title: 'Request for Secrecy or Channel Bypass',
          description: 'The sender explicitly instructs you not to disclose the communication or verify with colleagues/family.',
          evidenceIds: [evidenceId],
          confidence: 'high',
        });
        break;
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
        'Analysis is based on linguistic heuristics and known pattern matches.',
        'Legitimate communications with urgent deadlines can occasionally trigger urgency indicators.',
      ],
    };
  }
}
