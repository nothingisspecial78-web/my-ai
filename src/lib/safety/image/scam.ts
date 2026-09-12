/**
 * Visual Scam & Screenshot Fraud Intelligence (Stage 7.4)
 * 
 * Deterministic detection and multi-signal correlation for visual scam screenshots,
 * fake banking alerts, package delivery lures, crypto drainers, KYC intimidation,
 * and credential harvesting prompts.
 * 
 * STRICT INVARIANTS:
 * 1. UNTRUSTED INPUT: OCR text and visual cues are untrusted user data.
 * 2. ZERO GEMINI RISK SCORING: Gemini models never assign risk scores or verdicts.
 * 3. SOLE SCORING AUTHORITY: RiskEngine is the sole authority on score & risk level.
 * 4. PURE DETERMINISTIC LOGIC: Zero fetch, zero DNS, zero eval, zero native C++ deps.
 * 5. COMPLETE REDACTION: Sensitive OTPs, PINs, passwords, and keys are redacted.
 * 6. OBSERVATIONAL VOCABULARY: Observational terms ("suspicious", "potential indicator")
 *    are used; never declare a legitimate brand or image definitively fraudulent.
 */

import crypto from 'crypto';
import {
  Finding,
  Evidence,
  Recommendation,
} from '@/lib/safety/types';
import { LoadedImageContent } from '@/lib/attachments/loader';
import { redactSensitiveText } from '@/lib/safety/redaction';
import {
  EntityMatcher,
  SocialEngineeringAnalyzer,
  ScamAnalysisResult,
  ScamEngine,
} from '@/lib/safety/scam';
import {
  SanitizedOcrResult,
  SanitizedQrAnalysisResult,
  VisualScamCategory,
  VisualScamSignal,
  SanitizedVisualScamResult,
  DetectedAppType,
} from './types';

export interface VisualScamAnalysisOptions {
  scamResult?: ScamAnalysisResult;
}

// Regex patterns for deterministic visual screenshot fraud detection

const BANKING_SUSPENSION_PATTERNS = [
  /\b(?:account|card|online banking|access|profile)\s+(?:has been|is|will be|was)\s+(?:blocked|suspended|frozen|locked|restricted|deactivated|disabled|terminated)\b/i,
  /\b(?:unblock|reactivate|verify|restore|unlock|update)\s+your\s+(?:account|card|access|online banking)\b/i,
  /\b(?:unauthorized|suspicious|fraudulent)\s+(?:transaction|activity|charge|transfer|login|attempt)\b/i,
  /\b(?:fraud prevention|security alert|fraud detection)\s*[:\-]?\s*(?:your account|unusual activity)/i,
  /\b(?:immediate action required to prevent account termination|click here to unblock your account)\b/i,
];

const COURIER_SCAM_PATTERNS = [
  /\b(?:package|parcel|shipment|delivery|order)\s+(?:cannot be delivered|on hold|held|pending|failed|undelivered|stopped|delayed)\b/i,
  /\b(?:unpaid|outstanding|required|reschedule|customs|handling|redelivery)\s+(?:fee|charge|cost|payment|tax)\b/i,
  /\b(?:pay|settle)\s+(?:shipping|delivery|customs|fee)\b/i,
  /\bupdate\s+(?:your\s+)?(?:delivery\s+)?address\s+to\s+(?:receive|redeliver|release)\b/i,
];

const ACCOUNT_SUSPENSION_PATTERNS = [
  /\b(?:account\s+(?:will be|is)\s+(?:deleted|terminated|closed|disabled|suspended)\s+(?:within|in|by))\b/i,
  /\b(?:final notice|urgent warning|immediate action required|action required immediately|last chance to verify)\b/i,
  /\b(?:verify your account within \d+\s*(?:hours?|minutes?)|account will be closed permanently)\b/i,
];

const KYC_VERIFICATION_PATTERNS = [
  /\b(?:kyc|know your customer|identity verification|pan card|aadhaar|ssn|social security number)\s+(?:verification|update|expired|mandatory|required|pending|failed)\b/i,
  /\b(?:update|complete|submit|verify)\s+(?:your\s+)?(?:kyc|pan|aadhaar|id|identity)\s+(?:immediately|now|to avoid|before)\b/i,
  /\b(?:mandatory kyc update|kyc verification required to continue using)\b/i,
];

const CREDENTIAL_HARVESTING_PATTERNS = [
  /\b(?:enter|provide|send|submit|share|fill in|confirm)\s+(?:your\s+)?(?:otp|one[-\s]?time password|verification code|security code|pin\b)\b/i,
  /\b(?:enter|provide|submit)\s+(?:your\s+)?(?:password|current password|login credentials|cvv|card number)\b/i,
  /\b(?:login|sign in)\s+(?:to verify|to unblock|to confirm your identity|to secure your account)\b/i,
];

const CRYPTO_FRAUD_PATTERNS = [
  /\b(?:seed phrase|recovery phrase|secret recovery phrase|mnemonic phrase|private key|12 words|24 words)\b/i,
  /\b(?:connect\s+wallet\s+to\s+claim|sync\s+wallet|claim\s+airdrop|wallet\s+validation|rectify\s+wallet|restore\s+wallet)\b/i,
  /\b(?:input your 12-word seed phrase|enter private key to restore)\b/i,
];

const PRIZE_REWARD_PATTERNS = [
  /\b(?:congratulations|you have won|winner|selected as (?:the )?winner|claim your prize|lucky draw|cash prize|gift card reward|lottery winning)\b/i,
];

const PRIZE_FEE_PATTERNS = [
  /\b(?:claim now|click to claim|processing fee|shipping fee|taxes to claim|deposit to claim|release fee|pay fee to receive)\b/i,
];

const PAYMENT_RECEIPT_PATTERNS = [
  /\b(?:payment successful|transfer completed|money sent|transaction receipt|funds transferred)\b/i,
];

const PAYMENT_REVERSAL_PATTERNS = [
  /\b(?:refund|overpaid|overpayment|send back|reversed|cancelled|click to receive|claim refund|dispute payment)\b/i,
];

const CUSTOMER_SUPPORT_PATTERNS = [
  /\b(?:tech support|customer care|helpdesk|support helpline|call support)\s+(?:at|on|number)?:?\s*(?:\+?\d[\d\s-]{7,})/i,
  /\b(?:install|download)\s+(?:anydesk|teamviewer|ultraviewer|quicksupport|remote desktop)\b/i,
];

const GOVERNMENT_LEGAL_PATTERNS = [
  /\b(?:court order|arrest warrant|police department|law enforcement|tax evasion|customs seized|irs notice|legal penalty|legal action)\b/i,
];

const GOVERNMENT_SETTLE_PATTERNS = [
  /\b(?:pay fine|settle immediately|avoid arrest|warrant issued|case file|immediate payment)\b/i,
];

const SOCIAL_MEDIA_WARNING_PATTERNS = [
  /\b(?:copyright infringement|community guidelines violation|account will be permanently disabled|trademark violation)\b/i,
];

const SOCIAL_MEDIA_APPEAL_PATTERNS = [
  /\b(?:appeal here|appeal within|submit appeal|verify copyright|appeal form)\b/i,
];

const URGENCY_PATTERNS = [
  /\b(?:within 24 hours|within 12 hours|within 1 hour|within 15 minutes|immediate action required|act now|expires today|limited time only)\b/i,
];

const EDUCATIONAL_PATTERNS = [
  /\b(?:security awareness training|phishing simulation|infosec training|example of (?:a )?(?:scam|phishing)|how to spot (?:a )?scam|educational example|cybersecurity awareness)\b/i,
];

/**
 * Analyzes OCR text and visual layout context to identify scam screenshot indicators deterministically.
 */
export async function analyzeVisualScamSignals(
  loaded: LoadedImageContent,
  ocrResult?: SanitizedOcrResult,
  qrResult?: SanitizedQrAnalysisResult,
  options?: VisualScamAnalysisOptions
): Promise<SanitizedVisualScamResult> {
  const limitations: string[] = [];
  const findings: Finding[] = [];
  const evidence: Evidence[] = [];
  const recommendations: Recommendation[] = [];
  const signals: VisualScamSignal[] = [];
  const detectedCategories = new Set<VisualScamCategory>();

  // 1. Check OCR availability
  if (!ocrResult || ocrResult.status === 'unavailable') {
    return {
      status: 'inconclusive',
      isScreenshot: false,
      detectedCategories: [],
      signals: [],
      findings: [],
      evidence: [],
      recommendations: [
        {
          action: 'proceed_with_caution',
          title: 'Exercise Caution With Unverified Visual Media',
          description: 'Visual text and layout could not be extracted. Verify the origin of this image through independent channels.',
          priority: 'medium',
        },
      ],
      limitations: [
        'Visual scam and screenshot fraud inspection was inconclusive because visual OCR extraction was unavailable.',
      ],
    };
  }

  const isScreenshot = Boolean(ocrResult.visualContext?.isScreenshot);
  const detectedAppType: DetectedAppType | undefined = ocrResult.visualContext?.detectedAppType;
  const rawText = ocrResult.sanitizedText || '';
  const text = rawText.trim();

  // 2. Check if text is empty
  if (!ocrResult.hasText || text.length === 0) {
    return {
      status: 'clean',
      isScreenshot,
      detectedAppType,
      detectedCategories: [],
      signals: [],
      findings: [],
      evidence: [],
      recommendations: [
        {
          action: 'proceed_with_caution',
          title: 'Standard Digital Vigilance',
          description: 'No text or deceptive visual cues were detected in the image.',
          priority: 'low',
        },
      ],
      limitations: [],
    };
  }

  // 3. Prompt Injection Resistance
  // Any adversarial instruction inside the OCR text is treated as passive content.
  // We do not evaluate or execute code, nor do we let it alter our rules.

  // 4. Context Guardrails: Educational / Meta inquiry check
  const isEducational =
    SocialEngineeringAnalyzer.isEducationalOrMetaQuestion(text) ||
    EDUCATIONAL_PATTERNS.some(pat => pat.test(text));

  // 5. Evaluate Phase 6.2 ScamEngine (reusing existing precomputed result if provided)
  let scamResult = options?.scamResult;
  if (!scamResult) {
    try {
      scamResult = await ScamEngine.analyze(text);
    } catch {
      // ScamEngine tolerance: failure does not break image scam analysis
    }
  }

  // Helper to extract a safe, redacted snippet from text
  const getRedactedSnippet = (regex: RegExp): string => {
    const match = text.match(regex);
    if (!match) return '';
    const rawSnippet = match[0];
    return redactSensitiveText(rawSnippet);
  };

  // Helper to test if any pattern in a list matches
  const hasMatch = (patterns: RegExp[]): boolean => patterns.some(p => p.test(text));

  // 6. Category Detectors

  // A. Fake Banking / Account Suspension / Security Alert
  const isBankingSuspension = hasMatch(BANKING_SUSPENSION_PATTERNS);
  if (isBankingSuspension) {
    detectedCategories.add('fake_banking');
    signals.push({
      category: 'fake_banking',
      severity: 'high',
      title: 'Suspicious Banking Alert or Account Suspension Screenshot',
      description:
        'Screenshot exhibits urgent account suspension, blocking, or security alert language characteristic of banking fraud or phishing lures.',
      findingType: 'threat_coercion',
      confidence: detectedAppType === 'banking' || isScreenshot ? 'high' : 'medium',
      evidenceSnippet: getRedactedSnippet(BANKING_SUSPENSION_PATTERNS[0]),
      dedupKey: 'threat_coercion::banking_suspension',
    });
  }

  // B. Fake Courier / Delivery Notification
  const isCourierScam = hasMatch(COURIER_SCAM_PATTERNS);
  if (isCourierScam) {
    detectedCategories.add('fake_courier');
    signals.push({
      category: 'fake_courier',
      severity: 'high',
      title: 'Suspicious Package Delivery Alert Screenshot',
      description:
        'Screenshot displays package delivery failure or unpaid fee demands characteristic of parcel phishing scams.',
      findingType: 'delivery_scam',
      confidence: detectedAppType === 'courier' || isScreenshot ? 'high' : 'medium',
      evidenceSnippet: getRedactedSnippet(COURIER_SCAM_PATTERNS[0]),
      dedupKey: 'delivery_scam::package_delivery',
    });
  }

  // C. Coercive Account Suspension Warning (General)
  if (!isBankingSuspension && hasMatch(ACCOUNT_SUSPENSION_PATTERNS)) {
    detectedCategories.add('account_suspension');
    signals.push({
      category: 'account_suspension',
      severity: 'high',
      title: 'Coercive Account Suspension Warning Screenshot',
      description:
        'Screenshot conveys punitive account termination or deadline threats designed to induce hurried compliance.',
      findingType: 'threat_coercion',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(ACCOUNT_SUSPENSION_PATTERNS[0]),
      dedupKey: 'threat_coercion::account_suspension_general',
    });
  }

  // D. KYC or Identity Verification Demand
  const isKyc = hasMatch(KYC_VERIFICATION_PATTERNS);
  if (isKyc) {
    detectedCategories.add('kyc_verification');
    signals.push({
      category: 'kyc_verification',
      severity: 'high',
      title: 'Urgent KYC or Identity Document Solicitation',
      description:
        'Screenshot requests immediate KYC compliance or government identification under threat of account penalty.',
      findingType: 'credential_request',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(KYC_VERIFICATION_PATTERNS[0]),
      dedupKey: 'credential_request::kyc_solicitation',
    });
  }

  // E. Authentication Code (OTP / PIN) / Credential Solicitation
  const isCredentialHarvesting = hasMatch(CREDENTIAL_HARVESTING_PATTERNS);
  if (isCredentialHarvesting) {
    detectedCategories.add('login_credential_harvesting');
    const isOtp = /\b(?:otp|one[-\s]?time password|verification code|pin\b)/i.test(text);
    signals.push({
      category: 'login_credential_harvesting',
      severity: 'critical',
      title: isOtp
        ? 'Authentication Code (OTP/PIN) Solicitation'
        : 'Credential Solicitation Screenshot',
      description: isOtp
        ? 'Screenshot requests one-time passwords (OTP) or PINs. Legitimate organizations do not request authentication codes via unverified visual prompts.'
        : 'Screenshot solicits confidential account credentials or passwords. Never submit credentials into unverified portals.',
      findingType: isOtp ? 'otp_request' : 'credential_request',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(CREDENTIAL_HARVESTING_PATTERNS[0]),
      dedupKey: isOtp ? 'otp_request::code_solicitation' : 'credential_request::login_harvesting',
    });
  }

  // F. Crypto Wallet / Recovery Phrase / Private Key Solicitation
  const isCryptoFraud = hasMatch(CRYPTO_FRAUD_PATTERNS);
  if (isCryptoFraud) {
    detectedCategories.add('crypto_fraud');
    signals.push({
      category: 'crypto_fraud',
      severity: 'critical',
      title: 'Cryptocurrency Recovery Phrase or Secret Key Solicitation',
      description:
        'Screenshot requests cryptocurrency recovery phrases, private keys, or wallet synchronization. Sharing secret phrases grants irreversible asset transfer.',
      findingType: 'recovery_phrase_request',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(CRYPTO_FRAUD_PATTERNS[0]),
      dedupKey: 'recovery_phrase_request::crypto_seed',
    });
  }

  // G. Prize / Lottery / Reward Lure
  const isPrize = hasMatch(PRIZE_REWARD_PATTERNS) && hasMatch(PRIZE_FEE_PATTERNS);
  if (isPrize) {
    detectedCategories.add('prize_reward');
    signals.push({
      category: 'prize_reward',
      severity: 'high',
      title: 'Suspicious Prize or Lottery Claim Screenshot',
      description:
        'Screenshot presents unsolicited lottery or prize claims paired with fee payment or verification lures characteristic of advance-fee schemes.',
      findingType: 'prize_lure',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(PRIZE_REWARD_PATTERNS[0]),
      dedupKey: 'prize_lure::lottery_reward',
    });
  }

  // H. Suspicious Payment Confirmation / Transfer Slip
  const isPaymentSlipLayout = detectedAppType === 'payment_slip' || hasMatch(PAYMENT_RECEIPT_PATTERNS);
  const isPaymentReversal = hasMatch(PAYMENT_REVERSAL_PATTERNS);
  if (isPaymentSlipLayout && isPaymentReversal) {
    detectedCategories.add('suspicious_payment_slip');
    signals.push({
      category: 'suspicious_payment_slip',
      severity: 'medium',
      title: 'Suspicious Payment Receipt or Transfer Confirmation',
      description:
        'Screenshot displays payment receipt formatting paired with refund, overpayment, or reversal claims requiring independent verification.',
      findingType: 'financial_request',
      confidence: detectedAppType === 'payment_slip' ? 'high' : 'medium',
      evidenceSnippet: getRedactedSnippet(PAYMENT_RECEIPT_PATTERNS[0] || PAYMENT_REVERSAL_PATTERNS[0]),
      dedupKey: 'financial_request::payment_slip_reversal',
    });
  }

  // I. Customer Support / Remote Access
  const isSupport = hasMatch(CUSTOMER_SUPPORT_PATTERNS);
  if (isSupport) {
    detectedCategories.add('fake_customer_support');
    signals.push({
      category: 'fake_customer_support',
      severity: 'high',
      title: 'Suspicious Technical Support or Remote Access Request',
      description:
        'Screenshot directs contact to unverified helpline numbers or requests remote-access software installation.',
      findingType: 'social_engineering',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(CUSTOMER_SUPPORT_PATTERNS[0]),
      dedupKey: 'social_engineering::customer_support_remote',
    });
  }

  // J. Government / Law Enforcement / Legal Warning
  const isGov = hasMatch(GOVERNMENT_LEGAL_PATTERNS) && hasMatch(GOVERNMENT_SETTLE_PATTERNS);
  if (isGov) {
    detectedCategories.add('government_service_impersonation');
    signals.push({
      category: 'government_service_impersonation',
      severity: 'high',
      title: 'Suspicious Legal or Regulatory Warning Screenshot',
      description:
        'Screenshot employs punitive law enforcement, legal action, or government penalties to intimidate recipients into immediate payment.',
      findingType: 'threat_coercion',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(GOVERNMENT_LEGAL_PATTERNS[0]),
      dedupKey: 'threat_coercion::legal_government_threat',
    });
  }

  // K. Social Media / Platform Warning
  const isSocialMediaWarning = hasMatch(SOCIAL_MEDIA_WARNING_PATTERNS) && hasMatch(SOCIAL_MEDIA_APPEAL_PATTERNS);
  if (isSocialMediaWarning) {
    detectedCategories.add('social_media_warning');
    signals.push({
      category: 'social_media_warning',
      severity: 'high',
      title: 'Suspicious Social Media Security Notice',
      description:
        'Screenshot displays copyright or guideline violation warnings typical of social media account takeover lures.',
      findingType: 'phishing_indicator',
      confidence: detectedAppType === 'social_media' ? 'high' : 'medium',
      evidenceSnippet: getRedactedSnippet(SOCIAL_MEDIA_WARNING_PATTERNS[0]),
      dedupKey: 'phishing_indicator::social_media_appeal',
    });
  }

  // L. Artificial Urgency (if other signals or screenshot context exist)
  const isUrgency = hasMatch(URGENCY_PATTERNS);
  if (isUrgency && (signals.length > 0 || isScreenshot)) {
    detectedCategories.add('urgent_action_required');
    signals.push({
      category: 'urgent_action_required',
      severity: 'medium',
      title: 'Artificial Urgency Language Detected',
      description:
        'Screenshot imposes artificial deadlines to pressure quick action without due verification.',
      findingType: 'urgency_language',
      confidence: 'high',
      evidenceSnippet: getRedactedSnippet(URGENCY_PATTERNS[0]),
      dedupKey: 'urgency_language::artificial_urgency',
    });
  }

  // M. Claimed Entities / Authority Impersonation
  const claimedEntities = EntityMatcher.matchEntities(text);
  if (claimedEntities.length > 0 && signals.length > 0) {
    for (const entity of claimedEntities) {
      signals.push({
        category: 'general_visual_fraud',
        severity: 'high',
        title: `Potential Impersonation of ${entity.name}`,
        description: `Screenshot pairs references to ${entity.name} with coercive, urgent, or credential-seeking requests. Verify directly with official sources.`,
        findingType: 'authority_impersonation',
        confidence: 'high',
        evidenceSnippet: redactSensitiveText(entity.matchedText),
        dedupKey: `authority_impersonation::${entity.name.toLowerCase()}`,
      });
    }
  }

  // N. Quishing Cross-Correlation (QR in Screenshot)
  if (qrResult && qrResult.detectedCount > 0 && signals.length > 0) {
    signals.push({
      category: 'general_visual_fraud',
      severity: 'high',
      title: 'QR Code in Coercive Screenshot (Quishing Risk)',
      description:
        'Screenshot combines coercive visual scam indicators with a scannable QR code, a technique commonly used to bypass security filters (Quishing).',
      findingType: 'suspicious_qr',
      confidence: 'high',
      dedupKey: 'suspicious_qr::quishing_screenshot_fusion',
    });
  }

  // 7. Educational Context Suppression
  let finalSignals = signals;
  if (isEducational) {
    // If clearly educational, demote severe alarms to informational
    finalSignals = signals.map(sig => ({
      ...sig,
      severity: 'info' as const,
      title: `[Educational Example] ${sig.title}`,
      description: `${sig.description} (Observed within educational or security-training context).`,
    }));
  }

  // 8. Deduplicate signals by dedupKey
  const uniqueSignalMap = new Map<string, VisualScamSignal>();
  for (const sig of finalSignals) {
    if (!uniqueSignalMap.has(sig.dedupKey)) {
      uniqueSignalMap.set(sig.dedupKey, sig);
    }
  }
  const deduplicatedSignals = Array.from(uniqueSignalMap.values());

  // 9. Build Evidence
  const evidenceId = crypto.randomUUID();
  const now = new Date().toISOString();
  const categoriesList = Array.from(detectedCategories);

  evidence.push({
    id: evidenceId,
    sourceType: 'image_analysis',
    sourceName: 'Visual Scam & Screenshot Fraud Intelligence (Stage 7.4)',
    label: 'Visual Scam & Screenshot Inspection',
    description: deduplicatedSignals.length > 0
      ? `Identified ${deduplicatedSignals.length} visual scam indicator${deduplicatedSignals.length === 1 ? '' : 's'} across ${categoriesList.length} categor${categoriesList.length === 1 ? 'y' : 'ies'}.${isScreenshot ? ' Verified screenshot layout.' : ''}${detectedAppType ? ` Detected UI context: ${detectedAppType}.` : ''}`
      : isScreenshot
      ? `Visual layout exhibits screenshot characteristics${detectedAppType ? ` (${detectedAppType})` : ''} without deceptive or coercive patterns.`
      : 'Visual inspection completed with no deceptive or fraudulent cues detected.',
    data: {
      isScreenshot,
      detectedAppType,
      detectedCategories: categoriesList,
      signalCount: deduplicatedSignals.length,
      isEducational,
    },
    snippet: text.length > 0 ? redactSensitiveText(text.slice(0, 200)) : undefined,
    isAiGenerated: false,
    createdAt: now,
  });

  // 10. Build Findings from signals
  for (const sig of deduplicatedSignals) {
    findings.push({
      id: crypto.randomUUID(),
      type: sig.findingType,
      severity: sig.severity,
      title: sig.title,
      description: sig.description,
      confidence: sig.confidence,
      evidenceIds: [evidenceId],
      metadata: {
        category: sig.category,
        isScreenshot,
        detectedAppType,
        evidenceSnippet: sig.evidenceSnippet ? redactSensitiveText(sig.evidenceSnippet) : undefined,
      },
    });
  }

  // 11. Build Proportional Recommendations
  if (detectedCategories.has('crypto_fraud')) {
    recommendations.push({
      action: 'never_share_recovery_phrase',
      title: 'Never Disclose Recovery Phrases',
      description:
        'Reputable wallet providers and decentralized protocols never request secret recovery phrases or private keys.',
      priority: 'high',
    });
  }

  if (detectedCategories.has('login_credential_harvesting') || detectedCategories.has('kyc_verification')) {
    recommendations.push({
      action: 'do_not_share_otp',
      title: 'Never Disclose Authentication Codes or Passwords',
      description:
        'Avoid submitting one-time passwords (OTP), PINs, or credentials into prompts shown in unsolicited images or messages.',
      priority: 'high',
    });
  }

  if (detectedCategories.has('fake_banking')) {
    recommendations.push({
      action: 'contact_official_source',
      title: 'Verify Directly with Bank',
      description:
        'Contact your financial institution directly using the telephone number printed on your physical card or official app.',
      priority: 'high',
    });
  }

  if (detectedCategories.has('fake_courier')) {
    recommendations.push({
      action: 'verify_financial_claim',
      title: 'Verify Tracking with Official Courier',
      description:
        'Do not pay unexpected redelivery, handling, or customs fees. Verify your package status directly on the courier website.',
      priority: 'high',
    });
  }

  if (detectedCategories.has('prize_reward')) {
    recommendations.push({
      action: 'verify_financial_claim',
      title: 'Do Not Pay to Claim Winnings',
      description:
        'Legitimate lotteries and sweepstakes do not require processing fees or advance deposits to release rewards.',
      priority: 'high',
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      action: 'proceed_with_caution',
      title: 'Exercise Standard Digital Vigilance',
      description:
        deduplicatedSignals.length > 0
          ? 'Review visual content carefully before acting on urgent requests or unfamiliar contacts.'
          : 'No active visual scam indicators were identified. Continue practicing standard digital caution.',
      priority: deduplicatedSignals.length > 0 ? 'medium' : 'low',
    });
  }

  // 12. Limitations
  limitations.push(
    'Visual scam signals are based on deterministic heuristic layout and text analysis. Images can be manipulated or fabricated.'
  );

  const status: SanitizedVisualScamResult['status'] =
    deduplicatedSignals.length > 0 ? 'suspicious' : 'clean';

  return {
    status,
    isScreenshot,
    detectedAppType,
    detectedCategories: categoriesList,
    signals: deduplicatedSignals,
    findings,
    evidence,
    recommendations,
    limitations,
  };
}
