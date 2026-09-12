/**
 * Social Engineering & Scam Pattern Analyzer (Phase 6.2)
 * 
 * Deterministically analyzes text for psychological coercion tactics,
 * credential solicitation, advance-fee schemes, and impersonation fraud.
 * Enforces deduplication groups to prevent correlated score inflation.
 */

import { ScamSignal } from './types';

export class SocialEngineeringAnalyzer {
  // --- TACTIC 1: URGENCY ---
  private static URGENCY_PATTERNS = [
    /\b(immediately|act now|urgent|right now|without delay|at once)\b/i,
    /\bwithin (?:5|10|15|20|30|60) minutes\b/i,
    /\bwithin (?:12|24|48) hours\b/i,
    /\b(?:final|last) (?:warning|notice|reminder|chance)\b/i,
    /\b(?:expires|valid) (?:today|in \d+ (?:hours?|minutes?))\b/i,
  ];

  // --- TACTIC 2: FEAR & THREAT ---
  private static THREAT_PATTERNS = [
    /\baccount (?:will be|has been|is) (?:blocked|suspended|deactivated|closed|frozen|terminated|locked)\b/i,
    /\b(?:electricity|power|service|sim card) (?:will be|is) (?:disconnected|cut off|terminated) (?:tonight|today)\b/i,
    /\b(?:legal action|arrest warrant|court summons|police complaint|penalty imposed|lawsuit filed)\b/i,
    /\b(?:pan card|aadhaar card|kyc) (?:has expired|is invalid|must be updated immediately)\b/i,
  ];

  // --- TACTIC 3: CREDENTIAL & OTP SOLICITATION ---
  private static OTP_PATTERNS = [
    /\b(?:share|send|provide|tell|confirm|enter|give|forward)\s+(?:me|us)?\s*(?:the|your)?\s*(?:otp|one[-\s]?time[-\s]?password|verification code|security code|2fa code|login code)\b/i,
    /\bsend (?:the|your) code to (?:verify|unlock|reactivate)\b/i,
    /\bconfirm your (?:pin|mpin|password|upi pin)\b/i,
  ];

  private static CREDENTIAL_PATTERNS = [
    /\b(?:enter|update|verify|confirm|submit)\s+(?:your\s+)?(?:password|login credentials|banking password|netbanking id)\b/i,
    /\blogin (?:here|now) to (?:restore|unlock|reactivate|verify) your account\b/i,
  ];

  private static RECOVERY_PHRASE_TERMS =
    /\b(secret recovery phrase|recovery phrase|seed phrase|seed words|recovery words|wallet recovery phrase|backup phrase|mnemonic phrase|mnemonic words|private key)\b/i;

  private static RECOVERY_SOLICITATION_OR_ACTION =
    /\b(share|send|give|provide|tell|enter|input|submit|verify|unlock|validate|disclose|export|import|restore|backup|confirm|claim|type|paste|ask|asked|asking|request|requested|requesting|demand|demanded|wants?|needs?)\b/i;

  private static RECOVERY_CONTEXT_OR_INQUIRY =
    /\b(support|helpdesk|admin|agent|staff|team|representative|telegram|discord|dm|email|form|site|portal|airdrop|claim|giveaway|bonus|bot|anyone|somebody|someone|is it safe|can i|should i|is it okay|they (?:want|need|asked)|asked me|asking for|requested my|share my|send my|give them)\b/i;

  private static DEFENSIVE_PHRASE_PATTERNS =
    /\b(never (?:share|give|send|enter|provide|disclose|tell|ask)|(?:do not|don't) (?:share|give|send|enter|provide|disclose|tell)|will never ask|won't ask|never asked|store (?:it |your |them )?offline|keep (?:it |your |them )?safe)\b/i;

  private static ACTIVE_INQUIRY_OR_REPORT =
    /\b(is it safe|can i|should i|is it okay|asked me|asking me|wants me|demands|insists)\b/i;

  // --- TACTIC 4: REWARD & LOTTERY LURES ---
  private static REWARD_PATTERNS = [
    /\b(?:congratulations|congrats|lucky winner)\b/i,
    /\byou (?:have|'ve) (?:won|been awarded|been selected for)\s*(?:a prize|lottery|cash prize|₹|\$|cashback)\b/i,
    /\bclaim your (?:reward|prize|winnings|cashback|bonus|gift voucher)\b/i,
    /\bselected (?:to receive|for an exclusive reward)\b/i,
  ];

  // --- TACTIC 5: JOB & EMPLOYMENT SCAMS ---
  private static JOB_SCAM_PATTERNS = [
    /\b(?:work[-\s]?from[-\s]?home|part[-\s]?time job|online job|home[-\s]?based job)\b/i,
    /\bearn (?:daily|per day|hourly|weekly)\s*(?:₹|\$)?\s*\d+[kK,]?\b/i,
    /\b(?:registration fee|training fee|processing fee|security deposit)\s*(?:of|is)?\s*(?:₹|\$)?\s*\d+\b/i,
    /\bpay\s*(?:₹|\$)?\s*\d+\s*(?:as\s+(?:a\s+)?)?(?:registration|refundable|joining|entry)?\s*(?:fee|charge|deposit)\b/i,
    /\b(?:registration|joining|activation)\s+fee\s+to\s+(?:activate|start)\b/i,
    /\btask completion (?:commission|daily payout|youtube like job|telegram task)\b/i,
  ];

  // --- TACTIC 6: PARCEL & DELIVERY FRAUD ---
  private static DELIVERY_SCAM_PATTERNS = [
    /\b(?:parcel|package|shipment|courier|order)\s*(?:could not be delivered|is (?:being )?held|is detained|address is missing|pending delivery|undelivered)\b/i,
    /\b(?:reschedule|update address|redelivery)\s*(?:fee|link|charge|delivery)\b/i,
    /\breschedule delivery\b/i,
    /\bpay\s*(?:₹|\$)?\s*\d+\s*(?:immediately\s+)?(?:to\s+)?(?:reschedule|redelivery|customs|clearance|handling)\b/i,
  ];

  // --- TACTIC 7: FINANCIAL REQUESTS & ADVANCE FEES ---
  private static FINANCIAL_PATTERNS = [
    /\b(?:processing fee|refundable fee|advance fee|service charge|verification deposit)\b/i,
    /\bpay\s*(?:₹|\$)\s*\d+\s*(?:immediately|now|to receive|to claim)\b/i,
    /\b(?:transfer money|send payment|wire funds) via (?:gift card|crypto|cryptocurrency|usdt|bitcoin)\b/i,
  ];

  // --- TACTIC 8: SECRECY & CHANNEL BYPASS ---
  private static SECRECY_PATTERNS = [
    /\b(?:do not|don't) (?:tell|share with|disclose to)\s*(?:anyone|family|friends|bank|colleagues)\b/i,
    /\b(?:keep this|treat this as) (?:strictly confidential|secret|between us)\b/i,
    /\bcontact (?:me|us) only on (?:whatsapp|telegram|signal)\b/i,
  ];

  // --- CONTEXT GUARDRAILS ---
  private static EDUCATIONAL_GUARDRAIL = [
    /\b(?:how do scammers|scammers often|types of scams|explain (?:phishing|scams)|cybersecurity class|educational example)\b/i,
    /\b(?:never share your otp|keep your credentials safe|beware of scams|warning against fraud)\b/i,
  ];

  private static META_QUESTION_GUARDRAIL = [
    /^(?:is this (?:a )?scam|can you check if this is a scam|is this message safe|is this legit)\??$/i,
  ];

  /**
   * Evaluates if text is an educational discussion or pure meta-question.
   */
  static isEducationalOrMetaQuestion(text: string): boolean {
    const trimmed = text.trim();
    for (const pattern of this.META_QUESTION_GUARDRAIL) {
      if (pattern.test(trimmed)) return true;
    }
    for (const pattern of this.EDUCATIONAL_GUARDRAIL) {
      if (pattern.test(trimmed) && !trimmed.includes('http')) return true;
    }
    return false;
  }

  /**
   * Analyzes text and returns deduplicated scam signals.
   */
  static analyze(text: string): ScamSignal[] {
    const signals: ScamSignal[] = [];

    // 1. OTP / 2FA Solicitation (CRITICAL / HIGH)
    for (const pattern of this.OTP_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'otp_fraud',
          tactic: 'credential_pressure',
          severity: 'high',
          weight: 25,
          title: 'Requests One-Time Password (OTP) or PIN',
          description: 'The message pressures the recipient to provide an authentication code, OTP, or PIN. Banks and legitimate services generally do not ask customers to disclose one-time passwords through unsolicited messages.',
          evidenceSnippet: match[0],
          dedupGroup: 'otp_solicitation',
        });
        break;
      }
    }

    // 2. Recovery Phrase / Private Key (HIGH)
    if (this.RECOVERY_PHRASE_TERMS.test(text)) {
      const isDefensive = this.DEFENSIVE_PHRASE_PATTERNS.test(text);
      const isUserInquiringOrReporting = this.ACTIVE_INQUIRY_OR_REPORT.test(text);

      if (isDefensive && !isUserInquiringOrReporting) {
        // Benign defensive or educational statement - do not flag
      } else {
        const hasDirectAction = /\b(enter|input|submit|share|send|provide|disclose)\s+(?:(?:your|the|a|my)\s+)?(?:secret\s+)?(?:recovery\s+phrase|seed\s+phrase|private\s+key|seed\s+words|recovery\s+words)\b/i.test(text);
        const hasAction = this.RECOVERY_SOLICITATION_OR_ACTION.test(text);
        const hasContext = this.RECOVERY_CONTEXT_OR_INQUIRY.test(text);

        if (hasDirectAction || (hasAction && hasContext)) {
          signals.push({
            category: 'credential_harvesting',
            tactic: 'credential_pressure',
            severity: 'high',
            weight: 25,
            title: 'Recovery Phrase or Private Key Solicitation',
            description: 'The communication involves requesting, providing, or entering a cryptocurrency recovery phrase, seed phrase, or private key. Reputable platforms and support staff generally should not ask for recovery phrases or private keys.',
            evidenceSnippet: (text.match(this.RECOVERY_PHRASE_TERMS) || ['recovery phrase'])[0],
            dedupGroup: 'crypto_key_solicitation',
          });
        }
      }
    }

    // 3. Credential Solicitation (HIGH)
    for (const pattern of this.CREDENTIAL_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'credential_harvesting',
          tactic: 'credential_pressure',
          severity: 'high',
          weight: 25,
          title: 'Requests Password or Account Credentials',
          description: 'The communication pressures the user to verify or enter account credentials or banking login details.',
          evidenceSnippet: match[0],
          dedupGroup: 'credential_solicitation',
        });
        break;
      }
    }

    // 4. Fear / Account Suspension / Legal Threats (HIGH / MEDIUM)
    for (const pattern of this.THREAT_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'kyc_account_block',
          tactic: 'fear_threat',
          severity: 'high',
          weight: 25,
          title: 'Coercive Threat of Account Blocking or Legal Action',
          description: 'Uses threats of account closure, service disconnection, or legal penalties to induce panic and bypass critical thinking.',
          evidenceSnippet: match[0],
          dedupGroup: 'threat_coercion',
        });
        break;
      }
    }

    // 5. Urgency Pressure (MEDIUM)
    for (const pattern of this.URGENCY_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'social_engineering',
          tactic: 'urgency',
          severity: 'medium',
          weight: 10,
          title: 'Artificial Urgency and Time Pressure',
          description: 'Uses artificial deadlines ("immediately", "within minutes") to prevent the recipient from verifying claims.',
          evidenceSnippet: match[0],
          dedupGroup: 'urgency_pressure',
        });
        break;
      }
    }

    // 6. Job / Employment Fraud (HIGH)
    for (const pattern of this.JOB_SCAM_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'job_employment',
          tactic: 'financial_pressure',
          severity: 'high',
          weight: 25,
          title: 'Employment Offer with Upfront Fee or Task Fraud Pattern',
          description: 'Advertises high-paying work-from-home employment while requiring an upfront registration fee or task completion scheme.',
          evidenceSnippet: match[0],
          dedupGroup: 'job_scam',
        });
        break;
      }
    }

    // 7. Parcel / Courier Delivery Scam (HIGH)
    for (const pattern of this.DELIVERY_SCAM_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'delivery_parcel',
          tactic: 'financial_pressure',
          severity: 'high',
          weight: 25,
          title: 'Undelivered Parcel or Fake Delivery Fee Scheme',
          description: 'Claims a package cannot be delivered and demands payment of a small redelivery or customs fee.',
          evidenceSnippet: match[0],
          dedupGroup: 'delivery_scam',
        });
        break;
      }
    }

    // 8. Prize / Lottery Lure (HIGH)
    for (const pattern of this.REWARD_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'prize_lottery',
          tactic: 'reward_temptation',
          severity: 'high',
          weight: 25,
          title: 'Unrealistic Prize or Lottery Reward Claim',
          description: 'Claims unearned lottery winnings or cash rewards to lure the user into paying fees or submitting personal data.',
          evidenceSnippet: match[0],
          dedupGroup: 'prize_lure',
        });
        break;
      }
    }

    // 9. Financial Requests & Advance Fees (HIGH / MEDIUM)
    for (const pattern of this.FINANCIAL_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'advance_fee',
          tactic: 'financial_pressure',
          severity: 'high',
          weight: 20,
          title: 'Advance Fee or Wire Transfer Request',
          description: 'Requests upfront money transfers, processing fees, or payment via cryptocurrency / gift cards.',
          evidenceSnippet: match[0],
          dedupGroup: 'advance_fee',
        });
        break;
      }
    }

    // 10. Secrecy / Channel Bypass (HIGH)
    for (const pattern of this.SECRECY_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        signals.push({
          category: 'social_engineering',
          tactic: 'secrecy',
          severity: 'high',
          weight: 25,
          title: 'Demand for Secrecy or Channel Bypass',
          description: 'Instructs the recipient to keep the interaction secret or move communication to unauthorized private channels.',
          evidenceSnippet: match[0],
          dedupGroup: 'secrecy_demand',
        });
        break;
      }
    }

    // Deduplicate by dedupGroup, retaining the highest weight
    const dedupMap = new Map<string, ScamSignal>();
    for (const signal of signals) {
      const existing = dedupMap.get(signal.dedupGroup);
      if (!existing || signal.weight > existing.weight) {
        dedupMap.set(signal.dedupGroup, signal);
      }
    }

    return Array.from(dedupMap.values());
  }
}
