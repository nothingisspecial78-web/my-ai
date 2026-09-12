/**
 * Scam Message Intelligence Engine (Phase 6.2)
 * 
 * Central coordinator combining linguistic pattern analysis, entity recognition,
 * social-engineering tactics, contact extraction, and Phase 6.1 URL Intelligence.
 * 
 * ZERO USER-URL FETCHING POLICY: All embedded URLs are analyzed exclusively via
 * UrlIntelligenceEngine without connecting to user-submitted destinations.
 */

import crypto from 'crypto';
import {
  Finding,
  Evidence,
  Recommendation,
  RiskLevel,
  ConfidenceLevel,
} from '../types';
import {
  ScamAnalysisResult,
  ScamCategory,
  SocialEngineeringTactic,
  ClaimedEntity,
  ExtractedContacts,
  ScamSignal,
} from './types';
import { ContactExtractor, MAX_EXTRACTED_URLS } from './extractors';
import { EntityMatcher } from './entity-matcher';
import { SocialEngineeringAnalyzer } from './social-engineering';
import { UrlIntelligenceEngine, UrlIntelligenceResult } from '../url';
import { redactSensitiveText } from '../redaction';

export class ScamEngine {
  /**
   * Performs complete end-to-end deterministic scam message intelligence analysis.
   */
  static async analyze(rawContent: string): Promise<ScamAnalysisResult> {
    const text = ContactExtractor.sanitizeInput(rawContent);
    const sanitizedPreview = redactSensitiveText(text);

    // 1. Context Guardrail: Educational or Meta-Inquiry check
    const isEducational = SocialEngineeringAnalyzer.isEducationalOrMetaQuestion(text);

    // 2. Extract Artifacts and Contacts (URLs, Emails, Phone Numbers)
    const contacts: ExtractedContacts = ContactExtractor.extractAll(text);

    // 3. Match Claimed Institutions & Entities
    const claimedEntities: ClaimedEntity[] = EntityMatcher.matchEntities(text);

    // 4. Analyze Linguistic Patterns & Social Engineering Tactics
    let rawSignals: ScamSignal[] = isEducational ? [] : SocialEngineeringAnalyzer.analyze(text);

    // Context filter: If urgency exists in isolation without any other signal, suppress it
    if (rawSignals.length === 1 && rawSignals[0].dedupGroup === 'urgency_pressure') {
      // Benign business/casual urgency ("meeting in 10 minutes", "send report by 5pm")
      rawSignals = [];
    }

    // 5. Delegate Embedded URLs to Phase 6.1 URL Intelligence Engine
    const urlResults: UrlIntelligenceResult[] = [];
    const urlFindings: Finding[] = [];
    const urlEvidence: Evidence[] = [];

    // Analyze up to MAX_EXTRACTED_URLS
    for (const urlStr of contacts.urls.slice(0, MAX_EXTRACTED_URLS)) {
      try {
        const res = await UrlIntelligenceEngine.analyze(urlStr);
        urlResults.push(res);
        urlFindings.push(...res.findings);
        urlEvidence.push(...res.evidence);
      } catch {
        // Safe tolerance: URL provider/analyzer errors do not abort message analysis
      }
    }

    // Correlate URL risk into scam signals
    for (const urlRes of urlResults) {
      if (urlRes.riskLevel === 'critical' || urlRes.riskLevel === 'high') {
        const isLookalike = urlRes.findings.some(f => f.type === 'lookalike_brand' || f.type === 'host_confusion');
        rawSignals.push({
          category: 'phishing',
          tactic: 'credential_pressure',
          severity: urlRes.riskLevel === 'critical' ? 'critical' : 'high',
          weight: urlRes.riskLevel === 'critical' ? 40 : 25,
          title: isLookalike ? 'Contains Deceptive Brand-Lookalike Link' : 'Contains Suspicious or High-Risk Link',
          description: `The message directs the user to an elevated-risk destination (${urlRes.url}).`,
          evidenceSnippet: urlRes.url,
          dedupGroup: `url_risk_${urlRes.url}`,
        });
      } else if (urlRes.riskLevel === 'medium') {
        rawSignals.push({
          category: 'phishing',
          severity: 'medium',
          weight: 10,
          title: 'Contains Unverified Link with Anomalous Structure',
          description: `The message includes a link with structural anomalies or uncommon domain characteristics (${urlRes.url}).`,
          evidenceSnippet: urlRes.url,
          dedupGroup: `url_risk_${urlRes.url}`,
        });
      }
    }

    // Correlate Claimed Entities with Impersonation context
    if (claimedEntities.length > 0 && rawSignals.length > 0) {
      for (const entity of claimedEntities) {
        rawSignals.push({
          category: 'impersonation',
          tactic: 'authority_pressure',
          severity: 'high',
          weight: 20,
          title: `Impersonation Context: ${entity.name}`,
          description: `The communication claims representation from ${entity.name} while exhibiting coercive or fraudulent request patterns.`,
          evidenceSnippet: entity.matchedText,
          dedupGroup: `entity_impersonation_${entity.name}`,
        });
      }
    }

    // Deduplicate signals by dedupGroup
    const signalMap = new Map<string, ScamSignal>();
    for (const sig of rawSignals) {
      const existing = signalMap.get(sig.dedupGroup);
      if (!existing || sig.weight > existing.weight) {
        signalMap.set(sig.dedupGroup, sig);
      }
    }
    const finalSignals = Array.from(signalMap.values());

    // 6. Calculate Deterministic Risk Score
    // CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 3, INFO: 0
    let totalScore = 0;
    for (const sig of finalSignals) {
      totalScore += sig.weight;
    }
    const score = Math.min(100, Math.max(0, totalScore));

    // Calibrated Risk Level
    let riskLevel: RiskLevel;
    if (score >= 50 || finalSignals.some(s => s.severity === 'critical')) {
      riskLevel = 'critical';
    } else if (score >= 25 || finalSignals.some(s => s.severity === 'high')) {
      riskLevel = 'high';
    } else if (score >= 10 || finalSignals.some(s => s.severity === 'medium')) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    // 7. Calculate Confidence Level (Independent of Risk)
    let confidence: ConfidenceLevel;
    if (finalSignals.length >= 2 || (finalSignals.length === 1 && finalSignals[0].severity === 'critical')) {
      confidence = 'high';
    } else if (finalSignals.length === 1 || urlResults.length > 0) {
      confidence = 'medium';
    } else {
      confidence = 'high'; // High confidence in clean/normal message when text was fully processed without hits
    }

    // 8. Categories & Social Engineering Tactics
    const categoriesSet = new Set<ScamCategory>();
    const tacticsSet = new Set<SocialEngineeringTactic>();

    for (const sig of finalSignals) {
      categoriesSet.add(sig.category);
      if (sig.tactic) tacticsSet.add(sig.tactic);
    }
    const categories = Array.from(categoriesSet);
    const tactics = Array.from(tacticsSet);

    // 9. Build Findings & Evidence
    const findings: Finding[] = [];
    const evidence: Evidence[] = [];

    // Master message content evidence
    const contentEvidenceId = crypto.randomUUID();
    evidence.push({
      id: contentEvidenceId,
      sourceType: 'content_analysis',
      sourceName: 'Deterministic Message Intelligence',
      description: 'Extracted linguistic indicators, social engineering patterns, and structural signals from text',
      data: {
        textLength: text.length,
        preview: sanitizedPreview.slice(0, 160),
        extractedUrls: contacts.urls,
        extractedPhoneNumbers: contacts.phoneNumbers,
        extractedEmails: contacts.emails,
        claimedEntities: claimedEntities.map(e => e.name),
        detectedCategories: categories,
        detectedTactics: tactics,
      },
      isAiGenerated: false,
      createdAt: new Date().toISOString(),
    });

    // Convert signals to Findings
    for (const sig of finalSignals) {
      findings.push({
        id: crypto.randomUUID(),
        type:
          sig.dedupGroup === 'crypto_key_solicitation'
            ? 'recovery_phrase_request'
            : sig.category === 'job_employment'
            ? 'job_scam'
            : sig.category === 'delivery_parcel'
            ? 'delivery_scam'
            : sig.category === 'otp_fraud'
            ? 'otp_request'
            : sig.category === 'credential_harvesting'
            ? 'credential_request'
            : sig.category === 'kyc_account_block'
            ? 'threat_coercion'
            : sig.category === 'prize_lottery'
            ? 'prize_lure'
            : sig.category === 'advance_fee' || sig.category === 'financial_scam'
            ? 'financial_request'
            : sig.category === 'impersonation'
            ? 'authority_impersonation'
            : sig.tactic === 'urgency'
            ? 'urgency_language'
            : 'social_engineering',
        severity: sig.severity,
        title: sig.title,
        description: sig.description,
        evidenceIds: [contentEvidenceId],
        confidence: sig.severity === 'critical' || sig.severity === 'high' ? 'high' : 'medium',
        metadata: {
          category: sig.category,
          tactic: sig.tactic,
          evidenceSnippet: sig.evidenceSnippet,
        },
      });
    }

    // Merge URL findings and evidence
    findings.push(...urlFindings);
    evidence.push(...urlEvidence);

    // Extracted contacts factual findings (Neutral evidence, never accusing numbers of being scams)
    if (contacts.phoneNumbers.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'contact_extraction',
        severity: 'info',
        title: 'Phone Number Detected in Message',
        description: `Found contact number(s): ${contacts.phoneNumbers.join(', ')}. Presence of a phone number is an observable signal; verify independently before responding.`,
        evidenceIds: [contentEvidenceId],
        confidence: 'high',
        metadata: { phoneNumbers: contacts.phoneNumbers },
      });
    }

    if (contacts.emails.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'contact_extraction',
        severity: 'info',
        title: 'Email Address Detected in Message',
        description: `Found email contact(s): ${contacts.emails.join(', ')}. Compare the email domain against the official website of any claimed organization.`,
        evidenceIds: [contentEvidenceId],
        confidence: 'high',
        metadata: { emails: contacts.emails },
      });
    }

    // 10. Key Warning Signs
    const warningSigns: string[] = [];
    if (tactics.includes('credential_pressure')) {
      warningSigns.push('Requests one-time passwords (OTP), PINs, or account login credentials.');
    }
    if (tactics.includes('fear_threat')) {
      warningSigns.push('Uses coercive threats of account suspension, disconnection, or legal action.');
    }
    if (tactics.includes('urgency')) {
      warningSigns.push('Imposes artificial urgency or immediate deadlines to prevent independent verification.');
    }
    if (tactics.includes('reward_temptation')) {
      warningSigns.push('Offers unearned financial rewards, lotteries, or prizes.');
    }
    if (categories.includes('job_employment')) {
      warningSigns.push('Demands upfront registration fees or commission deposits for employment.');
    }
    if (categories.includes('delivery_parcel')) {
      warningSigns.push('Claims undelivered packages requiring payment of rescheduling or customs fees.');
    }
    if (claimedEntities.length > 0 && riskLevel !== 'low') {
      warningSigns.push(`Impersonates or claims affiliation with ${claimedEntities.map(e => e.name).join(', ')}.`);
    }
    if (urlResults.some(u => u.riskLevel === 'critical' || u.riskLevel === 'high')) {
      warningSigns.push('Directs recipients to suspicious, deceptive, or lookalike links.');
    }

    // 11. Recommendations
    const recommendations: Recommendation[] = [];
    if (finalSignals.some(s => s.dedupGroup === 'crypto_key_solicitation')) {
      recommendations.push({
        action: 'never_share_recovery_phrase',
        title: 'Never Share Recovery or Seed Phrases',
        description: 'Legitimate support, services, or administrators will never ask for your recovery phrase or private key. Disclosing it grants irreversible control over your assets.',
        priority: 'high',
      });
    }
    if (tactics.includes('credential_pressure') || categories.includes('otp_fraud')) {
      recommendations.push({
        action: 'do_not_share_otp',
        title: 'Never Share Authentication Codes',
        description: 'Never disclose OTPs, PINs, passwords, or recovery phrases to anyone, including customer support.',
        priority: 'high',
      });
    }
    if (categories.includes('prize_lottery')) {
      recommendations.push({
        action: 'verify_financial_claim',
        title: 'Do Not Pay to Claim Winnings',
        description: 'Legitimate lotteries and sweepstakes never require processing fees or advance deposits to release rewards.',
        priority: 'high',
      });
    }
    if (categories.includes('job_employment') || categories.includes('advance_fee') || categories.includes('delivery_parcel')) {
      recommendations.push({
        action: 'do_not_pay_advance_fee',
        title: 'Do Not Pay Upfront Fees',
        description: 'Legitimate employers and established couriers do not require upfront deposits or transfer fees via unusual channels.',
        priority: 'high',
      });
    }
    if (claimedEntities.length > 0) {
      recommendations.push({
        action: 'contact_official_source',
        title: 'Verify Directly Through Official Channels',
        description: 'Contact the organization using their verified official website, phone app, or telephone number rather than replying to this message.',
        priority: 'high',
      });
    }
    if (contacts.urls.length > 0 && riskLevel !== 'low') {
      recommendations.push({
        action: 'do_not_click',
        title: 'Avoid Clicking Embedded Links',
        description: 'Do not open links provided in unexpected messages. Navigate to services directly through official bookmarks or apps.',
        priority: 'high',
      });
    }
    if (tactics.includes('urgency')) {
      recommendations.push({
        action: 'pause_and_verify',
        title: 'Pause and Verify Before Acting',
        description: 'Scammers deliberately induce panic and urgency. Take time to independently check the sender before taking action.',
        priority: 'medium',
      });
    }
    if (recommendations.length === 0) {
      recommendations.push({
        action: 'proceed_with_caution',
        title: 'Exercise Standard Digital Vigilance',
        description: 'No active scam patterns were identified. Continue practicing standard digital caution with unexpected communications.',
        priority: 'low',
      });
    }

    // 12. Limitations
    const limitations: string[] = [
      'Analysis is deterministic and based on linguistic heuristics and observable structural patterns.',
      'No external phone number or email sender reputation database was queried.',
      'Automated safety checks analyze observable signals. Absence of flags is not an absolute guarantee of safety.',
    ];
    if (contacts.urls.length > 0) {
      limitations.push('Embedded URLs were evaluated without visiting, resolving, or crawling destination websites (Zero-Fetch).');
    }

    return {
      riskLevel,
      score,
      confidence,
      categories,
      tactics,
      signals: finalSignals,
      findings,
      evidence,
      claimedEntities,
      contacts,
      warningSigns,
      recommendations,
      limitations,
    };
  }
}
