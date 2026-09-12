import {
  Finding,
  RiskLevel,
  ConfidenceLevel,
  Recommendation,
  AnalyzerResult,
} from './types';

export interface RiskEvaluationResult {
  riskLevel: RiskLevel;
  confidenceLevel: ConfidenceLevel;
  score: number; // Internal heuristic score (0-100), not an absolute certainty metric
  recommendations: Recommendation[];
  limitations: string[];
}

/**
 * Deterministic Risk Engine.
 * Calculates risk levels and generates proportional recommendations based on findings.
 * Decouples risk severity from assessment confidence.
 */
export class RiskEngine {
  /**
   * Evaluates overall risk deterministically from aggregated findings and analyzer results.
   */
  static evaluate(findings: Finding[], analyzerResults: AnalyzerResult[]): RiskEvaluationResult {
    const limitations: string[] = [];

    // Collect limitations from all analyzers
    for (const res of analyzerResults) {
      if (res.limitations) {
        limitations.push(...res.limitations);
      }
    }

    // Always state the universal safety boundary: no analysis can offer 100% absolute guarantee
    limitations.push(
      'Automated safety checks analyze observable signals and patterns. Absence of flags is not an absolute guarantee of safety.'
    );

    // If there were no findings and no analyzers succeeded or input was empty
    if (analyzerResults.length === 0) {
      return {
        riskLevel: 'unknown',
        confidenceLevel: 'low',
        score: 0,
        recommendations: [
          {
            action: 'proceed_with_caution',
            title: 'Exercise General Caution',
            description: 'No analyzers could process this input format. Be cautious when handling unknown sources.',
            priority: 'medium',
          },
        ],
        limitations,
      };
    }

    // Tally severities
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const finding of findings) {
      switch (finding.severity) {
        case 'critical':
          criticalCount++;
          break;
        case 'high':
          highCount++;
          break;
        case 'medium':
          mediumCount++;
          break;
        case 'low':
          lowCount++;
          break;
        case 'info':
          // Info findings are neutral evidence and do not contribute to risk score
          break;
      }
    }

    // Check if this evaluation includes code security findings/analyzers
    const isCodeAnalysis = analyzerResults.some(r => r.analyzerType === 'code_security');

    // Calculate deterministic risk score (0 - 100)
    // For Code Intelligence: Critical: 40 pts, High: 25 pts, Medium: 10 pts, Low: 3 pts
    // For URL/Scam/General Intelligence: Critical: 50 pts, High: 20 pts, Medium: 10 pts, Low: 3 pts
    let rawScore = isCodeAnalysis
      ? criticalCount * 40 + highCount * 25 + mediumCount * 10 + lowCount * 3
      : criticalCount * 50 + highCount * 20 + mediumCount * 10 + lowCount * 3;

    // Guaranteed floor thresholds mapped to severity:
    // Any critical finding guarantees >= 50
    // Any high finding guarantees >= 25
    // Any medium finding or 2+ low findings guarantee >= 10
    if (criticalCount > 0) {
      rawScore = Math.max(50, rawScore);
    } else if (highCount > 0) {
      rawScore = Math.max(25, rawScore);
    } else if (mediumCount > 0 || lowCount >= 2) {
      rawScore = Math.max(10, rawScore);
    }

    const score = Math.min(100, Math.max(0, rawScore));

    // Pure mathematical risk-level mapping:
    // score < 10   → low
    // score < 25   → medium
    // score < 50   → high
    // score >= 50  → critical
    let riskLevel: RiskLevel;
    if (score >= 50) {
      riskLevel = 'critical';
    } else if (score >= 25) {
      riskLevel = 'high';
    } else if (score >= 10) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'low';
    }

    // Determine confidence level independently of risk
    // Based on whether analyzers succeeded and findings confidence
    let confidenceLevel: ConfidenceLevel = 'high';
    const failedAnalyzers = analyzerResults.filter(r => r.status === 'failed' || r.status === 'partial');
    if (failedAnalyzers.length > 0 && findings.length === 0) {
      confidenceLevel = 'low';
    } else if (findings.some(f => f.confidence === 'low')) {
      confidenceLevel = 'medium';
    } else if (findings.length === 0) {
      // Clean analysis with full analyzer execution gives medium confidence that no known signals are present
      confidenceLevel = 'medium';
    }

    // Generate proportional recommendations
    const recommendations = this.buildRecommendations(findings, riskLevel);

    return {
      riskLevel,
      confidenceLevel,
      score,
      recommendations,
      limitations,
    };
  }

  /**
   * Produces proportional, non-alarmist recommendations mapped to specific findings.
   */
  private static buildRecommendations(findings: Finding[], riskLevel: RiskLevel): Recommendation[] {
    const recs: Recommendation[] = [];
    const actionsAdded = new Set<string>();

    const addRec = (rec: Recommendation) => {
      if (!actionsAdded.has(rec.action)) {
        actionsAdded.add(rec.action);
        recs.push(rec);
      }
    };

    for (const f of findings) {
      if (f.type === 'otp_request') {
        addRec({
          action: 'do_not_share_otp',
          title: 'Never Share One-Time Passwords (OTPs)',
          description: 'Do not disclose verification codes or PINs to anyone via call, message, or email.',
          priority: 'high',
        });
      }

      if (f.type === 'credential_request' || f.type === 'credential_in_url') {
        addRec({
          action: 'do_not_enter_password',
          title: 'Do Not Enter Login Credentials',
          description: 'Do not input your password or account details on this page or message.',
          priority: 'high',
        });
      }

      if (f.type === 'recovery_phrase_request') {
        addRec({
          action: 'never_share_recovery_phrase',
          title: 'Never Share Recovery or Seed Phrases',
          description: 'Reputable platforms and support staff generally should not ask for recovery phrases or private keys. Disclosing them grants complete and irreversible control over digital assets.',
          priority: 'high',
        });
      }

      if (f.type === 'host_confusion') {
        addRec({
          action: 'verify_destination_host',
          title: 'Verify Actual Destination Host',
          description: 'The URL uses misleading userinfo/syntax to hide its true destination. Avoid visiting it.',
          priority: 'high',
        });
      }

      if (f.type === 'lookalike_domain' || f.type === 'lookalike_brand') {
        addRec({
          action: 'verify_domain',
          title: 'Verify Official Website Directly',
          description: 'Navigate to the organization’s verified site by typing their known URL directly into your browser address bar.',
          priority: 'high',
        });
        addRec({
          action: 'do_not_click',
          title: 'Avoid Clicking Lookalike Links',
          description: 'Refrain from opening the link or interacting with its contents.',
          priority: 'medium',
        });
      }

      if (f.type === 'suspicious_domain' || f.type === 'ip_as_host') {
        addRec({
          action: 'do_not_click',
          title: 'Avoid Clicking Unverified Links',
          description: 'Refrain from opening the link or interacting with its contents.',
          priority: 'medium',
        });
      }

      if (f.type === 'prize_lure' || f.type === 'financial_request') {
        addRec({
          action: 'verify_financial_claim',
          title: 'Do Not Send Funds or Pay Upfront Fees',
          description: 'Legitimate lotteries and organizations typically do not ask for processing fees or gift cards to release winnings or services.',
          priority: 'high',
        });
      }

      if (f.type === 'job_scam') {
        addRec({
          action: 'do_not_pay_advance_fee',
          title: 'Do Not Pay Upfront Employment Fees',
          description: 'Legitimate employers typically do not demand registration fees, task security deposits, or upfront payments for job placement.',
          priority: 'high',
        });
      }

      if (f.type === 'delivery_scam') {
        addRec({
          action: 'verify_courier_delivery',
          title: 'Verify Delivery via Official Courier App',
          description: 'Do not pay redelivery or customs fees via unverified links. Check your tracking number directly on the official courier website.',
          priority: 'high',
        });
      }

      if (f.type === 'threat_coercion' || f.type === 'authority_impersonation' || f.type === 'impersonation_claim' || f.type === 'urgency_language') {
        addRec({
          action: 'contact_official_source',
          title: 'Contact Official Organization via Trusted Channels',
          description: 'Verify unexpected account suspension claims or notices through official portals or customer support.',
          priority: 'medium',
        });
      }

      if (f.type === 'social_engineering') {
        addRec({
          action: 'pause_and_verify',
          title: 'Pause and Verify Before Acting',
          description: 'Social engineering relies on panic, urgency, or artificial pressure. Take time to independently verify claims.',
          priority: 'medium',
        });
      }

      if (f.type === 'exposed_secret') {
        addRec({
          action: 'rotate_exposed_secret',
          title: 'Revoke and Rotate Exposed Secret Immediately',
          description: 'Invalidate the compromised credential in your provider console and replace it with a fresh key stored in environment variables.',
          priority: 'high',
        });
      }

      if (f.type === 'sql_injection_pattern') {
        addRec({
          action: 'use_parameterized_queries',
          title: 'Use Parameterized Queries or Prepared Statements',
          description: 'Never concatenate user input directly into SQL queries. Bind parameters using placeholders or query builder methods.',
          priority: 'high',
        });
      }

      if (f.type === 'command_injection_pattern') {
        addRec({
          action: 'avoid_shell_execution',
          title: 'Avoid Unsanitized Shell Subprocess Execution',
          description: 'Avoid passing user input to shell commands. Use argument vectors with execFile/spawn without shell=True, or utilize built-in APIs.',
          priority: 'high',
        });
      }

      if (f.type === 'dangerous_function') {
        addRec({
          action: 'avoid_dynamic_eval',
          title: 'Avoid Dynamic Evaluation and Unsafe Deserialization',
          description: 'Replace eval() or unsafe serialization formats (like pickle) with structured formats like JSON.parse().',
          priority: 'high',
        });
      }

      if (f.type === 'suspicious_attachment') {
        addRec({
          action: 'scan_file_before_opening',
          title: 'Avoid Opening or Executing Untrusted Files',
          description: 'Ensure files are inspected in an isolated environment before interacting with them.',
          priority: 'high',
        });
      }

      if (f.type === 'insecure_protocol') {
        addRec({
          action: 'use_https',
          title: 'Use Secure HTTPS Connection',
          description: 'This link uses unencrypted HTTP. Do not submit sensitive data over unencrypted connections.',
          priority: 'low',
        });
      }

      if (f.type === 'reputation_malicious') {
        addRec({
          action: 'avoid_known_malicious_url',
          title: 'Avoid Known Malicious Link',
          description: 'External threat intelligence lists this URL as actively malicious or associated with threats.',
          priority: 'high',
        });
        addRec({
          action: 'do_not_click',
          title: 'Do Not Click or Open Link',
          description: 'Avoid visiting this URL to protect against malware, credential harvesting, or exploitation.',
          priority: 'high',
        });
      }

      if (f.type === 'reputation_suspicious' || f.type === 'reputation_disputed') {
        addRec({
          action: 'verify_reported_threat',
          title: 'Exercise Caution with Flagged Link',
          description: 'Threat intelligence providers report suspicious activity or conflicting ratings for this link.',
          priority: 'medium',
        });
      }
    }

    // Default recommendation if no specific signals were found
    if (recs.length === 0) {
      if (riskLevel === 'low') {
        addRec({
          action: 'no_action_needed',
          title: 'No Suspicious Indicators Detected',
          description: 'No known threat or scam patterns were identified. Continue practicing standard digital hygiene.',
          priority: 'low',
        });
      } else {
        addRec({
          action: 'proceed_with_caution',
          title: 'Proceed with Caution',
          description: 'Verify sender identity and link legitimacy before taking sensitive actions.',
          priority: 'medium',
        });
      }
    }

    return recs;
  }
}
