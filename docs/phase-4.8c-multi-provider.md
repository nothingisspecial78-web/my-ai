# Phase 4.8C — Multi-Provider Reputation Intelligence

**Status**: Implemented  
**Date**: September 11, 2026  
**Scope**: Multi-Provider Threat Intelligence Architecture, Google Safe Browsing Lookup API Integration, Consensus & Disagreement Aggregation Matrix, Scope & Boundary Telemetry  

---

## 1. Executive Summary

Phase 4.8C introduces **Multi-Provider Reputation Intelligence** to MyAI's safety architecture. By extending the reputation layer from a single feed to multiple independent threat intelligence providers, MyAI achieves resilient, balanced threat detection while adhering to strict safety principles:

1. **No Provider Dictates the Final Verdict**: External reputation feeds are treated as structured evidence, never as authoritative or infallible truth.
2. **Provider Disagreements are Represented Explicitly**: When one provider flags a URL as malicious while another rates it clean, MyAI classifies the aggregate status as `suspicious` (disputed) with downgraded confidence, preventing false certainty.
3. **Decoupled Risk & Lexical Sovereignty**: Strong local lexical indicators (e.g. lookalike domains, credential harvesting, seed phrase requests) retain high risk even if all external reputation providers report `clean`.
4. **Zero Client-Side Key Exposure**: Server-side credentials (`SAFE_BROWSING_API_KEY` and `URLHAUS_AUTH_KEY`) are kept isolated on the server and are never exposed in browser bundles, logs, or serialized evidence.
5. **Partial Coverage Transparency**: When providers return `unknown` or become unavailable during an evaluation, MyAI explicitly discloses partial coverage in analysis limitations.

---

## 2. Second Provider: Google Safe Browsing Lookup API (v4)

### 2.1 Provider Selection Rationale
- **Authoritative Anti-Phishing & Malware Coverage**: Google Safe Browsing is an industry-standard web safety service protecting billions of devices across malware, phishing, and unwanted software.
- **True Negative / Clean Signal**: Unlike URLhaus (which indexes malware URLs and returns `no_results` $\rightarrow$ `unknown`), Google Safe Browsing evaluates active blocklists. An empty response `{}` confirms that no active threats are listed, enabling genuine `clean` vs `malicious` consensus modeling.
- **Server-Side Lookup Only**: Uses the official REST API (`POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=...`) with JSON payloads. No client scraping, no browser automation, no downloading of malicious binaries.
- **Developer Tier**: Free developer access with generous daily quotas suitable for server-side lookup queries.

### 2.2 Request Structure
- **Endpoint**: `https://safebrowsing.googleapis.com/v4/threatMatches:find`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`, `User-Agent: MyAI-SafetyCheck/1.0`
- **Authentication**: `SAFE_BROWSING_API_KEY` passed safely via server-to-server query parameter.
- **Payload**:
  ```json
  {
    "client": {
      "clientId": "myai-safety-service",
      "clientVersion": "1.0.0"
    },
    "threatInfo": {
      "threatTypes": [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION"
      ],
      "platformTypes": ["ANY_PLATFORM"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [{ "url": "<normalized_and_redacted_url>" }]
    }
  }
  ```

### 2.3 Normalized Mapping Specification
| Safe Browsing API Response | Detection Status | Confidence | Threat Categories | Risk Impact |
| :--- | :--- | :--- | :--- | :--- |
| `matches` present (MALWARE, SOCIAL_ENGINEERING, etc.) | `malicious` | `high` | `malware`, `phishing`, `unwanted`, `suspicious` | Contributes to `high` risk |
| Empty match `{}` / `matches: []` | `clean` | `medium` | None | Contributes to clean consensus; never overwrites local lexical risk |
| HTTP 429 (Rate Limited) | `unavailable` | `low` | None | Triggers cooldown backoff; local analysis continues |
| HTTP 400 (Bad Request) | `unavailable` | `low` | None | Normalizes to `invalid_response` |
| HTTP 401 / 403 (Auth Error) | `unavailable` | `low` | None | Normalizes to `network_error` without leaking key |
| HTTP 500+ / Timeout / Network Error | `unavailable` | `low` | None | Graceful fallback; local analysis continues |
| Missing `SAFE_BROWSING_API_KEY` | `unavailable` | `low` | None | Degrades gracefully; provider marked unconfigured |

---

## 3. Multi-Provider Aggregation & Disagreement Matrix

The `ReputationAggregator` evaluates all active providers using weighted scoring and explicit conflict detection:

$$\text{Consensus Score} = \frac{\sum (\text{Status Weight} \times \text{Confidence Multiplier})}{\sum \text{Confidence Multiplier}}$$

Where:
- `malicious`: $+1.0$
- `suspicious`: $+0.5$
- `unknown` / `unavailable`: $0.0$
- `clean`: $-1.0$

### 3.1 Aggregation Scenarios (A through H)

| Scenario | Provider 1 (URLhaus) | Provider 2 (Safe Browsing) | Aggregate Status | Finding Type | Limitations / Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | `malicious` | `malicious` | `malicious` | `reputation_malicious` | Strong consensus; score $+1.0$, `high` confidence |
| **B** | `malicious` | `clean` | `suspicious` | `reputation_disputed` | Explicit conflict detected; score $\approx 0.0$, `medium` confidence |
| **C** | `unknown` | `clean` | `clean` | `reputation_clean` | Clean evidence recorded; limitation notes partial coverage & non-definitive status |
| **D** | `unknown` | `unknown` | `unknown` | None | Zero phantom findings; summary notes insufficient telemetry |
| **E** | `unavailable` | `unavailable` | `unavailable` | None | Safe degradation; zero crashes; limitations list offline vendors |
| **F** | `malicious` | `unavailable` | `malicious` | `reputation_malicious` | Threat preserved; limitation explicitly notes partial coverage |
| **G** | `clean` / `unknown` | `malicious` | `suspicious` (disputed) / `malicious` | `reputation_disputed` / `reputation_malicious` | Disagreements represented explicitly; never suppressed |
| **H** | `clean` | `clean` (Local Lexical: `HIGH`) | `clean` (reputation) | `reputation_clean` (severity `info`) | **Final risk remains `HIGH`**; local lexical findings preserve sovereignty |

---

## 4. UI Rendering in SafetyAnalysisCard

`SafetyAnalysisCard` renders structured reputation telemetry while preserving an accessible visual hierarchy:

- **Per-Provider Telemetry**:
  - Provider name (e.g. `URLhaus`, `Google Safe Browsing`)
  - Status badge (`Status: Malicious`, `Status: Clean`, etc.)
  - Confidence indicator (`Confidence: High`, `Confidence: Medium`)
  - Descriptive summary & snippet
- **Consensus Badge**:
  - Automatically rendered when multiple providers are queried.
  - Displays aggregate consensus status (`Consensus: Disputed`, `Consensus: Malicious`, `Consensus: Clean`) and numerical score.
- **Scope & Analysis Boundaries**:
  - Renders all provider limitations (e.g. conflicting telemetry, partial coverage, unlisted domain caveats).

---

## 5. Security & Privacy Architecture

- **Server-Only Secrets**: `SAFE_BROWSING_API_KEY` and `URLHAUS_AUTH_KEY` are read strictly in Node server contexts. Neither is prefixed with `NEXT_PUBLIC_`.
- **Pre-Query Redaction**: URLs are stripped of sensitive query parameters (e.g. passwords, tokens, session IDs) and analytics tracking tokens (`utm_*`, `fbclid`, etc.) before lookup and cache key hashing.
- **Cache Isolation**: Redis keys use SHA-256 digests scoped by provider ID (`rep:urlhaus:<sha256>`, `rep:safebrowsing:<sha256>`). Raw API responses and authentication headers are never written to the cache.
