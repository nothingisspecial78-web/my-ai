# Phase 4.8A — Live URL Reputation Intelligence Architecture

**Status**: Implemented  
**Date**: September 10, 2026  
**Scope**: Provider-Agnostic Reputation Intelligence, Normalization, Aggregation, Caching & Risk Engine Integration  

---

## 1. Executive Summary

Phase 4.8A establishes the **Live URL Reputation Intelligence Architecture** for MyAI. This architecture enables future integration with external threat intelligence and URL reputation vendors (such as VirusTotal, Google Safe Browsing, PhishTank, and URLScan) without making direct external network requests in this phase, without exposing credentials or API keys to the client, and without treating external verdicts as infallible ground truth.

In MyAI's safety model:
- **Offline deterministic lexical analysis remains the immutable baseline**.
- External reputation results serve as **supporting evidence** rather than autonomous verdicts.
- Risk severity is strictly **decoupled from assessment confidence**.
- The system **never claims 100% certainty** (safe or malicious).

---

## 2. Architecture & System Topology

```
+-----------------------------------------------------------------------------------+
|                                  USER / CLIENT                                    |
|                   Submits URL / Message with Embedded Links                       |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        MYAI SAFETY CHECKUP SERVICE                                |
|                                                                                   |
|  1. Input Classification                                                          |
|     Identifies 'url' or extracts embedded URLs from 'message' / 'email'           |
|                                                                                   |
|  2. Privacy & Normalization Layer (redaction.ts & cache.ts)                       |
|     - Strips tracking & analytics params (utm_*, fbclid, gclid, etc.)             |
|     - Redacts sensitive params (password, token, otp, secret, etc.)               |
|     - Normalizes protocol, hostname casing, standard ports, and query order       |
|     - Generates SHA-256 cache key: rep:<scope>:<sha256>                           |
+-----------------------------------------------------------------------------------+
             |                                              |
             v                                              v
+--------------------------+               +----------------------------------------+
|  DETERMINISTIC ANALYZER  |               |       REPUTATION PROVIDER LAYER        |
|  (url-analyzer.ts)       |               |       (reputation/provider.ts)         |
|                          |               |                                        |
|  - IP as host            |               |  +----------------------------------+  |
|  - Lookalike domain      |               |  | Reputation Cache (Redis/Memory)  |  |
|  - Brand impersonation   |               |  +----------------------------------+  |
|  - Host confusion        |               |                  |                     |
|  - Insecure HTTP         |               |  +---------------+------------------+  |
|  - Shortened URLs        |               |  | Provider Registry & Execution    |  |
|  - Sensitive credentials |               |  | - Timeout guard (AbortSignal)    |  |
+--------------------------+               |  | - Rate-limit backoff (429)       |  |
             |                             |  | - Non-fatal error isolation      |  |
             |                             |  +----------------------------------+  |
             |                             +----------------------------------------+
             |                                              |
             +----------------------+-----------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------------+
|                          REPUTATION AGGREGATION LAYER                             |
|                           (reputation/aggregator.ts)                              |
|                                                                                   |
|  - Calculates weighted consensus score (-1.0 clean to +1.0 malicious)             |
|  - Resolves provider disputes (e.g. 1 malicious vs 1 clean -> suspicious/dispute) |
|  - Synthesizes Finding objects ('reputation_malicious', 'reputation_disputed')    |
|  - Attaches Evidence records with isAiGenerated: false                            |
|  - Appends telemetry limitation notes                                             |
+-----------------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------------+
|                           DETERMINISTIC RISK ENGINE                               |
|                                (risk-engine.ts)                                   |
|                                                                                   |
|  - Combines deterministic lexical findings + reputation findings                  |
|  - Calculates calibrated risk level: low | medium | high | critical                |
|  - Decouples confidence level: low | medium | high                                |
|  - Generates actionable, proportional recommendations                             |
+-----------------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------------+
|                      GEMINI REASONING & EXPLANATION LAYER                         |
|                                                                                   |
|  Explains findings in plain, objective language without overriding risk level     |
+-----------------------------------------------------------------------------------+
```

---

## 3. Data Flow Specification

1. **Input Ingestion**:
   The user submits a link or message. The input classifier assigns the input type as `'url'` or identifies embedded links within text.
2. **Canonical Normalization**:
   Before any caching or external lookup, the URL is processed by `normalizeUrlForReputation(rawUrl)`. Sensitive credentials (`password`, `token`, `otp`, `secret`) are replaced with `[REDACTED]`. Tracking artifacts (`utm_*`, `fbclid`, etc.) are removed. Hostname is lowercased, default ports (`:80`, `:443`) and client hash fragments (`#...`) are stripped, and search parameters are sorted alphabetically.
3. **Cache Lookup**:
   The normalized URL is hashed using SHA-256 (`rep:${providerId}:${sha256}`). The `RedisReputationCache` checks for a valid, non-stale cached result. If fresh, it returns immediately with `cached: true`.
4. **Provider Execution Guard**:
   If a cache miss occurs, the provider executes within a strict timeout window (`Promise.race` with `defaultTimeoutMs`). If the provider is rate-limited (HTTP 429), it fast-fails into a cooldown state without blocking the application.
5. **Aggregation & Conflict Resolution**:
   `ReputationAggregator` gathers all provider outputs. If providers disagree (e.g., Provider A flags malicious, Provider B reports clean), the dispute algorithm assigns `'suspicious'`, flags `disputed: true`, and generates a `reputation_disputed` finding with moderate severity (`medium`), rather than blindly escalating to `critical`.
6. **Risk Engine Synthesis**:
   All findings (lexical and reputation) enter `RiskEngine.evaluate()`. Recommendations such as `avoid_known_malicious_url`, `verify_reported_threat`, or `do_not_click` are emitted.
7. **Explanation**:
   Gemini receives the structured `SafetyReport` and translates findings into transparent user guidance.

---

## 4. Provider Interface & Normalized Result Contract

### 4.1. Core Interface (`ReputationProvider`)

```typescript
export interface ReputationProvider {
  readonly id: string;
  readonly name: string;
  readonly defaultTimeoutMs: number;
  getStatus(): ProviderStatus;
  lookupUrl(url: string, options?: ReputationLookupOptions): Promise<ProviderReputationResult>;
}
```

### 4.2. Normalized Result Schema (`ProviderReputationResult`)

```typescript
export interface ProviderReputationResult {
  providerId: string;
  providerName: string;
  url: string; // Normalized & privacy-redacted
  status: ProviderStatus; // 'ready' | 'degraded' | 'rate_limited' | 'disabled' | 'unavailable'
  detectionStatus: ReputationDetectionStatus; // 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'unavailable'
  confidence: ConfidenceLevel; // 'low' | 'medium' | 'high'
  threatCategories?: ReputationThreatCategory[];
  rawDetails?: Record<string, unknown>;
  evidence: Evidence;
  timestamp: string; // ISO 8601
  latencyMs: number;
  cached: boolean;
  error?: ReputationError;
}
```

---

## 5. Aggregation & Conflict Resolution

External vendors frequently disagree due to indexing delays, false positives, or specialized heuristics. The aggregation layer enforces the following principles:

| Scenario | Provider A | Provider B | Provider C | Aggregated Status | Disputed? | Resulting Finding | Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Consensus Clean** | Clean (High) | Clean (Med) | - | `clean` | No | `reputation_clean` | High |
| **Consensus Malicious** | Malicious (High) | Malicious (Med) | - | `malicious` | No | `reputation_malicious` | High |
| **Provider Conflict (1 Malicious vs 1 Clean)** | Malicious (High) | Clean (High) | Unknown | `suspicious` | **Yes** | `reputation_disputed` | Medium |
| **2 Malicious + 1 Clean** | Malicious (High) | Malicious (High) | Clean (High) | `suspicious` | **Yes** | `reputation_disputed` | Medium |
| **1 Malicious + 2 Clean** | Malicious (High) | Clean (High) | Clean (High) | `suspicious` | **Yes** | `reputation_disputed` | Medium |
| **1 Suspicious + 2 Clean** | Suspicious (Med) | Clean (High) | Clean (High) | `clean` | No | `reputation_clean` | Medium (capped) |
| **3 Unknown** | Unknown (Low) | Unknown (Low) | Unknown (Low) | `unknown` | No | None (limitation added) | Low |
| **Suspicious Signal Alone** | Suspicious (Med) | Unknown (Low) | - | `suspicious` | No | `reputation_suspicious` | Medium |
| **All Offline / Timeout** | Timeout | 429 Rate Limit | Network Error | `unavailable` | No | None (limitation added) | Low |

### Why Conflicts Do Not Escalate Blindly to Malicious
If a newly registered domain or benign blog is flagged by a single aggressive blacklist while major search engine telemetry rates it clean, labeling the site as confirmed malicious causes false panic. The system generates a `reputation_disputed` finding with `medium` severity and recommends independent verification (`verify_reported_threat`).

---

## 6. Caching Architecture & Redis Integration

- **Cache Interface**: `ReputationCache` defines `get`, `set`, `delete`, and `clear`.
- **Primary Backend**: `RedisReputationCache` connects via `getRedis()` from `src/lib/redis.ts`.
- **In-Memory Fallback**: When `REDIS_URL` is omitted (local development, unit tests, or CI), the cache operates seamlessly via an internal memory map without throwing errors.
- **Key Derivation**: Keys are generated using SHA-256 hashes of canonicalized URLs (`rep:<provider_id>:<sha256>`).
- **Staleness Handling**: When a record exceeds its TTL, `get()` marks `stale: true`, allowing consumers to decide whether to serve background-refreshed data.

---

## 7. Privacy & Data Protection

- **URLs are Untrusted Data**: URLs are never executed, fetched, or crawled.
- **Query Parameter Redaction**: Any parameter containing passwords, authentication tokens, session identifiers, API keys, or OTPs is stripped or replaced with `[REDACTED]` prior to cache key generation and prior to logging or evidence creation.
- **Tracking Parameter Removal**: Marketing trackers (`utm_*`, `fbclid`, `gclid`, `msclkid`, etc.) are removed during normalization to protect user privacy and maximize cache hit ratios.

---

## 8. Failure Handling & Resilience

1. **Timeout Shielding**:
   Every provider lookup is raced against a configurable deadline (`defaultTimeoutMs`, default 3,000ms). If a provider fails to respond in time, an `unavailable` result with `error: { code: 'timeout' }` is returned.
2. **Rate-Limit Fast Failure**:
   Upon receiving HTTP 429, the provider transitions to `'rate_limited'` status with an active cooldown timestamp. Subsequent lookups fast-fail in `<5ms` without making calls until the cooldown expires.
3. **Graceful Degradation**:
   If all external providers fail or time out, the safety report continues successfully using deterministic lexical rules. A limitation note is added: *"All external reputation providers were unavailable or timed out. Analysis relies on deterministic pattern checks."*

---

## 9. Security Boundaries

In accordance with strict security requirements:
- **No Crawling or Fetching**: MyAI does not issue HTTP requests to user-submitted URLs.
- **No DNS Resolution**: The application does not resolve DNS records for arbitrary user URLs.
- **No Script Execution**: JavaScript execution and browser automation are strictly prohibited.
- **No Client-Side Secrets**: All reputation provider coordination is confined to the server layer.

---

## 10. Future Provider Integration

When real reputation providers are connected in subsequent phases:
1. Extend `BaseReputationProvider` (e.g. `VirusTotalReputationProvider`, `GoogleSafeBrowsingProvider`).
2. Implement the single abstract method:
   ```typescript
   protected abstract executeLookup(
     normalizedUrl: string,
     options?: ReputationLookupOptions
   ): Promise<{
     detectionStatus: ReputationDetectionStatus;
     confidence: ConfidenceLevel;
     threatCategories?: ReputationThreatCategory[];
     rawDetails?: Record<string, unknown>;
     description?: string;
   }>;
   ```
3. Register the provider instance in `reputationRegistry.register(provider)`.
4. Inject API keys strictly via server-side environment variables (`process.env.VIRUSTOTAL_API_KEY`).

---

## 11. Why the Final Risk Decision Remains Inside MyAI

External reputation providers are remote data vendors with varying coverage, geographic biases, latency, and false positive rates. They do not understand the contextual surroundings of the user's inquiry (e.g. urgency language in an accompanying email, fake bank domains, or credential harvesting forms).

Therefore:
- External providers supply **evidence signals**.
- **MyAI's Deterministic Risk Engine** synthesizes reputation evidence with local lexical findings.
- **MyAI retains absolute ownership of the final risk level and user recommendations.**
