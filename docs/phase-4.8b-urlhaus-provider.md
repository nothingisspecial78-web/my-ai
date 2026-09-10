# Phase 4.8B — URLhaus Live Reputation Provider

**Status**: Implemented  
**Date**: September 10, 2026  
**Scope**: URLhaus Community API Integration (abuse.ch), Lookup-Only Boundary, Normalization, Evidence Mapping & Safety Checkup Integration  

---

## 1. Executive Summary

Phase 4.8B introduces the **URLhaus Live Reputation Provider** as the first concrete external threat intelligence feed integrated into MyAI's safety architecture. URLhaus is a project operated by **abuse.ch** dedicated to tracking and sharing malicious URLs actively used for malware distribution.

In accordance with MyAI's architectural principles:
- **Lookup Only**: MyAI queries URLhaus for telemetry; it never submits URLs, crawls links, follows redirects, or executes remote content.
- **Offline Lexical Analysis Remains Sovereign**: URLhaus findings enrich deterministic lexical analysis rather than replacing it.
- **Absence of a Record ≠ Safety**: When a URL is not found in URLhaus, the result is normalized to `unknown`, never `clean`.
- **Zero Client Credential Leakage**: `URLHAUS_AUTH_KEY` is read strictly on the server and is never exposed to browser bundles or serialized into logs or evidence.

---

## 2. URLhaus API Endpoint & Request Isolation

- **Endpoint**: `https://urlhaus-api.abuse.ch/v1/url/`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Payload**: `url=<normalized_and_redacted_url>`
- **Authentication**: `Auth-Key: <URLHAUS_AUTH_KEY>` header (server-side only)
- **User-Agent**: `MyAI-SafetyCheck/1.0`

HTTP interactions are completely isolated within `UrlhausReputationProvider` (`src/lib/safety/reputation/urlhaus.ts`), which inherits from `BaseReputationProvider`. The provider enforces timeout protection, rate limiting, and safe degradation.

---

## 3. Normalized Mapping Specification

URLhaus API responses are strictly normalized into MyAI's `ProviderReputationResult` schema:

| URLhaus API Status (`query_status`) | MyAI `detectionStatus` | Confidence | Threat Categories | Finding Generated | Risk Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ok` (Active or historical threat) | `malicious` | `high` | `['malware']` (+ `['phishing']` if tagged) | `reputation_malicious` | Elevates overall risk to `high` |
| `no_results` (URL not in database) | `unknown` | `low` | None | None | Leaves lexical risk intact |
| `invalid_url` (Malformed query) | `unknown` | `low` | None | None | Leaves lexical risk intact |
| HTTP 429 (Rate limited) | `unavailable` | `low` | None | None | Fast-fail cooldown; local analysis continues |
| HTTP 401 / 403 (Auth failure) | `unavailable` | `low` | None | None | Logged safely without key; local analysis continues |
| HTTP 500+ / Network Error | `unavailable` | `low` | None | None | Isolated upstream error; local analysis continues |
| Missing `URLHAUS_AUTH_KEY` | `unavailable` | `low` | None | None | Provider unconfigured; local analysis continues |

---

## 4. Unknown vs. Malicious Semantics

A critical safety principle of URLhaus integration is that **"Not found in URLhaus" does not equal "safe"**:

1. **Why `no_results` maps to `unknown`**:
   URLhaus is a focused malware-distribution database. It does not track every benign website, nor does it immediately capture all zero-day phishing kits, brand-new scam domains, or targeted spear-phishing links. Labeling an unlisted domain as `clean` would create a dangerous false sense of security.
2. **Deterministic Fallback**:
   When URLhaus returns `no_results`, it attaches an informational evidence record:
   - *Label*: `URLhaus Threat Intelligence`
   - *Description*: `URLhaus: No matching malicious record found. Absence of a record is not proof of safety.`
   - *Snippet*: `Status: no_results | No malware records found in URLhaus feed`
   The risk evaluation continues relying on MyAI's deterministic lexical and brand-impersonation analyzers.

---

## 5. Security & Privacy Safeguards

- **Strict Server-Only Environment Variable**:
  `URLHAUS_AUTH_KEY` is loaded directly from `process.env.URLHAUS_AUTH_KEY` on the server. It is never prefixed with `NEXT_PUBLIC_` and is never included in client JavaScript bundles.
- **Privacy Redaction Before Hashing & Transmission**:
  Before any URL is sent to URLhaus or hashed into cache keys, it passes through `normalizeUrlForReputation()`. All embedded credentials (`user:password@host`) and sensitive query parameters (`password`, `token`, `otp`, `secret`, `session`) are redacted to `[REDACTED]`. Tracking parameters (`utm_*`, `fbclid`, etc.) are stripped.
- **Zero Execution of User URLs**:
  URLs are handled strictly as passive string data. MyAI never:
  - Navigates to user URLs.
  - Follows HTTP redirects.
  - Resolves DNS records.
  - Scans TCP/UDP ports.
  - Downloads or executes payloads.
- **No Secret Leakage in Logs or Errors**:
  Provider error messages and evidence records are sanitized to guarantee that `URLHAUS_AUTH_KEY` is never reflected in error text or database storage.

---

## 6. Caching Layer Integration

`UrlhausReputationProvider` integrates with `RedisReputationCache`:
- **Cache Key Format**: `rep:urlhaus:<sha256_of_normalized_url>`
- **TTL**: 3600 seconds (1 hour default)
- **Stale Detection**: Expired entries are detected and bypassed, prompting a fresh lookup rather than serving stale verdicts as fresh.
- **In-Memory Fallback**: Operates without errors when Redis is unconfigured or temporarily offline.

---

## 7. UI Presentation in `SafetyAnalysisCard`

URLhaus telemetry is rendered directly in `SafetyAnalysisCard` under **Reputation Telemetry**:
- If malicious:
  - *Title*: `URLhaus Threat Intelligence`
  - *Description*: `URLhaus reputation: Known malicious URL associated with malware distribution (malware_download).`
  - *Snippet*: `Threat: malware_download | Status: online | Tags: elf, Mozi`
- If no matching record:
  - *Title*: `URLhaus Threat Intelligence`
  - *Description*: `URLhaus: No matching malicious record found. Absence of a record is not proof of safety.`
  - *Snippet*: `Status: no_results | No malware records found in URLhaus feed`

---

## 8. Limitations

- URLhaus tracks malware distribution sites. It does not catalog all forms of internet fraud, scams, or unindexed phishing domains.
- A clean or unlisted record in URLhaus is not an endorsement or guarantee of website safety.
- MyAI's deterministic risk engine remains the sovereign authority for assessing overall risk levels.
