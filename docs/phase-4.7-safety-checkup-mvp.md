# Phase 4.7 — Safety Checkup MVP Documentation
## Real URL Analysis + Scam Message Analysis + Chat Integration

### 1. Executive Summary

Phase 4.7 activates the end-user Safety Checkup MVP in MyAI. The application now accepts user inputs (pure URLs, suspicious SMS/WhatsApp/email messages, or source code snippets) and performs deterministic, offline lexical security analysis. It computes a calibrated risk level, identifies granular indicators, applies privacy redactions, persists the analysis to Supabase under strict Row-Level Security (RLS), guides Google Gemini to explain the findings objectively without overriding them, and renders a dedicated accessible UI card (`SafetyAnalysisCard`).

If Gemini or upstream AI services fail or exhaust quota, a deterministic fallback markdown report is delivered automatically without presenting an internal server error.

---

### 2. Supported Input Types & Deterministic Classification

Input routing is evaluated deterministically by `InputClassifier`:
- **`url`**: Single-token strings adhering to valid URI schemes (`http://`, `https://`, `ftp://`, or IP addresses). No whitespace or multi-sentence tokens are permitted.
- **`message`**: Multi-word text, SMS alerts, WhatsApp forwards, phishing emails, or paragraphs containing embedded links. When a message contains URLs, `MessageScamAnalyzer` extracts every link and executes lexical URL analysis concurrently, combining all findings into a unified report.
- **`code`**: Scripts and programming syntax (e.g. JavaScript, Python, SQL) identified by keywords (`function`, `const`, `import`, `def`, `SELECT`, `UPDATE`).
- **`email`**: Standalone email addresses or headers.
- **`claim`**: General claims or questions.
- **`document` / `file` / `image` / `screenshot` / `qr`**: Identified via MIME types, file extensions, or dedicated classifiers.

---

### 3. Deterministic Analyzer Behavior

All analyzers operate **strictly offline**.
- **No external HTTP requests**
- **No page loading or headless browsing**
- **No DNS lookups or socket connections**
- **No execution of user code** (`eval`, `child_process`, or shell execution are strictly prohibited)

#### A. URL Analyzer (`UrlAnalyzer`)
1. **Protocol Analysis**: Identifies insecure `http:` vs secure `https:`, and flags unusual or unsupported protocols.
2. **Hostname & IP Checks**:
   - Detects raw IP addresses used as hostnames.
   - Distinguishes private/internal IP ranges (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `127.0.0.1`, `localhost`) from public IPs.
   - Flags Punycode domains (`xn--`) and internationalized lookalike characters.
   - Identifies excessive subdomains and abnormal hyphenation.
3. **Host Confusion & Userinfo Tricks**:
   - Detects the `@` trick (e.g. `https://paypal.com@evil.example/login`), where credentials or brand names preceding `@` obscure the true destination host (`evil.example`).
4. **Suspicious Keyword Identification**:
   - Inspects subdomains, pathnames, and query parameters for credential harvesting and account coercion keywords (`login`, `verify`, `account`, `security`, `signin`, `recover`, `unlock`, `wallet`, `bank`).
5. **Brand-Lookalike Heuristics**:
   - Evaluates conservative character substitutions (e.g. `paypa1`, `micros0ft`, `goog1e`, `app1e`) and records findings as "Possible lookalike-brand pattern" rather than claiming confirmed trademark infringement.
6. **URL Shortening Detection**:
   - Recognizes known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd`, `cutt.ly`, etc.) and notes the masked destination as a low-severity observation.

#### B. Message Scam Analyzer (`MessageScamAnalyzer`)
1. **Threat & Coercion**: Detects urgent threats of account suspension, closure, or legal action.
2. **Urgency Language**: Detects pressure tactics (`immediately`, `within 24 hours`, `final warning`).
3. **Credential Requests**: Detects requests to provide passwords or account credentials.
4. **OTP Requests**: Flags solicitations for one-time passwords, verification codes, or PINs. Legitimate 2FA security advisories (e.g. "Never share your OTP") are explicitly distinguished and not falsely flagged.
5. **Financial & Prize Requests**: Identifies advance-fee fraud, lottery winnings requiring processing fees, and wire/gift card requests.
6. **Embedded Link Analysis**: Automatically extracts all URLs from the message and runs them through `UrlAnalyzer`, combining all signals.

---

### 4. Calibrated Risk Methodology

The risk engine (`RiskEngine`) evaluates findings deterministically. The discrete `RiskLevel` is authoritative; the `score` (0–100) is an internal heuristic support metric:
- **Low Risk**:
  - No suspicious signals found (e.g. `https://example.com` or "My bank appointment is today").
  - Single weak signals (e.g. unencrypted HTTP alone or a shortened URL alone).
- **Medium Risk**:
  - Private network administrative interface (e.g. `http://192.168.1.1/login`).
  - Single moderate finding or isolated threat language without credentials/URLs.
- **High Risk**:
  - Combination of active coercion + credential/OTP request.
  - Phishing messages with embedded login links.
  - URL host confusion tricks (e.g. `https://paypal.com@evil.example/login`).
  - Lookalike brand domain paired with login/security keywords.
- **Critical Risk**:
  - Reserved for rare, unambiguous hazards such as plaintext exposed API keys/secrets or active multi-vector credential theft combinations.

---

### 5. Privacy & Redaction Layer

Data minimization is enforced at all storage boundaries:
- **`redactUrl(url)`**: Sanitizes sensitive query parameters (`password`, `passwd`, `pwd`, `token`, `otp`, `pin`, `secret`, `session`, `auth`, `api_key`, `key`) into `[REDACTED]`.
- **`redactSensitiveText(text)`**: Redacts raw OTP numeric sequences, known API key prefixes (`ghp_`, `sk_live_`, `AKIA`), and password patterns before reports are returned or stored.
- **`redactDataRecord(record)`**: Recursively sweeps structured evidence objects, replacing sensitive keys with `[REDACTED]`.

Raw user chat history follows normal chat application rules, but all records stored in the `safety_*` tables are strictly redacted.

---

### 6. Persistence & Row-Level Security (RLS)

Safety analyses are persisted into the Phase 4.6 tables:
- `public.safety_analyses`
- `public.safety_findings`
- `public.safety_evidence`
- `public.safety_recommendations`

**Security Enforcement**:
- All operations are executed server-side via `SafetyRepository`.
- Authentication is derived strictly from the `@supabase/ssr` server cookie session.
- Additive migration `20260910120000_safety_security_insert_policies.sql` establishes `INSERT` policies enforcing `WITH CHECK (auth.uid() = user_id)`.
- Client code cannot supply an arbitrary `user_id`.
- Browser clients do not have direct mutation permissions; only `SELECT` is allowed for records where `auth.uid() = user_id`.

---

### 7. Gemini Explanation Layer & Deterministic Fallback

1. **Role of Gemini**:
   - Receives structured analysis context (`SafetyService.formatForGemini`).
   - Explains findings clearly in natural, non-alarmist language.
   - System prompt instructs Gemini never to alter the deterministic risk level, invent external scan results, or claim certainty.
2. **Deterministic Fallback (`SafetyService.generateFallbackResponse`)**:
   - If Gemini is unavailable, rate-limited, or throws an exception, `/api/chat` catches the error and streams the structured deterministic markdown report directly.
   - The user receives an immediate, fully actionable safety assessment without encountering an internal server error.

---

### 8. User Interface (`SafetyAnalysisCard`)

- **Component**: `src/components/safety/SafetyAnalysisCard.tsx`
- Integrated into `src/components/chat/Message.tsx` whenever `metadata.safetyReport` is present.
- **Accessibility**:
  - Communicates risk using prominent text badges (`LOW RISK`, `MEDIUM RISK`, `HIGH RISK`, `CRITICAL RISK`) and distinct icons (`ShieldCheck`, `AlertTriangle`, `ShieldAlert`, `AlertOctagon`), avoiding reliance on color alone.
  - Displays confidence level and heuristic risk score.
  - Contains expandable/collapsible details for detected indicators, recommended actions, and scope boundaries.

---

### 9. Explicit Boundaries & Future External Reputation Architecture

**CRITICAL NOTICE**:
> **Phase 4.7 DOES NOT perform live website reputation checks.**
> It relies entirely on offline lexical analysis of the provided text/URL.
> It does NOT verify whether a domain is currently registered, whether an IP is active, or whether a website is listed on third-party blocklists.

**Future Integrations (Post-Phase 4.7)**:
Future milestones may safely integrate server-side reputation APIs:
- Google Safe Browsing API v4
- VirusTotal v3 API
- URLhaus / PhishTank
- RDAP / Whois domain age lookup services

These must be integrated via backend queuing with caching, rate limiting, and timeout isolation to avoid SSRF vulnerabilities.
