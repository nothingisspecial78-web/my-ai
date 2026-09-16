# Google Sheets Integration Guide

This guide documents the architecture, configuration, security guarantees, and usage of the **Google Sheets Telemetry Integration** for the *Before You Click* application.

---

## 1. Architectural Principles & Invariants

1. **Supabase/PostgreSQL is the Sole Source of Truth**:
   - Application state, chat sessions, user profiles, and security analyses are exclusively stored and managed in Supabase with strict Row Level Security (RLS).
   - Google Sheets is strictly an **optional external telemetry & analytics export sink**.
2. **Never Authoritative for Security Decisions**:
   - Google Sheets data is never read back to make security determinations.
   - The deterministic `RiskEngine` is the sole scoring and verdict authority.
3. **Decoupled & Non-Blocking**:
   - Google Sheets API calls are executed asynchronously and in isolated try/catch boundaries.
   - Outages, rate limits (429), timeouts, or credential revocations on Google's side **never** delay, abort, or alter chat responses or security analyses.
4. **Strict Privacy Boundary**:
   - Zero raw user prompts, raw chat messages, raw OCR text, raw QR payloads, passwords, OTPs, API keys, or private RFC 1918 IPs/localhost hosts are ever sent to Google Sheets.
   - User IDs are pseudonomized using truncated HMAC-SHA256 hashes (`user_id_hash`).
   - Freeform concerns and explanations are scrubbed with `redactSensitiveText` and hard-bounded to 300 characters.

---

## 2. Google Cloud Console Setup

To enable user Google Sheets authorization in development and production:

### Step A: Create or Select a Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project (e.g., `before-you-click-prod`) or select an existing project.

### Step B: Enable Google Sheets API
1. Go to **APIs & Services > Library**.
2. Search for **Google Sheets API**.
3. Click **Enable**.

### Step C: Configure OAuth Consent Screen
1. Go to **APIs & Services > OAuth consent screen**.
2. Select **User Type**:
   - **External** (if allowing any Google account user to connect their sheet).
3. Fill in App Information:
   - **App Name**: `Before You Click`
   - **User support email**: Your support contact email.
   - **Developer contact information**: Your technical contact email.
4. Under **Scopes**, add:
   - `https://www.googleapis.com/auth/spreadsheets` (Spreadsheet row appending and sheet inspection).
5. For testing, add Test Users under the **Test users** tab.

### Step D: Create OAuth 2.0 Client Credentials
1. Go to **APIs & Services > Credentials**.
2. Click **Create Credentials > OAuth client ID**.
3. Select **Application type**: **Web application**.
4. Set **Name**: `Before You Click Web Client`.
5. Under **Authorized redirect URIs**, add:
   - Development: `http://localhost:3000/api/integrations/google-sheets/callback`
   - Production: `https://your-domain.com/api/integrations/google-sheets/callback`
6. Click **Create**. Copy the **Client ID** and **Client Secret**.

---

## 3. Environment Variables Configuration

Add the following environment variables to your `.env.local` (server-side only, **never** prefix with `NEXT_PUBLIC_`):

```bash
# Google Sheets OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:3000/api/integrations/google-sheets/callback

# Server-side AES-256-GCM token encryption key (32-byte hex or base64)
# Generate using: openssl rand -hex 32
GOOGLE_SHEETS_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Pseudonymous user ID hashing salt
# Generate using: openssl rand -hex 16
GOOGLE_SHEETS_USER_HASH_SALT=fedcba9876543210fedcba9876543210
```

---

## 4. Database Schema & Security

The integration relies on two Supabase tables with Row Level Security enabled:

### `user_google_sheets_integrations`
Stores user OAuth tokens (AES-256-GCM encrypted) and spreadsheet preferences:
- `user_id`: Foreign key to `auth.users` (RLS enforced: users can only select/update their own record).
- `status`: `'connected' | 'disconnected' | 'revoked' | 'error'`.
- `spreadsheet_id`: Target Google Sheet ID.
- `sheet_name`: Target sheet tab (defaults to `"Security Telemetry"`).
- `encrypted_refresh_token`: Ciphertext of the Google OAuth refresh token.
- `token_iv`: Initialization vector.
- `token_tag`: AES-GCM authentication tag.
- `last_synced_at`: Timestamp of most recent export.

### `safety_analysis_exports`
Provides durable idempotency to prevent duplicate row appends:
- Unique constraint: `UNIQUE (user_id, analysis_id, destination)`
- `destination`: `'google_sheets'`
- `status`: `'exported' | 'failed' | 'skipped'`

---

## 5. Export Data Schema (15 Columns)

Each exported row appends the following standardized columns:

| Column | Header | Type | Description |
|---|---|---|---|
| 1 | `timestamp` | ISO String | Timestamp of analysis execution |
| 2 | `analysis_id` | String | Unique report identifier |
| 3 | `user_id_hash` | String | 16-character pseudonymous HMAC-SHA256 hash |
| 4 | `input_type` | String | Input type (`url`, `message`, `image`, etc.) |
| 5 | `theme` | String | Active theme slug (`security-checkup`, etc.) |
| 6 | `risk_level` | String | Uppercase verdict (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| 7 | `risk_score` | Number | Deterministic score (0-100) from `RiskEngine` |
| 8 | `confidence_level` | String | Confidence rating (`LOW`, `MEDIUM`, `HIGH`) |
| 9 | `primary_concern` | String | Privacy-redacted concern summary (max 300 chars) |
| 10 | `domains_involved` | String | Semicolon-separated public domains (private IPs blocked) |
| 11 | `finding_count` | Number | Count of observable security findings |
| 12 | `recommendation_count` | Number | Count of structured recommendations |
| 13 | `analyzer_coverage` | String | Semicolon-separated list of active analyzers |
| 14 | `status` | String | Execution status (`COMPLETED`, `PARTIAL`, `FAILED`) |
| 15 | `created_at` | ISO String | Original report creation timestamp |

---

## 6. Testing & Quality Verification

Run the dedicated integration test suites:

```bash
npx vitest run src/lib/integrations/google-sheets
```

Run full project quality gates:

```bash
npx vitest run
npx tsc --noEmit
npm run lint
npm run build
```
