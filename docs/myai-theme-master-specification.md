# MYAI THEME MASTER SPECIFICATION
**Architecture & Design Blueprint for the Unified Visual & Intelligence Theme System**

---

## 1. Core Architecture

The MyAI Theme System establishes a unified, two-layer architecture that completely separates **Visual Presentation** from **Domain Intelligence & Deterministic Processing**. This decoupling allows themes to scale from simple visual styling to prompt-guided personas, up to full deterministic backend security and mathematical engines, without architectural coupling or code duplication.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                UNIFIED THEME SYSTEM                                    │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│           LAYER 1: VISUAL LAYER           │        LAYER 2: INTELLIGENCE LAYER         │
│          (Client-Side & Styling)          │       (Server-Side & Model Pipeline)       │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│  • Theme Design Tokens (CSS Custom Props) │  • System Prompt Directives & Rules        │
│  • Tailwind v4 @theme inline token bridge │  • Deterministic Backend Engines           │
│  • data-theme="[slug]" container scoping  │  • Input Analyzers & Context Builders      │
│  • Accent, Border, Glow, & Avatar Colors  │  • Multi-Provider Reputation Telemetry     │
│  • Dynamic Welcome Screen Hero & Prompts  │  • Domain Risk Engines & Threat Models     │
│  • Active Chat Header Badges              │  • Specialized Structured Result Cards     │
│  • Sidebar Conversation Theme Badging     │  • Telemetry Metadata Passing in Stream    │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

### 1.1 Four Permitted Theme Archetypes

A theme within MyAI can operate under any of four distinct archetypes:

| Theme Archetype | Visual Layer | Prompt Rules | Deterministic Engine | Example |
| :--- | :--- | :--- | :--- | :--- |
| **1. Visual-Only** | Custom palette & tokens | None (inherits General AI) | None | Future custom aesthetics (e.g. *Midnight Amber*, *Nordic Slate*) |
| **2. Prompt-Guided** | Custom palette & tokens | Injected instructions & rules | None | `mathematics`, `programming`, `study` |
| **3. Engine-Powered** | Default or subtle palette | Minimal prompt guidance | Active `ThemeImplementation` | Internal deterministic validators |
| **4. Full Specialized**| Custom palette & tokens | Specialized prompt guidance | Active `ThemeImplementation` + Specialized Cards | `safety-checkup`, `security-checkup` |

### 1.2 Separation of Responsibilities

To avoid mixing business logic with styling, responsibilities are partitioned as follows:

- **Theme Identity & Metadata**: Statically declared in code (`slug`, `name`, `description`, `icon`, `isSystem`). Represents the canonical definition of what the theme is.
- **Visual Tokens**: CSS custom properties scoped to `[data-theme="[slug]"]`, governing component colors, borders, shadows, and subtle ambient glows.
- **Tailwind v4 Token Bridge**: Registered via `@theme inline` in `globals.css` to expose native Tailwind classes (`bg-theme-accent`, `border-theme-border`, `bg-theme-subtle`).
- **Component Variants**: Subtle visual shifts in the avatar, user message bubble, composer active border, and active chat header badge.
- **Welcome Experience**: Context-aware hero titles, subtitles, and curated quick-prompt cards tailored to the active theme.
- **Prompt Configuration**: Strict system instructions, reasoning rules, method constraints, and formatting requirements injected into the Gemini context.
- **Deterministic Engine**: Server-side TypeScript implementation (`ThemeImplementation`) that runs algorithms, queries reputation feeds, or computes formulas before Gemini responds.
- **Input Analyzer**: Extracts structured entities, intents, URLs, or code tokens from raw input and conversation history without invoking the LLM.
- **Specialized Result Cards**: Interactive React components (`SafetyCheckupCard`, `SecurityDiagnosticsCard`) that render structured data returned by deterministic engines in the assistant's message.
- **Theme Registry**: Server-safe singleton mapping slugs to deterministic engines; client-safe catalog mapping slugs to visual definitions and welcome prompts.
- **Theme Resolver**: Validates that a requested `theme_id` or `slug` exists, is enabled, and is an authorized system theme, falling back cleanly to General AI if resolution fails.
- **Database Persistence**: Stores only the relationship (`conversations.theme_id`) and declarative prompt configuration. The database **never** contains executable JavaScript or styling logic.

---

## 2. Active MyAI Themes

The active user-facing themes for MyAI are strictly defined as:

1. **General AI** (`general`): The versatile, baseline AI assistant.
2. **Mathematics** (`mathematics`): Exact formulas, step-by-step mathematical proofs, and computational problem-solving.
3. **Programming** (`programming`): Software engineering, architecture, code debugging, and defensive security-first development.
4. **Safety Checkup** (`safety-checkup`): Everyday consumer protection against suspicious links, phishing, scam messages, social engineering, and fraud.
5. **Security Checkup** (`security-checkup`): Deep technical inspection of domains, protocols, HTTP headers, code vulnerabilities, and threat telemetry.
6. **Study** (`study`): Socratic tutor that guides learners using probing questions and hints without giving away direct answers.

### 2.1 Legacy / Dormant Infrastructure Policy (Tibb al-Nabi)

- The Prophetic Medicine engine located at `src/lib/theme/engines/tibb-al-nabi` is **legacy/dormant compatibility infrastructure**.
- It is **NOT** an active user-facing theme and must not appear in `ThemeSelector` or user menus.
- The engine, its 12 unit tests, and its ingestion data must **remain intact and functional in code** to prevent breaking historical test suites and knowledge-base dependencies, but it will not have an active database row in production migrations until a deliberate future phase reactivates specialized historical domain engines.

---

## 3. General AI as Canonical Baseline

### 3.1 Resolving Current Architectural Duplication

The Phase 5 audit revealed a brittle antipattern:
- The database contains a row for General AI (`id = '11111111-1111-1111-1111-111111111111'`, `slug = 'general'`).
- In the client application, `selectedThemeId === null` represents General AI.
- `ThemeSelector.tsx` executes `data.filter(t => t.slug !== 'general')` to suppress the duplicate database row from rendering twice in the dropdown.

### 3.2 Canonical Decision: Hybrid Null-Tolerant Resolution

**Decision**: General AI has a static, canonical definition (`slug = 'general'`), but in the database and API layers, `theme_id: null` is the canonical representation of General AI.

```typescript
// src/lib/theme/resolver.ts (Canonical Standard)
export const GENERAL_AI_THEME: ThemeDefinition = {
  id: '11111111-1111-1111-1111-111111111111',
  slug: 'general',
  name: 'General AI',
  description: 'Standard versatile AI assistant.',
  icon: 'Globe',
  enabled: true,
  isSystem: true,
  archetype: 'visual_prompt',
  visual: {
    themeAttribute: 'general',
    accentColor: '#2563eb',
    iconName: 'Globe',
    avatarBg: '#2563eb',
    avatarFg: '#ffffff',
    badgeText: 'General AI',
  },
  welcome: {
    heroTitle: 'Welcome to MyAI',
    heroSubtitle: 'How can I help you today?',
    heroIcon: 'Sparkles',
    suggestions: [ ... ],
  },
};

export async function resolveAuthorizedTheme(themeId: string | null | undefined): Promise<ThemeDefinition> {
  // 1. null, undefined, 'general', or canonical General AI ID immediately maps to the static baseline
  if (!themeId || themeId === 'general' || themeId === '11111111-1111-1111-1111-111111111111') {
    return GENERAL_AI_THEME;
  }
  
  // 2. Query specialized theme from DB
  const dbTheme = await getThemeById(themeId);
  if (!dbTheme || !dbTheme.enabled || !dbTheme.is_system) {
    return GENERAL_AI_THEME; // Safe fallback
  }

  // 3. Merge DB config with canonical registered metadata
  const registered = themeRegistry.getDefinition(dbTheme.slug);
  if (registered) {
    return {
      ...registered,
      id: dbTheme.id,
      instructions: (dbTheme.config as { instructions?: string })?.instructions || registered.instructions,
      rules: (dbTheme.config as { rules?: string[] })?.rules || registered.rules,
    };
  }

  return GENERAL_AI_THEME;
}
```

**Why this is the cleanest architecture**:
1. `theme_id: null` in `public.conversations` is the most storage-efficient and natural SQL representation for "no specialized theme applied".
2. It preserves backward compatibility for existing records referencing `'11111111-1111-1111-1111-111111111111'`.
3. The frontend `ThemeSelector` no longer performs ad-hoc array filtering (`t.slug !== 'general'`). Instead, `ThemeSelector` consumes the registered theme list where General AI is the hardcoded, guaranteed first option bound to `null`.

---

## 4. Safety Checkup vs. Security Checkup

Currently, `safety-checkup` and `security-checkup` point to the same engine instance (`safetySecurityImpl`) and display the exact same `SafetyAnalysisCard` labeled "Safety Checkup". Under the Master Specification, they will **diverge into two complementary themes sharing the same underlying security infrastructure**.

```
                           ┌───────────────────────────────────────────────┐
                           │         SHARED SECURITY INFRASTRUCTURE        │
                           │  • UrlAnalyzer & MessageScamAnalyzer          │
                           │  • ReputationAggregator (URLhaus, GSBN)       │
                           │  • RiskEngine & Deterministic Scoring         │
                           │  • SafetyRepository & Analysis Persistence    │
                           └───────────────────────┬───────────────────────┘
                                                   │
                       ┌───────────────────────────┴───────────────────────────┐
                       ▼                                                       ▼
        ┌─────────────────────────────┐                         ┌─────────────────────────────┐
        │       SAFETY CHECKUP        │                         │      SECURITY CHECKUP       │
        ├─────────────────────────────┤                         ├─────────────────────────────┤
        │ • Target: Everyday Users    │                         │ • Target: Tech / Sec / Dev  │
        │ • Focus: Phishing, scams,   │                         │ • Focus: Protocol anomalies,│
        │   seed extraction, fake SMS │                         │   secrets, headers, code    │
        │ • Language: Plain, high-    │                         │ • Language: Technical risk, │
        │   empathy, actionable steps │                         │   RFCs, attack mechanisms   │
        │ • UI: SafetyCheckupCard     │                         │ • UI: SecurityDiagnosticsCard│
        │ • Palette: Cobalt & Emerald │                         │ • Palette: Obsidian & Amber │
        └─────────────────────────────┘                         └─────────────────────────────┘
```

### 4.1 Safety Checkup (`safety-checkup`)
- **Audience**: Everyday consumers, non-technical users, mobile message recipients.
- **Domain Scope**:
  - Phishing links and fake login portals
  - SMS / WhatsApp scam scripts and lure messages
  - Seed phrase and private key theft attempts
  - OTP interception lures
  - Unsolicited payment requests and spoofed invoices
  - Malicious or misleading QR codes
- **Tone & Prompt Persona**: "You are a protective digital safety assistant explaining online risks in plain, accessible language without technical jargon."
- **Card Presentation**: `SafetyCheckupCard` emphasizing the overall verdict (Low/Medium/High/Critical), direct recommendations ("Do not click", "Block sender"), and human-readable finding explanations.

### 4.2 Security Checkup (`security-checkup`)
- **Audience**: Developers, cybersecurity analysts, sysadmins, technical users.
- **Domain Scope**:
  - Deep URL & domain analysis (punycode, entropy, subdomain nesting, TLD abuse)
  - HTTP vs HTTPS transport vulnerabilities
  - Exposed secrets, credentials, API keys, and sensitive tokens in query strings
  - Technical threat intelligence telemetry (threat categories, provider response latencies, cache headers)
  - Code vulnerability patterns (SQL injection signatures, shell command injections)
- **Tone & Prompt Persona**: "You are a cybersecurity expert and threat analyst providing rigorous technical risk breakdowns, protocol analysis, and defensive engineering recommendations."
- **Card Presentation**: `SecurityDiagnosticsCard` emphasizing raw evidence IDs, threat taxonomy (CWE/OWASP), provider consensus breakdowns, and cryptographic/protocol details.

### 4.3 Telemetry Metadata Passing in Stream
To allow the UI to distinguish which card presentation to render, the route handler must attach `themeSlug` to the stream's `done` event:

```typescript
// src/app/api/chat/route.ts
if (event.type === 'done' && safetyReport) {
  event.metadata = {
    model: event.metadata?.model || 'ai-model',
    provider: event.metadata?.provider || 'ai-provider',
    ...event.metadata,
    themeSlug: theme.slug, // Attached so client knows whether it's safety-checkup or security-checkup
    safetyReport,
  };
}
```

In `Message.tsx`:
```tsx
// src/components/chat/Message.tsx
{safetyReport && (
  metadata?.themeSlug === 'security-checkup' ? (
    <SecurityDiagnosticsCard report={safetyReport} />
  ) : (
    <SafetyCheckupCard report={safetyReport} />
  )
)}
```

---

## 5. Visual Design Token System

Domain themes must integrate seamlessly with **Light**, **Dark**, and **System** appearance modes managed by `next-themes`. The appearance mode (Light/Dark) and the domain theme (General/Math/Code/Safety/Security/Study) are **orthogonal dimensions**.

### 5.1 Semantic Token Definition

All domain styling is governed by these standardized semantic CSS custom properties:

```css
/* Core Semantic Token Taxonomy */
--theme-bg                     /* Subtle tinted page background */
--theme-card                   /* Surface background for message boxes and cards */
--theme-card-muted             /* Secondary surface for code blocks, quotes */
--theme-border                 /* Primary border tone */
--theme-border-strong          /* Emphasized border for focused inputs */
--theme-accent                 /* Primary theme brand accent */
--theme-accent-subtle          /* Translucent accent wash (10-15% opacity) */
--theme-accent-foreground      /* Readable text on top of theme accent */
--theme-avatar-bg              /* Assistant avatar background */
--theme-avatar-fg              /* Assistant avatar icon color */
--theme-bubble-user            /* User message bubble background */
--theme-bubble-user-text       /* User message bubble text */
--theme-composer-border        /* Composer normal border */
--theme-composer-focus         /* Composer ring color on focus */
--theme-badge-bg               /* Theme header badge pill background */
--theme-badge-text             /* Theme header badge pill text */
--theme-glow                   /* Ambient box-shadow / drop-shadow glow */
--theme-risk-low               /* Emerald low risk indicator */
--theme-risk-medium            /* Amber medium risk indicator */
--theme-risk-high              /* Rose high risk indicator */
--theme-risk-critical          /* Crimson critical risk indicator */
```

---

## 6. Theme-Scoped CSS Architecture & Tailwind v4 Bridge

Themes are applied to the chat container via the `data-theme` HTML attribute. This prevents global pollution and allows different viewports or embedded widgets to render specific themes independently.

### 6.1 Tailwind v4 `@theme inline` Integration

In `src/app/globals.css`, we bridge the custom properties to Tailwind v4 utilities:

```css
@import "tailwindcss";

@theme inline {
  --color-theme-accent: var(--theme-accent);
  --color-theme-subtle: var(--theme-accent-subtle);
  --color-theme-border: var(--theme-accent-border);
  --color-theme-avatar-bg: var(--theme-avatar-bg);
  --color-theme-avatar-fg: var(--theme-avatar-fg);
  --color-theme-badge-bg: var(--theme-badge-bg);
  --color-theme-badge-text: var(--theme-badge-text);
  --color-theme-composer-focus: var(--theme-composer-focus);
}
```

This empowers all React components to use clean, semantic Tailwind classes (`bg-theme-accent`, `text-theme-badge-text`, `border-theme-border`, `bg-theme-subtle`) instead of arbitrary inline styles or fragile bracket syntax.

### 6.2 Token Palette Mapping

```css
/* ==========================================================================
   MYAI UNIFIED DESIGN TOKENS
   ========================================================================== */

/* 1. GENERAL AI (Default Baseline) */
[data-theme="general"] {
  --theme-accent: #2563eb;               /* Blue 600 */
  --theme-accent-subtle: #eff6ff;        /* Blue 50 */
  --theme-accent-border: #bfdbfe;        /* Blue 200 */
  --theme-avatar-bg: #2563eb;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(37, 99, 235, 0.4);
  --theme-badge-bg: #eff6ff;
  --theme-badge-text: #1d4ed8;
  --theme-glow: rgba(37, 99, 235, 0.15);
}
.dark [data-theme="general"] {
  --theme-accent: #3b82f6;               /* Blue 500 */
  --theme-accent-subtle: rgba(59, 130, 246, 0.12);
  --theme-accent-border: rgba(59, 130, 246, 0.3);
  --theme-avatar-bg: #1d4ed8;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(59, 130, 246, 0.4);
  --theme-badge-bg: rgba(59, 130, 246, 0.15);
  --theme-badge-text: #93c5fd;
  --theme-glow: rgba(59, 130, 246, 0.2);
}

/* 2. MATHEMATICS (Scientific Teal & Slate) */
[data-theme="mathematics"] {
  --theme-accent: #0d9488;               /* Teal 600 */
  --theme-accent-subtle: #f0fdfa;        /* Teal 50 */
  --theme-accent-border: #99f6e4;        /* Teal 200 */
  --theme-avatar-bg: #0d9488;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(13, 148, 136, 0.4);
  --theme-badge-bg: #f0fdfa;
  --theme-badge-text: #0f766e;
  --theme-glow: rgba(13, 148, 136, 0.15);
}
.dark [data-theme="mathematics"] {
  --theme-accent: #14b8a6;               /* Teal 500 */
  --theme-accent-subtle: rgba(20, 184, 166, 0.12);
  --theme-accent-border: rgba(20, 184, 166, 0.3);
  --theme-avatar-bg: #0f766e;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(20, 184, 166, 0.4);
  --theme-badge-bg: rgba(20, 184, 166, 0.15);
  --theme-badge-text: #5eead4;
  --theme-glow: rgba(20, 184, 166, 0.2);
}

/* 3. PROGRAMMING (Emerald Terminal) */
[data-theme="programming"] {
  --theme-accent: #059669;               /* Emerald 600 */
  --theme-accent-subtle: #ecfdf5;        /* Emerald 50 */
  --theme-accent-border: #a7f3d0;        /* Emerald 200 */
  --theme-avatar-bg: #059669;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(5, 150, 105, 0.4);
  --theme-badge-bg: #ecfdf5;
  --theme-badge-text: #047857;
  --theme-glow: rgba(5, 150, 105, 0.15);
}
.dark [data-theme="programming"] {
  --theme-accent: #10b981;               /* Emerald 500 */
  --theme-accent-subtle: rgba(16, 185, 129, 0.12);
  --theme-accent-border: rgba(16, 185, 129, 0.3);
  --theme-avatar-bg: #047857;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(16, 185, 129, 0.4);
  --theme-badge-bg: rgba(16, 185, 129, 0.15);
  --theme-badge-text: #6ee7b7;
  --theme-glow: rgba(16, 185, 129, 0.2);
}

/* 4. SAFETY CHECKUP (Cyber Shield Cobalt & Emerald) */
[data-theme="safety-checkup"] {
  --theme-accent: #2563eb;               /* Cobalt 600 */
  --theme-accent-subtle: #eff6ff;
  --theme-accent-border: #bfdbfe;
  --theme-avatar-bg: #10b981;            /* Emerald Shield */
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(37, 99, 235, 0.4);
  --theme-badge-bg: #ecfdf5;
  --theme-badge-text: #065f46;
  --theme-glow: rgba(16, 185, 129, 0.15);
}
.dark [data-theme="safety-checkup"] {
  --theme-accent: #3b82f6;
  --theme-accent-subtle: rgba(59, 130, 246, 0.12);
  --theme-accent-border: rgba(59, 130, 246, 0.3);
  --theme-avatar-bg: #059669;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(59, 130, 246, 0.4);
  --theme-badge-bg: rgba(16, 185, 129, 0.15);
  --theme-badge-text: #6ee7b7;
  --theme-glow: rgba(16, 185, 129, 0.2);
}

/* 5. SECURITY CHECKUP (Technical Obsidian & Amber) */
[data-theme="security-checkup"] {
  --theme-accent: #d97706;               /* Amber 600 */
  --theme-accent-subtle: #fffbeb;
  --theme-accent-border: #fde68a;
  --theme-avatar-bg: #e11d48;            /* Rose Threat */
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(217, 119, 6, 0.4);
  --theme-badge-bg: #fff1f2;
  --theme-badge-text: #9f1239;
  --theme-glow: rgba(225, 29, 72, 0.15);
}
.dark [data-theme="security-checkup"] {
  --theme-accent: #f59e0b;               /* Amber 500 */
  --theme-accent-subtle: rgba(245, 158, 11, 0.12);
  --theme-accent-border: rgba(245, 158, 11, 0.3);
  --theme-avatar-bg: #be123c;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(245, 158, 11, 0.4);
  --theme-badge-bg: rgba(225, 29, 72, 0.15);
  --theme-badge-text: #fda4af;
  --theme-glow: rgba(225, 29, 72, 0.2);
}

/* 6. STUDY (Academic Warm Indigo & Violet) */
[data-theme="study"] {
  --theme-accent: #7c3aed;               /* Violet 600 */
  --theme-accent-subtle: #f5f3ff;
  --theme-accent-border: #ddd6fe;
  --theme-avatar-bg: #7c3aed;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(124, 58, 237, 0.4);
  --theme-badge-bg: #f5f3ff;
  --theme-badge-text: #5b21b6;
  --theme-glow: rgba(124, 58, 237, 0.15);
}
.dark [data-theme="study"] {
  --theme-accent: #8b5cf6;               /* Violet 500 */
  --theme-accent-subtle: rgba(139, 92, 246, 0.12);
  --theme-accent-border: rgba(139, 92, 246, 0.3);
  --theme-avatar-bg: #6d28d9;
  --theme-avatar-fg: #ffffff;
  --theme-composer-focus: rgba(139, 92, 246, 0.4);
  --theme-badge-bg: rgba(139, 92, 246, 0.15);
  --theme-badge-text: #c4b5fd;
  --theme-glow: rgba(139, 92, 246, 0.2);
}
```

---

## 7. Component Theming

Rather than radical component redesigns, MyAI applies a **subtle, premium, consistent design language**:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  [Sidebar]                 [Chat Header]                                       │
│  Conversation Row:         [ShieldCheck] Safety Checkup (Badge)                │
│  [ShieldCheck] Paypal Scam ─────────────────────────────────────────────────── │
│  [Code] Next.js Route      [Message List]                                      │
│                            Avatar: bg-theme-avatar-bg text-theme-avatar-fg     │
│                            Card:   border-theme-border                         │
│                            ─────────────────────────────────────────────────── │
│                            [ChatComposer]                                      │
│                            Border Focus: ring-theme-composer-focus             │
└────────────────────────────────────────────────────────────────────────────────┘
```

1. **AI Avatar (`Message.tsx`)**:
   - Replaces hardcoded `bg-blue-600` with `bg-theme-avatar-bg text-theme-avatar-fg`.
   - The icon corresponds to the theme (`Sparkles` for General AI, `Calculator` for Math, `Code` for Programming, `ShieldCheck` for Safety, `ShieldAlert` for Security, `BookOpen` for Study).
2. **Thinking Pulse (`Message.tsx`)**:
   - Pulses with `bg-theme-accent` instead of hardcoded blue.
3. **Chat Composer (`ChatComposer.tsx`)**:
   - Active textarea ring transitions smoothly to `focus-within:ring-theme-composer-focus`.
   - Send button maintains high contrast with an accent hover: `hover:bg-theme-accent`.
4. **Chat Navigation Header (`ChatClient.tsx`)**:
   - Displays a compact, accessible pill badge on desktop and mobile: `[Icon] Theme Name` styled with `bg-theme-badge-bg text-theme-badge-text`.

---

## 8. Theme-Aware Welcome Screen

The Welcome Screen dynamically reflects the active theme selected in `ThemeSelector`.

### 8.1 Welcome Screen Specifications by Theme

```typescript
export interface WelcomeSuggestion {
  title: string;
  prompt: string;
  iconName: string;
}

export interface WelcomeThemeConfig {
  heroTitle: string;
  heroSubtitle: string;
  heroIcon: string;
  suggestions: WelcomeSuggestion[];
}
```

#### 1. General AI (`general`)
- **Hero Title**: "Welcome to MyAI"
- **Hero Subtitle**: "How can I help you today?"
- **Hero Icon**: `Sparkles`
- **Suggestions**:
  1. *"Summarize this document"* (Icon: `FileText`, Prompt: "Summarize the key takeaways of this article:")
  2. *"Draft a clear email"* (Icon: `Mail`, Prompt: "Draft a polite follow-up email regarding:")
  3. *"Brainstorm fresh ideas"* (Icon: `Lightbulb`, Prompt: "Brainstorm 5 innovative ideas for:")
  4. *"Explain a complex topic"* (Icon: `BookOpen`, Prompt: "Explain this concept simply:")

#### 2. Mathematics (`mathematics`)
- **Hero Title**: "Mathematics Assistant"
- **Hero Subtitle**: "Exact derivations, step-by-step proofs, and algebraic problem-solving."
- **Hero Icon**: `Calculator`
- **Suggestions**:
  1. *"Step-by-step calculus derivation"* (Icon: `Divide`, Prompt: "Find the derivative of f(x) = x^3 * e^(2x) and explain each step:")
  2. *"Linear algebra transformation"* (Icon: `Grid`, Prompt: "Calculate the eigenvalues and eigenvectors of this 2x2 matrix:")
  3. *"Probability distribution proof"* (Icon: `Percent`, Prompt: "Prove Bayes' theorem from the definition of conditional probability:")
  4. *"Discrete math logic"* (Icon: `Binary`, Prompt: "Construct a truth table for the following compound proposition:")

#### 3. Programming (`programming`)
- **Hero Title**: "Software Engineering Copilot"
- **Hero Subtitle**: "Architecture, clean code, debugging, and security-first development."
- **Hero Icon**: `Code`
- **Suggestions**:
  1. *"Debug a TypeScript error"* (Icon: `Bug`, Prompt: "Help me diagnose this TypeScript type inference error:")
  2. *"Design a REST/tRPC API"* (Icon: `Layers`, Prompt: "Design an idiomatic RESTful API contract for an authentication flow:")
  3. *"Optimize React re-renders"* (Icon: `Zap`, Prompt: "Review this React component for excessive re-renders:")
  4. *"SQL query optimization"* (Icon: `Database`, Prompt: "Analyze this PostgreSQL query and suggest indexing strategies:")

#### 4. Safety Checkup (`safety-checkup`)
- **Hero Title**: "Digital Safety Checkup"
- **Hero Subtitle**: "Analyze suspicious links, messages, emails, and scam requests."
- **Hero Icon**: `ShieldCheck`
- **Suggestions**:
  1. *"Check a suspicious URL"* (Icon: `Link`, Prompt: "Is this URL safe or a phishing attempt? ")
  2. *"Verify an unexpected text message"* (Icon: `MessageSquareWarning`, Prompt: "I received this text asking for urgent action. Is it a scam? ")
  3. *"Recovery phrase security inquiry"* (Icon: `Key`, Prompt: "Someone claiming to be customer support asked for my wallet seed phrase. Should I share it?")
  4. *"Analyze an invoice link"* (Icon: `FileWarning`, Prompt: "Check this payment notification link for deceptive signals: ")

#### 5. Security Checkup (`security-checkup`)
- **Hero Title**: "Technical Security Inspection"
- **Hero Subtitle**: "Audit web endpoints, security headers, token leaks, and vulnerabilities."
- **Hero Icon**: `ShieldAlert`
- **Suggestions**:
  1. *"Inspect URL structure and punycode"* (Icon: `Terminal`, Prompt: "Perform a technical security breakdown on this suspicious domain: ")
  2. *"Audit code for injection flaws"* (Icon: `FileCode`, Prompt: "Inspect this server code for SQL injection or command injection risks: ")
  3. *"Review HTTP security headers"* (Icon: `ShieldCheck`, Prompt: "Audit the recommended CSP and HSTS headers for this web service: ")
  4. *"Exposed credential audit"* (Icon: `AlertTriangle`, Prompt: "Check if this API URL inadvertently exposes sensitive credentials in query parameters:")

#### 6. Study (`study`)
- **Hero Title**: "Socratic Learning Tutor"
- **Hero Subtitle**: "Deepen your understanding through guided questions, hints, and practice."
- **Hero Icon**: `BookOpen`
- **Suggestions**:
  1. *"Guide me through quantum mechanics"* (Icon: `Atom`, Prompt: "Guide me to understand wave-particle duality through questions:")
  2. *"Practice system design fundamentals"* (Icon: `Compass`, Prompt: "Help me practice designing a distributed rate limiter via Socratic dialogue:")
  3. *"World history analysis"* (Icon: `Globe`, Prompt: "Ask me questions to help me analyze the economic causes of the Industrial Revolution:")
  4. *"Language grammar breakdown"* (Icon: `FileText`, Prompt: "Test my understanding of Spanish subjunctive verb conjugations with exercises:")

---

## 9. Active Conversation Theme Persistence (Server-to-Client Prop Flow)

Currently, once a conversation is initiated and navigated to `/chat/[id]`, the theme disappears completely from the UI because `ChatClient` only receives `conversation` without joined theme metadata.

### 9.1 Server Component Hydration Architecture

In Next.js App Router, `src/app/chat/[id]/page.tsx` is an async Server Component. Rather than creating client-side waterfalls, the theme is resolved cleanly on the server and passed directly as a typed prop:

```tsx
// src/app/chat/[id]/page.tsx (Server Component)
import { notFound } from 'next/navigation';
import { getConversation, getMessages } from '@/lib/database';
import { resolveAuthorizedTheme } from '@/lib/theme/resolver';
import { ChatClient } from './ChatClient';

export const dynamic = 'force-dynamic';

export default async function ChatIdPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const conversation = await getConversation(id);
  if (!conversation) notFound();

  const messages = await getMessages(id);
  const theme = await resolveAuthorizedTheme(conversation.theme_id);

  return (
    <ChatClient 
      key={conversation.id} 
      conversation={conversation} 
      initialMessages={messages} 
      theme={theme} 
    />
  );
}
```

In `ChatClient.tsx`:
```tsx
// src/app/chat/[id]/ChatClient.tsx
export function ChatClient({ conversation, initialMessages, theme }: ChatClientProps) {
  return (
    <div data-theme={theme.slug} className="flex h-full w-full flex-col relative">
      {/* Chat Navigation Header displaying Theme Pill Badge */}
      <header className="h-12 border-b border-gray-200 dark:border-gray-800 px-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-theme-badge-bg text-theme-accent">
            {ICONS[theme.icon] || <Globe size={14} />}
          </span>
          <span className="text-xs font-semibold tracking-wide text-theme-badge-text">
            {theme.name}
          </span>
        </div>
      </header>
      ...
    </div>
  );
}
```

- **Zero Client-Side Waterfall**: Theme metadata is available immediately during initial HTML render.
- **Zero Hydration Mismatch**: `data-theme` attribute is rendered server-side.
- **Desktop & Mobile Consistency**: The header displays a compact pill badge on all viewports.

---

## 10. Sidebar Integration

The conversation history in `Sidebar.tsx` will display a compact, non-intrusive theme indicator:

1. **Client-Side Theme Icon Mapping**:
   `public.conversations` already stores `theme_id`. To avoid N+1 database queries, `Sidebar.tsx` maps `theme_id` using a static client-side registry or cached theme list:
   ```typescript
   const THEME_ICON_MAP: Record<string, LucideIcon> = {
     '22222222-2222-2222-2222-222222222222': Calculator,
     '33333333-3333-3333-3333-333333333333': Code,
     '44444444-4444-4444-4444-444444444444': BookOpen,
     '55555555-5555-5555-5555-555555555555': ShieldCheck,
     '66666666-6666-6666-6666-666666666666': ShieldAlert,
   };
   ```
2. **General AI**: Displays standard clean message icon (`MessageSquare`).
3. **Specialized Themes**: Displays the corresponding theme icon in the row with subtle theme-accent tinting, immediately revealing the context of past conversations.
4. **No Layout Bloat**: The icon replaces the generic message icon in the row rather than adding extra badges, preserving clean alignment.

---

## 11. Theme Selection Lifecycle & Error Handling

```
User visits /chat
      │
      ▼
ThemeSelector (default: General AI)
      │
      ▼
User selects Theme ──(selectedThemeId)──► createConversation(title, theme_id)
                                                    │
                                                    ▼
                                          DB: conversations table
                                                    │
                                                    ▼
                                          Router.push(/chat/[id])
                                                    │
                                                    ▼
                                          Server Component resolves theme
                                          Passes theme prop to ChatClient
                                                    │
                                                    ▼
                                          POST /api/chat { conversationId }
                                                    │
                                                    ▼
                                          resolver.ts: resolveAuthorizedTheme(theme_id)
```

### 11.1 Matrix of Edge Cases & Fallbacks

| Scenario | System Behavior | Visual Feedback | User Impact |
| :--- | :--- | :--- | :--- |
| **Normal Selection** | Theme resolved, instructions and engine attached. | `data-theme` set, active badge rendered. | Full themed experience. |
| **`theme_id = null`** | Resolves to `GENERAL_AI_THEME`. | `data-theme="general"`. | Seamless default experience. |
| **Invalid UUID / Not Found** | Resolves safely to `GENERAL_AI_THEME`. | Falls back to `data-theme="general"`. | Conversation succeeds without error; runs General AI. |
| **Disabled Theme (`enabled=false`)**| Resolves safely to `GENERAL_AI_THEME`. | Falls back to `data-theme="general"`. | Protects against deprecated or disabled features. |
| **Non-System Theme (`is_system=false`)**| Resolves safely to `GENERAL_AI_THEME`. | Falls back to `data-theme="general"`. | Prevents unauthorized tenant/user injection. |
| **Database Connection Failure** | Logs structured warning, returns `GENERAL_AI_THEME`. | Falls back to `data-theme="general"`. | Chat continues generating; zero downtime for user. |

---

## 12. Mid-Conversation Theme Switching Policy

### Evaluation of Options

- **Option A: Immutable Theme (Fixed for Conversation Lifetime)**:
  Once created, a conversation maintains its theme. The user cannot change the theme mid-thread.
- **Option B: Dynamic In-Place Switching**:
  User can change the theme dropdown at any time within an active `/chat/[id]`.
- **Option C: Branching on Theme Switch**:
  Changing theme forks the conversation into a new thread.

### Architectural Decision: **Option A (Immutable Lifetime)**

**Rationale**:
1. **Context Pollution**: In MyAI, `prepareContext(messages)` transmits previous turns to Gemini. If a user analyzes a phishing link in `Safety Checkup` and then switches to `Mathematics`, the conversation history contains safety telemetry and warning prompts. This contaminates the mathematical system prompt and causes unpredictable model hallucinations.
2. **Telemetry & Auditability**: Messages stored in Supabase with `metadata.safetyReport` belong to a deterministic security analysis session. Mutating the theme breaks the analytical audit trail.
3. **Clean UX**: If a user wishes to switch tasks, clicking "New Chat" and selecting another theme is intuitive, safe, and guarantees an uncontaminated context window.
4. **Future Path**: In a post-v1 phase, Option C (branching/forking thread into a new theme) can be added cleanly as an explicit user action without compromising the integrity of Option A.

---

## 13. Safety & Security Card Presentation Architecture

Both `safety-checkup` and `security-checkup` consume the identical, verified `SafetyReport` data structure produced by `SafetyService.analyze()`. They diverge in their presentation layer.

```
                            SafetyReport (Domain Model)
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
           SafetyCheckupCard                      SecurityDiagnosticsCard
        (Focus: Consumer Action)                 (Focus: Technical Telemetry)
    ┌───────────────────────────────┐       ┌───────────────────────────────┐
    │ • Prominent Risk Pill         │       │ • Protocol & Transport Details│
    │ • Plain Language Explanation  │       │ • Specific Risk Weight Table  │
    │ • Direct Action Recommendations│      │ • Telemetry Consensus Breakdown│
    │ • Collapsible Tech Evidence   │       │ • Raw Indicators & RFC Notes  │
    └───────────────────────────────┘       └───────────────────────────────┘
```

### 13.1 Strict Safety Communication Guardrails
Regardless of whether the card is rendering in Safety or Security mode:
- **Zero Absolute Safety Claims**: Never output "100% safe", "guaranteed safe", "confirmed safe", or "verified benign".
- **Telemetry Fidelity**: Unlisted domains must be labeled *"No threat match found in queried lists"*, never *"Certified safe by vendors"*.
- **Clear Confidence Cues**: Distinguish deterministic rule findings (high confidence) from single-vendor absence of records (medium/low confidence).

---

## 14. Theme Registry Design

The future registry decouples visual cataloging from server-side deterministic logic:

```typescript
// src/lib/theme/types.ts

export type ThemeArchetype = 'visual_only' | 'visual_prompt' | 'deterministic_engine';

export interface ThemeVisualConfig {
  themeAttribute: string;               // e.g. 'safety-checkup'
  accentColor: string;                  // Primary accent hex
  iconName: string;                     // Lucide icon name
  avatarBg: string;                     // CSS variable or hex
  avatarFg: string;                     // CSS variable or hex
  badgeText: string;                    // Short badge title
}

export interface ThemeDefinition {
  id: string;
  slug: string;
  name: string;
  description: string;
  icon: string;
  enabled: boolean;
  isSystem: boolean;
  archetype: ThemeArchetype;
  visual: ThemeVisualConfig;
  welcome: WelcomeThemeConfig;
  instructions?: string;
  rules?: string[];
}
```

```typescript
// src/lib/theme/registry.ts

class ThemeRegistry {
  private definitions = new Map<string, ThemeDefinition>();
  private engines = new Map<string, ThemeImplementation>();

  // Register visual & prompt definition (safe for client and server)
  registerDefinition(definition: ThemeDefinition): void {
    this.definitions.set(definition.slug, definition);
  }

  // Register deterministic engine (server-only)
  registerEngine(slug: string, impl: ThemeImplementation): void {
    this.engines.set(slug, impl);
  }

  getDefinition(slug: string): ThemeDefinition | undefined {
    return this.definitions.get(slug);
  }

  getEngine(slug: string): ThemeImplementation | undefined {
    return this.engines.get(slug);
  }

  getAllActiveDefinitions(): ThemeDefinition[] {
    return Array.from(this.definitions.values()).filter(d => d.enabled && d.isSystem);
  }
}

export const themeRegistry = new ThemeRegistry();
```

---

## 15. Database Model & Schema Invariants

### 15.1 Storage Allocation Matrix

| Data Item | Storage Location | Rationale |
| :--- | :--- | :--- |
| `conversations.theme_id` | **PostgreSQL (UUID)** | Links the session to its theme. Auditable and RLS-protected. |
| `themes` metadata (name, slug, desc, icon) | **PostgreSQL** | Dynamic tenant management and administrative toggling. |
| Theme Prompt Instructions & Rules | **PostgreSQL (`config JSONB`)** | Configurable without code deployment. |
| Theme Visual Design Tokens | **CSS (`globals.css`)** | Instant rendering, zero layout shift, zero database latency. |
| Theme Deterministic Engines | **TypeScript Server Files** | Security invariant: eliminates remote code execution (RCE). |
| Welcome Prompts & Suggestions | **Static Code Registry** | Client-side bundle efficiency and immediate render. |

### 15.2 Schema Refinements
The current `themes` table schema is sound and requires **no breaking migrations**. In Phase 5:
- All 6 active themes will have verified system rows.
- General AI row (`1111...`) will be retained in DB for foreign key backwards compatibility, while resolver canonically normalizes `null` to `general`.
- `config JSONB` remains strictly declarative (`instructions`, `rules`, `methods`).

---

## 16. Accessibility & WCAG Compliance

### 16.1 `ThemeSelector` Accessibility Specifications
- **ARIA 1.2 Combobox / Listbox Pattern**:
  - Trigger `<button>`: `type="button"`, `role="combobox"`, `aria-haspopup="listbox"`, `aria-expanded={isOpen}`, `aria-controls="theme-listbox"`, `aria-activedescendant={activeOptionId}`, `aria-label="Select AI Theme"`.
  - Dropdown container: `role="listbox"`, `id="theme-listbox"`, `aria-label="Available AI Themes"`.
  - Option items: `role="option"`, `id={`theme-opt-${theme.slug}`}`, `aria-selected={selectedThemeId === theme.id}`.
- **Keyboard Navigation State Machine**:
  - `ArrowDown` / `ArrowUp`: Cycles active descendant through theme options with visual focus ring without closing.
  - `Home` / `End`: Jumps to first / last theme option.
  - `Enter` / `Space`: Selects the active option, closes dropdown, and updates selection state.
  - `Escape`: Closes the dropdown and returns keyboard focus to the trigger button.
  - `Tab`: Closes the dropdown and naturally moves focus to the composer textarea.
- **Focus Indicators**: 2px solid `var(--theme-accent)` with 2px offset on all interactive states.
- **Touch Targets**: Minimum 44px x 44px hit target for all buttons and options on mobile.
- **Non-Color Risk Cues**: Indicators must combine color with distinct icons (`ShieldAlert`, `AlertTriangle`, `CheckCircle`) and text labels.

---

## 17. Responsive & Mobile Design

The theme architecture is engineered for fluid responsiveness across all target viewports:

| Viewport Width | Device Type | ThemeSelector Behavior | Header Theme Badge | Welcome Suggestions |
| :--- | :--- | :--- | :--- | :--- |
| **320px – 360px** | Ultra-compact (SE, Mini) | Full-width bottom drawer with overlay | Icon-only pill (`[Icon]`) | 1-column compact cards |
| **375px – 430px** | Standard Mobile (iPhone, Galaxy) | Popover or bottom sheet (max-w-[calc(100vw-32px)]) | Icon + Compact Name | 1-column rich cards |
| **768px – 1024px** | Tablets / Foldables | Popover anchored to button | Icon + Full Name + Description | 2-column grid |
| **1200px+** | Desktop Displays | Popover anchored to button | Icon + Full Name + Status Pill | 2-column grid |

---

## 18. Future Extensibility

Adding a future theme (e.g., *Arabic Language*, *Finance Engine*, or *Fiqh Advisor*) requires only three localized steps:

```
Step 1: CSS Tokens            Step 2: Theme Definition       Step 3: Engine (Optional)
[data-theme="finance"]        themeRegistry.register({       themeRegistry.registerEngine(
  --theme-accent: #0284c7;      slug: 'finance',               'finance', financeImpl
  ...                           welcome: { ... }             );
                                });
```

No existing components, routes, or chat interfaces require refactoring.

---

## 19. Test Architecture

The future theme architecture mandates testing across 8 distinct verification layers:

1. **Registry Unit Tests**: Validate registration, deduplication, and fallback behavior.
2. **Resolver Tests**: Validate UUID resolution, `null` General AI handling, invalid ID fallback, and RLS safety.
3. **Engine Isolation Tests**: Confirm deterministic engines do not call external LLMs or contaminate each other.
4. **CSS Token Tests**: Verify all CSS variables exist and provide proper contrast in both Light and Dark modes.
5. **Component Tests (`ThemeSelector`)**: Verify click-outside, ARIA roles, `aria-expanded`, `aria-activedescendant`, and selection events.
6. **Keyboard Navigation Tests**: Test `ArrowDown`, `ArrowUp`, `Enter`, `Escape` navigation sequences.
7. **Welcome Screen Integration Tests**: Verify suggestions dynamically shift when the theme is selected.
8. **End-to-End Persistence Tests**: Verify that starting a conversation in `/chat` with a theme preserves the theme in `/chat/[id]` and attaches the correct telemetry.

---

## 20. Migration Strategy

The migration from the current codebase to the Master Specification will occur incrementally across safe, independent phases. **No existing features, database tables, or test suites will be broken at any stage.**

---

## 21. Phased Implementation Plan

```
Phase 5.1 ──► Phase 5.2 ──► Phase 5.3 ──► Phase 5.4 ──► Phase 5.5 ──► Phase 5.6 ──► Phase 5.7 ──► Phase 5.8
Registry      Design        Welcome       Active Chat   Sidebar       Safety/Sec    Mobile &       E2E Test
Foundation    Tokens (CSS)  Adaptation    Awareness     Badges        Divergence    A11y Pass      Validation
```

### Phase 5.1: Registry Foundation & General AI Harmonization
- **Goal**: Unify `ThemeDefinition` catalog in `src/lib/theme/` and formalize `theme_id: null` resolution for General AI.
- **Affected Files**: `src/lib/theme/types.ts`, `src/lib/theme/registry.ts`, `src/lib/theme/resolver.ts`.
- **Validation**: 100% passing Vitest tests for resolver and registry.

### Phase 5.2: CSS Token System & Tailwind v4 `@theme inline` Bridge
- **Goal**: Implement semantic CSS variables in `globals.css` scoped to `data-theme`, register Tailwind v4 `@theme inline` aliases, and bind `ChatClient` container to `data-theme`.
- **Affected Files**: `src/app/globals.css`, `src/app/chat/[id]/ChatClient.tsx`, `src/app/chat/page.tsx`.
- **Validation**: Zero layout shift, full light/dark mode compatibility.

### Phase 5.3: Contextual Welcome Screen
- **Goal**: Connect `ThemeSelector` to `WelcomeScreen` on `/chat` so suggestions adapt dynamically to the selected theme.
- **Affected Files**: `src/components/chat/WelcomeScreen.tsx`, `src/app/chat/page.tsx`.
- **Validation**: Verifying that selecting "Safety Checkup" displays URL/scam suggestions instead of generic coding prompts.

### Phase 5.4: Active Conversation Theme Visibility (Server Component Hydration)
- **Goal**: Resolve theme in `src/app/chat/[id]/page.tsx` and pass `theme` prop to `ChatClient`; render header theme badge.
- **Affected Files**: `src/app/chat/[id]/page.tsx`, `src/app/chat/[id]/ChatClient.tsx`.
- **Validation**: Desktop and mobile header verification with zero client-side waterfall.

### Phase 5.5: Sidebar Theme Indicators
- **Goal**: Add compact theme icons to conversation rows in `Sidebar.tsx`.
- **Affected Files**: `src/components/layout/Sidebar.tsx`.
- **Validation**: Clean alignment without horizontal overflow.

### Phase 5.6: Safety vs. Security Specialization & Stream Metadata
- **Goal**: Pass `themeSlug` in stream `done` event metadata; specialize prompts and split card rendering between `SafetyCheckupCard` and `SecurityDiagnosticsCard`.
- **Affected Files**: `src/app/api/chat/route.ts`, `src/lib/theme/engines/safety-security/`, `src/components/chat/Message.tsx`, `src/components/safety/SafetyAnalysisCard.tsx`.
- **Validation**: Ensuring neither theme claims 100% safety and both render distinct, specialized card presentations.

### Phase 5.7: Mobile & Accessibility Hardening
- **Goal**: Add full ARIA 1.2 combobox attributes, keyboard navigation (arrow keys, Esc), and touch target optimizations to `ThemeSelector`.
- **Affected Files**: `src/components/chat/ThemeSelector.tsx`.
- **Validation**: Screen reader testing and keyboard navigation test pass.

### Phase 5.8: End-to-End Validation & Quality Gates
- **Goal**: Run the full project test suite, TypeScript typecheck, ESLint, and Next.js production build.
- **Validation**: All quality gates passing with 0 errors.

---

## 22. Non-Negotiable Invariants

1. **Deterministic Precedence**: Deterministic analysis always executes before Gemini explanation. The LLM cannot override, suppress, or modify deterministic risk findings.
2. **Absolute Safety Prohibition**: No theme, card, prompt, or engine may ever state that a URL, file, or message is "100% safe", "guaranteed safe", or "verified benign".
3. **RLS & Authorization Integrity**: Theme selection must never bypass Supabase Row Level Security. Users can only access enabled system themes or their own authorized data.
4. **No Code in Database**: Database columns must strictly store declarative JSON configuration. No executable code, `eval`, or script strings may be persisted in PostgreSQL.
5. **Orthogonal Appearance Modes**: Visual domain themes must remain completely decoupled from `next-themes` Light/Dark/System appearance modes.
6. **Safe Fallback**: Any unknown, invalid, disabled, or failing theme must automatically and safely degrade to General AI without crashing the chat session.
7. **Zero Engine-Styling Coupling**: Visual styling changes must never alter backend security analysis semantics, and backend engine updates must never require CSS redesigns.
8. **Dormant Code Quarantine**: Legacy infrastructure (Tibb al-Nabi) must remain functional in unit tests but strictly dormant and unexposed to user interfaces.
9. **Mobile First Usability**: All theme indicators, selectors, cards, and composer elements must be fully operational on 320px–430px viewports without horizontal clipping.

---

## 23. Decisions & Open Questions

### A. Decisions Made in this Specification
1. **General AI Identity**: General AI is canonically represented as `theme_id: null` in the database, with static catalog fallback for `'general'` and `'1111...'`.
2. **Theme Switching Policy**: Themes are immutable for the lifetime of a conversation. Users start a new chat to switch themes.
3. **Safety vs. Security Divergence**: Retain shared backend security infrastructure (`SafetyService`, `RiskEngine`, `ReputationAggregator`) while diverging UI cards, prompt personas, and stream metadata passing.
4. **Visual Token Scoping**: CSS variables scoped via `[data-theme="[slug]"]` on container elements, bridging to Tailwind v4 via `@theme inline`.
5. **Server Component Hydration**: Active theme is resolved in `page.tsx` on the server and passed as a typed prop to `ChatClient`, eliminating client-side fetch waterfalls.

### B. Decisions That Can Wait for Later Phases
1. **Custom User Themes**: Allowing users to create custom theme prompts or custom color schemes in settings (deferred to post-v1).
2. **Tibb al-Nabi Reactivation**: When and how to connect the Hadith medicine engine to a remote vector database (deferred until Arabic/Hadith RAG phase).
3. **Mid-Conversation Branching**: Allowing a user to fork a conversation into another theme at a specific message turn.

### C. Risks Requiring Ongoing Monitoring
1. **Context Window Token Overhead**: Ensuring that specialized prompts for Math or Security do not consume excessive prompt tokens before conversation history is evaluated.
2. **Mobile Keyboard Viewport Resizing**: Ensuring `ThemeSelector` drawer does not clash with the mobile OS virtual keyboard on iOS Safari and Android Chrome.

---
*End of MyAI Theme Master Specification.*
