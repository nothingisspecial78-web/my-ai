# Generic Deterministic Theme Engine

## General AI vs Specialized AI
MyAI primarily operates as a **General AI** where user inputs are directly passed to a generic Large Language Model (Gemini). A **Specialized AI Theme** (such as Mathematics, Programming, or the future `طب النبي` engine) allows the application to intercept specific conversations, execute rigorous deterministic logic on the server, and inject the results into the prompt. This prevents hallucinations by making Gemini the *explainer* rather than the *calculator*.

## Core Concepts

### Theme vs ThemeEngine
* **Theme:** The database record that represents a specific domain. It holds simple, declarative configuration (e.g., instructions, rules) in JSON.
* **ThemeEngine:** The actual TypeScript executable logic on the server that performs work for that Theme. 
* *Crucial Distinction:* The database MUST NOT contain executable code. The `ThemeEngine` is hardcoded on the server and manually registered to a Theme's slug.

### ThemeAnalyzer
The analyzer is responsible for parsing raw user input and conversation history into a structured context.
```typescript
interface ThemeAnalyzer {
  analyze(input: string, history: Message[]): Promise<Partial<ThemeContext>>;
}
```

### ThemeContext
A structured representation of the conversation state. Rather than raw text, the engine receives specific entities, facts, and intents.
```typescript
interface ThemeContext {
  themeId: string;
  themeSlug: string;
  rawInput: string;
  history: Message[];
  facts: Record<string, unknown>;
  entities: string[];
  conditions: string[];
  intent: string | null;
  metadata: Record<string, unknown>;
}
```

### ThemeResult
The structured output from the `ThemeEngine`. The `explanationContext` property is what actually gets passed to Gemini.
```typescript
interface ThemeResult {
  success: boolean;
  result: unknown;
  warnings: string[];
  errors: string[];
  explanationContext: string;
  metadata: Record<string, unknown>;
}
```

### ThemeEngineRegistry
A secure server-side map that links a Theme `slug` (e.g., `tibb-al-nabi`) to its TypeScript `ThemeImplementation`. This registry guarantees that only explicitly authorized, statically analyzed server code is ever executed.

### ThemeProcessor
The orchestrator. It intercepts the chat request, validates the theme, looks up the registry, runs the analyzer and engine, and formats the result.

## Authorization Flow
1. **Conversation Ownership:** `route.ts` verifies the user owns the conversation via existing Supabase RLS.
2. **Theme Validation:** `resolver.ts` checks that the requested theme is strictly `enabled = true` AND `is_system = true`.
3. **Registry Lookup:** The processor looks for a registered engine using the Theme's slug.
4. **Execution:** The engine is executed. If any of the above steps fail (or the theme has no deterministic engine), it safely falls back to standard LLM generation.

## Deterministic Logic vs Gemini
The architecture forces a strict separation:
1. Deterministic Engine → Calculates, retrieves facts, runs algorithms.
2. Gemini → Takes the structured explanation context and translates it into a natural, empathetic, conversational response.
*The Deterministic Engine does NOT call Gemini.*

## Why Executable Logic is Server-Registered
Storing executable logic (like `eval` or JS strings) in a database JSON column creates massive security vulnerabilities (RCE). By requiring a static registry map in `src/lib/theme/registry.ts`, the database can only toggle *which* pre-approved engine runs, not *how* it runs.

## How Future Themes Plug In

### Future طب النبي Support
When `طب النبي` is implemented, we will create `src/lib/theme/engines/tibb-al-nabi.ts`. It will implement `ThemeAnalyzer` (to extract symptoms or concepts from the prompt) and `ThemeEngine` (to query an external verified Hadith/Medicine database). It will then register itself:
```typescript
themeRegistry.registerEngine('tibb-al-nabi', TibbAlNabiImpl);
```

### Future Mathematics/Programming Support
Similarly, a Mathematics engine would extract equations, run them through a safe math evaluator (like `mathjs`), and return the exact output in `explanationContext`.
