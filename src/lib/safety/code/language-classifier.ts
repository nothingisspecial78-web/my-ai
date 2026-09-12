/**
 * Deterministic Programming Language Classifier (Phase 6.3)
 * 
 * Identifies code language based on file extension, shebangs, markdown fences,
 * and language-specific syntactic tokens without running external processes.
 */

import { ProgrammingLanguage } from './types';

export interface LanguageDetectionResult {
  language: ProgrammingLanguage;
  confidence: 'high' | 'medium' | 'low';
}

export class LanguageClassifier {
  private static EXTENSION_MAP: Record<string, ProgrammingLanguage> = {
    js: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    jsx: 'javascript',
    ts: 'typescript',
    tsx: 'typescript',
    mts: 'typescript',
    cts: 'typescript',
    py: 'python',
    pyw: 'python',
    sh: 'shell',
    bash: 'shell',
    zsh: 'shell',
    sql: 'sql',
    php: 'php',
    phtml: 'php',
    go: 'go',
    json: 'json',
    yaml: 'yaml',
    yml: 'yaml',
  };

  /**
   * Classifies the programming language of a code snippet or file.
   */
  static classify(content: string, filename?: string): LanguageDetectionResult {
    const trimmed = content.trim();

    // 1. Filename extension inspection (High confidence)
    if (filename) {
      const extMatch = filename.toLowerCase().match(/\.([a-z0-9]+)$/);
      if (extMatch && this.EXTENSION_MAP[extMatch[1]]) {
        return {
          language: this.EXTENSION_MAP[extMatch[1]],
          confidence: 'high',
        };
      }
    }

    // 2. Markdown fenced code block tag inspection
    const fenceMatch = trimmed.match(/^```([a-zA-Z0-9_-]+)/m);
    if (fenceMatch) {
      const tag = fenceMatch[1].toLowerCase();
      if (tag === 'js' || tag === 'javascript' || tag === 'jsx') return { language: 'javascript', confidence: 'high' };
      if (tag === 'ts' || tag === 'typescript' || tag === 'tsx') return { language: 'typescript', confidence: 'high' };
      if (tag === 'py' || tag === 'python') return { language: 'python', confidence: 'high' };
      if (tag === 'sh' || tag === 'bash' || tag === 'shell' || tag === 'zsh') return { language: 'shell', confidence: 'high' };
      if (tag === 'sql') return { language: 'sql', confidence: 'high' };
      if (tag === 'php') return { language: 'php', confidence: 'high' };
      if (tag === 'go' || tag === 'golang') return { language: 'go', confidence: 'high' };
      if (tag === 'json') return { language: 'json', confidence: 'high' };
      if (tag === 'yaml' || tag === 'yml') return { language: 'yaml', confidence: 'high' };
    }

    // 3. Shebang inspection (High confidence)
    const firstLine = trimmed.split('\n')[0] || '';
    if (firstLine.startsWith('#!')) {
      const shebang = firstLine.toLowerCase();
      if (shebang.includes('python')) return { language: 'python', confidence: 'high' };
      if (shebang.includes('bash') || shebang.includes('sh') || shebang.includes('zsh')) return { language: 'shell', confidence: 'high' };
      if (shebang.includes('node')) return { language: 'javascript', confidence: 'high' };
      if (shebang.includes('php')) return { language: 'php', confidence: 'high' };
    }

    // 4. Strong syntactic markers
    if (/<\?php/i.test(trimmed)) {
      return { language: 'php', confidence: 'high' };
    }

    if (/\bpackage\s+main\b/.test(trimmed) || (/\bpackage\s+[a-z0-9_]+\b/.test(trimmed) && /\bfunc\s+[a-zA-Z0-9_]+\s*\(/.test(trimmed))) {
      return { language: 'go', confidence: 'high' };
    }

    // JSON check: begins with { or [ and valid syntax
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        JSON.parse(trimmed);
        return { language: 'json', confidence: 'high' };
      } catch {
        // Not valid JSON, continue
      }
    }

    // 5. Multi-factor syntactic scoring
    const scores: Record<ProgrammingLanguage, number> = {
      javascript: 0,
      typescript: 0,
      python: 0,
      shell: 0,
      sql: 0,
      php: 0,
      go: 0,
      json: 0,
      yaml: 0,
      unknown: 0,
    };

    // Python indicators
    if (/\bdef\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*:/.test(trimmed)) scores.python += 5;
    if (/\bimport\s+[a-zA-Z0-9_]+(\s+as\s+[a-zA-Z0-9_]+)?/.test(trimmed) && !/from\s+['"]/.test(trimmed)) scores.python += 3;
    if (/\bfrom\s+[a-zA-Z0-9_.]+\s+import\b/.test(trimmed)) scores.python += 4;
    if (/\belif\b\s+.*:/.test(trimmed)) scores.python += 4;
    if (/:\s*$/m.test(trimmed) && /\b(if|else|for|while|try|except|with|class)\b/.test(trimmed)) scores.python += 3;
    if (/\bprint\s*\(/.test(trimmed) && !trimmed.includes(';')) scores.python += 2;

    // TypeScript specific indicators
    if (/\binterface\s+[A-Z][a-zA-Z0-9_]*\s*\{/.test(trimmed)) scores.typescript += 6;
    if (/\btype\s+[A-Z][a-zA-Z0-9_]*\s*=/.test(trimmed)) scores.typescript += 5;
    if (/:\s*(string|number|boolean|any|void|unknown|never)\b/.test(trimmed)) scores.typescript += 4;

    // JavaScript / TypeScript indicators
    if (/\bconst\s+[a-zA-Z0-9_$]+\s*=/.test(trimmed)) { scores.javascript += 3; scores.typescript += 3; }
    if (/\blet\s+[a-zA-Z0-9_$]+\s*=/.test(trimmed)) { scores.javascript += 3; scores.typescript += 3; }
    if (/\bfunction\s+[a-zA-Z0-9_$]*\s*\(/.test(trimmed)) { scores.javascript += 3; scores.typescript += 3; }
    if (/\bconsole\.(log|error|warn|info)\s*\(/.test(trimmed)) { scores.javascript += 4; scores.typescript += 4; }
    if (/\bimport\s+.*from\s+['"][^'"]+['"]/.test(trimmed)) { scores.javascript += 4; scores.typescript += 4; }
    if (/\bexport\s+(default\s+)?(function|const|let|class)\b/.test(trimmed)) { scores.javascript += 4; scores.typescript += 4; }
    if (/=>\s*[{(\w]/.test(trimmed)) { scores.javascript += 3; scores.typescript += 3; }

    // Shell indicators
    if (/\b(echo|chmod|chown|sudo|mkdir|grep|cat|curl|wget)\s+/.test(trimmed)) scores.shell += 3;
    if (/\bexport\s+[A-Z_][A-Z0-9_]*=/.test(trimmed)) scores.shell += 4;
    if (/\bif\s+\[\s+.*\];\s*then\b/.test(trimmed)) scores.shell += 6;
    if (/\bfi\b/.test(trimmed)) scores.shell += 4;
    if (/\bdone\b/.test(trimmed) && /\b(for|while)\b/.test(trimmed)) scores.shell += 4;

    // SQL indicators
    if (/\bSELECT\b[\s\S]+\bFROM\b/i.test(trimmed)) scores.sql += 6;
    if (/\bINSERT\s+INTO\b/i.test(trimmed)) scores.sql += 6;
    if (/\bUPDATE\b[\s\S]+\bSET\b/i.test(trimmed)) scores.sql += 6;
    if (/\bDELETE\s+FROM\b/i.test(trimmed)) scores.sql += 6;
    if (/\bCREATE\s+TABLE\b/i.test(trimmed)) scores.sql += 6;

    // PHP indicators
    if (/\$[a-zA-Z0-9_]+\s*=/.test(trimmed) && trimmed.includes(';')) scores.php += 3;
    if (/->[a-zA-Z0-9_]+\s*\(/.test(trimmed)) scores.php += 2;

    // Go indicators
    if (/\bfunc\s+[a-zA-Z0-9_]+\s*\(/.test(trimmed) && !trimmed.includes('function')) scores.go += 4;
    if (/\bfmt\.(Println|Printf|Sprintf)\s*\(/.test(trimmed)) scores.go += 5;

    // YAML indicators
    if (trimmed.startsWith('---') || (/^[a-zA-Z0-9_-]+:\s*[^\n]+/m.test(trimmed) && !trimmed.includes('{') && !trimmed.includes(';'))) {
      scores.yaml += 3;
    }

    // Determine highest score
    let highestLang: ProgrammingLanguage = 'unknown';
    let maxScore = 0;

    for (const [lang, score] of Object.entries(scores) as [ProgrammingLanguage, number][]) {
      if (score > maxScore) {
        maxScore = score;
        highestLang = lang;
      }
    }

    if (maxScore >= 6) {
      return { language: highestLang, confidence: 'high' };
    }
    if (maxScore >= 3) {
      return { language: highestLang, confidence: 'medium' };
    }

    return { language: 'unknown', confidence: 'low' };
  }
}
