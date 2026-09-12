import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Attachment } from '@/lib/ai/types';
import { imageEngine } from './image-engine';
import { detectImageFormat, loadImageContent, MAX_IMAGE_DOWNLOAD_BYTES } from '@/lib/attachments/loader';
import { SafetySecurityAnalyzer } from '@/lib/theme/engines/safety-security/analyzer';

// Helper to create synthetic valid PNG buffer with specified dimensions
function createMockPng(width = 100, height = 100): Buffer {
  const buf = Buffer.alloc(33);
  // PNG signature
  buf.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  // IHDR chunk: length 13
  buf.writeUInt32BE(13, 8);
  buf.write('IHDR', 12, 'ascii');
  buf.writeUInt32BE(width, 16);
  buf.writeUInt32BE(height, 20);
  buf.set([0x08, 0x02, 0x00, 0x00, 0x00], 24); // 8-bit truecolor
  buf.writeUInt32BE(0, 29); // CRC dummy
  return buf;
}

// Helper to create synthetic valid JPEG buffer with specified dimensions
function createMockJpeg(width = 100, height = 100): Buffer {
  const buf = Buffer.alloc(35);
  // SOI + APP0 (JFIF)
  buf.set([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00], 0);
  // SOF0 marker (0xFF, 0xC0)
  buf.set([0xff, 0xc0, 0x00, 0x0b, 0x08], 20);
  buf.writeUInt16BE(height, 25);
  buf.writeUInt16BE(width, 27);
  buf.set([0x03, 0x01, 0x11, 0x00], 29);
  // EOI marker
  buf.set([0xff, 0xd9], 33);
  return buf;
}

// Helper to create synthetic valid WEBP buffer with specified dimensions
function createMockWebp(width = 100, height = 100): Buffer {
  const buf = Buffer.alloc(30);
  // RIFF header
  buf.write('RIFF', 0, 'ascii');
  buf.writeUInt32LE(22, 4); // File size - 8
  buf.write('WEBP', 8, 'ascii');
  buf.write('VP8 ', 12, 'ascii');
  buf.writeUInt32LE(14, 16); // Chunk size
  // VP8 keyframe header
  buf.set([0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a], 20);
  buf.writeUInt16LE(width & 0x3fff, 26);
  buf.writeUInt16LE(height & 0x3fff, 28);
  return buf;
}

describe('Stage 7.1: Image Intelligence Foundation & Architectural Integration', () => {
  const originalEnv = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;

  beforeEach(() => {
    process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME = 'testcloud';
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME = originalEnv;
    vi.restoreAllMocks();
  });

  // =========================================================================
  // 1. Format Detection & Magic Bytes
  // =========================================================================
  describe('A. Image Format & Magic-Byte Detection', () => {
    it('1. Correctly detects valid JPEG magic bytes', () => {
      const jpegBuf = createMockJpeg(200, 150);
      expect(detectImageFormat(jpegBuf)).toBe('jpeg');
    });

    it('2. Correctly detects valid PNG magic bytes', () => {
      const pngBuf = createMockPng(300, 200);
      expect(detectImageFormat(pngBuf)).toBe('png');
    });

    it('3. Correctly detects valid WEBP magic bytes', () => {
      const webpBuf = createMockWebp(120, 80);
      expect(detectImageFormat(webpBuf)).toBe('webp');
    });

    it('4. Rejects unsupported MIME types or arbitrary text files', () => {
      const textBuf = Buffer.from('Plain text file content masquerading as image');
      expect(detectImageFormat(textBuf)).toBeNull();

      const exeBuf = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]);
      expect(detectImageFormat(exeBuf)).toBeNull();
    });

    it('5. Rejects truncated or short buffer (< 12 bytes)', () => {
      const shortBuf = Buffer.from([0xff, 0xd8, 0xff]);
      expect(detectImageFormat(shortBuf)).toBeNull();
    });
  });

  // =========================================================================
  // 2. Safe Image Loading & SSRF Boundaries
  // =========================================================================
  describe('B. Safe Image Loading & SSRF Protections', () => {
    it('6. Rejects missing attachment object', async () => {
      // @ts-expect-error testing missing attachment
      await expect(loadImageContent(null)).rejects.toThrow(/No attachment provided/i);
    });

    it('7. Rejects unsupported non-image attachment type', async () => {
      const att: Attachment = {
        type: 'file',
        original_name: 'script.py',
        mime_type: 'text/x-python',
        url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/script.py',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Unsupported image format/i);
    });

    it('8. Rejects non-Cloudinary host (SSRF Protection)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'photo.png',
        url: 'https://evil-attacker.com/testcloud/image/upload/v1/my_ai_uploads/photo.png',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Invalid host/i);
    });

    it('9. Rejects non-HTTPS protocol (SSRF Protection)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'photo.png',
        url: 'http://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/photo.png',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Invalid host/i);
    });

    it('10. Rejects foreign Cloudinary cloud name (SSRF Protection)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'photo.png',
        url: 'https://res.cloudinary.com/foreigncloud/image/upload/v1/my_ai_uploads/photo.png',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Invalid path/i);
    });

    it('11. Rejects path traversal attempt in publicId (Namespace Isolation)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'photo.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/../secret.png',
        public_id: 'my_ai_uploads/../secret.png',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Invalid characters/i);
    });

    it('12. Rejects unauthorized upload folder (Namespace Isolation)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'photo.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/other_folder/photo.png',
        public_id: 'other_folder/photo.png',
      };
      await expect(loadImageContent(att)).rejects.toThrow(/Invalid upload namespace/i);
    });

    it('13. Handles HTTP network fetch failure cleanly', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'missing.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/missing.png',
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 404,
      } as unknown as Response);

      await expect(loadImageContent(att)).rejects.toThrow(/Fetch failed: 404/i);
    });

    it('14. Rejects oversized image exceeding 5MB limit via content-length', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'huge.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/huge.png',
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({
          'content-length': String(MAX_IMAGE_DOWNLOAD_BYTES + 1024),
          'content-type': 'image/png',
        }),
      } as unknown as Response);

      await expect(loadImageContent(att)).rejects.toThrow(/Image exceeds 5MB limit/i);
    });

    it('15. Rejects streaming oversized image exceeding 5MB limit during chunk reading', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'stream-huge.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/stream-huge.png',
      };

      const hugeChunk = new Uint8Array(6 * 1024 * 1024); // 6MB chunk
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: hugeChunk })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn().mockResolvedValue(undefined),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      await expect(loadImageContent(att)).rejects.toThrow(/Image exceeds 5MB limit during download/i);
      expect(mockReader.cancel).toHaveBeenCalled();
    });

    it('16. Detects MIME / content-type mismatch (MIME spoofing)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'fake.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/fake.png',
      };

      const jpegBuf = createMockJpeg(100, 100);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(jpegBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }), // Claims PNG, but bytes are JPEG
        body: { getReader: () => mockReader },
      } as unknown as Response);

      await expect(loadImageContent(att)).rejects.toThrow(/MIME spoofing detected/i);
    });

    it('17. Rejects corrupt image with invalid magic bytes', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'corrupt.jpg',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/corrupt.jpg',
      };

      const corruptBuf = Buffer.from('<html><body>Not an image</body></html>');
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(corruptBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/jpeg' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      await expect(loadImageContent(att)).rejects.toThrow(/Corrupt or unsupported image format/i);
    });
  });

  // =========================================================================
  // 3. ImageEngine Analysis & Reporting
  // =========================================================================
  describe('C. ImageEngine Analysis Contract', () => {
    it('18. Valid clean PNG produces LOW risk, score 0, and neutral Stage 7.1 summary', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'chart.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/chart.png',
      };

      const pngBuf = createMockPng(640, 480);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(pngBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);

      expect(report.inputType).toBe('image');
      expect(report.status).toBe('completed');
      expect(report.riskLevel).toBe('low');
      expect(report.confidenceLevel).toBe('medium');
      expect(report.score).toBe(0);
      expect(report.findings).toHaveLength(0);
      expect(report.summary).toBe('Image inspection completed with no Stage 7.1 structural issues detected.');

      // Evidence inspection
      expect(report.evidence).toHaveLength(1);
      expect(report.evidence[0].data.format).toBe('png');
      expect(report.evidence[0].data.width).toBe(640);
      expect(report.evidence[0].data.height).toBe(480);

      // Limitations check: presence of Stage 7.1 boundaries
      expect(report.limitations.some(l => l.includes('Stage 7.1 foundation scan'))).toBe(true);
      expect(report.limitations.some(l => l.includes('Absence of structural flags is not an endorsement'))).toBe(true);
    });

    it('19. Valid clean JPEG extracts dimensions and produces LOW risk', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'scenery.jpg',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/scenery.jpg',
      };

      const jpegBuf = createMockJpeg(800, 600);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(jpegBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/jpeg' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);
      expect(report.status).toBe('completed');
      expect(report.riskLevel).toBe('low');
      expect(report.score).toBe(0);
      expect(report.evidence[0].data.format).toBe('jpeg');
      expect(report.evidence[0].data.width).toBe(800);
      expect(report.evidence[0].data.height).toBe(600);
    });

    it('20. Valid clean WEBP extracts dimensions and produces LOW risk', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'sticker.webp',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/sticker.webp',
      };

      const webpBuf = createMockWebp(250, 250);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(webpBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/webp' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);
      expect(report.status).toBe('completed');
      expect(report.riskLevel).toBe('low');
      expect(report.score).toBe(0);
      expect(report.evidence[0].data.format).toBe('webp');
      expect(report.evidence[0].data.width).toBe(250);
      expect(report.evidence[0].data.height).toBe(250);
    });

    it('21. Detects decompression risk on extreme dimensions (> 16384px or > 64MP)', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'bomb.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/bomb.png',
      };

      // 20,000 x 20,000 pixels
      const bombBuf = createMockPng(20000, 20000);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(bombBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);

      expect(report.riskLevel).toBe('medium');
      expect(report.score).toBe(10);
      expect(report.findings).toHaveLength(1);
      expect(report.findings[0].type).toBe('metadata_anomaly');
      expect(report.findings[0].title).toContain('Excessive Image Dimensions');
      expect(report.evidence[0].data.isDecompressionRisk).toBe(true);
    });

    it('22. Image analysis failure produces incomplete/unknown state', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'unreachable.jpg',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/unreachable.jpg',
      };

      vi.spyOn(global, 'fetch').mockRejectedValueOnce(new Error('Connection timeout'));

      const report = await imageEngine.analyzeAttachment(att);

      expect(report.status).toBe('failed');
      expect(report.riskLevel).toBe('unknown');
      expect(report.confidenceLevel).toBe('low');
      expect(report.score).toBe(0);
      expect(report.recommendations[0].action).toBe('proceed_with_caution');
      expect(report.summary).toContain('could not be retrieved');
    });

    it('23. Privacy: Never exposes raw image bytes or signed upload URLs in report', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'sensitive.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/sensitive.png',
      };

      const pngBuf = createMockPng(100, 100);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(pngBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);
      const serialized = JSON.stringify(report);

      // Verify no raw base64 or Buffer dumps appear
      expect(serialized).not.toContain(pngBuf.toString('base64'));
      expect(serialized).not.toContain('CLOUDINARY_API_SECRET');
      expect(serialized).not.toContain('api_sign_request');
    });

    it('24. Epistemic humility: Does NOT make absolute safety claims in Stage 7.1', async () => {
      const att: Attachment = {
        type: 'image',
        original_name: 'innocent.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/innocent.png',
      };

      const pngBuf = createMockPng(50, 50);
      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(pngBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const report = await imageEngine.analyzeAttachment(att);

      expect(report.summary).not.toContain('100% safe');
      expect(report.summary).not.toContain('authentic');
      expect(report.summary).not.toContain('not AI-generated');
      expect(report.findings.some(f => f.findingType === 'possible_ai_generated')).toBe(false);
      expect(report.findings.some(f => f.findingType === 'scam_indicator')).toBe(false);
      expect(report.findings.some(f => f.findingType === 'suspicious_qr')).toBe(false);
    });

    it('25. Memory Cache Reuse: Does not re-fetch if attachment already has loadedImage in-memory', async () => {
      const pngBuf = createMockPng(100, 100);
      const att: Attachment = {
        type: 'image',
        original_name: 'cached.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/cached.png',
        // @ts-expect-error pre-cached
        loadedImage: {
          buffer: pngBuf,
          rawSizeBytes: pngBuf.length,
          filename: 'cached.png',
          mimeType: 'image/png',
          format: 'png',
          width: 100,
          height: 100,
          publicId: 'my_ai_uploads/cached.png',
          url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/cached.png',
          magicBytesValid: true,
        },
      };

      const fetchSpy = vi.spyOn(global, 'fetch');
      const report = await imageEngine.analyzeAttachment(att);

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(report.status).toBe('completed');
      expect(report.evidence[0].data.width).toBe(100);
    });
  });

  // =========================================================================
  // 4. SafetySecurityAnalyzer Full Pipeline Integration
  // =========================================================================
  describe('D. SafetySecurityAnalyzer Attachment Integration', () => {
    it('26. Routes image attachments through SafetySecurityAnalyzer and produces completed image report', async () => {
      const analyzer = new SafetySecurityAnalyzer();
      const pngBuf = createMockPng(400, 300);

      const att: Attachment = {
        id: 'att-img-1',
        type: 'image',
        original_name: 'test_screenshot.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/test_screenshot.png',
      };

      const mockReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(pngBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch').mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'image/png' }),
        body: { getReader: () => mockReader },
      } as unknown as Response);

      const context = await analyzer.analyze('', [
        {
          id: 'msg-1',
          role: 'user',
          content: '',
          metadata: {
            attachments: [att],
          },
          created_at: new Date().toISOString(),
        },
      ]);

      expect(context.facts).toBeDefined();
      const facts = context.facts as { report: import('@/lib/safety/types').SafetyReport };
      expect(facts.report).toBeDefined();
      expect(facts.report.inputType).toBe('image');
      expect(facts.report.riskLevel).toBe('low');
      expect(facts.report.score).toBe(0);
      expect(facts.report.summary).toBe('Image inspection completed with no Stage 7.1 structural issues detected.');
    });

    it('27. Handles multiple attachments: image + code simultaneously', async () => {
      const analyzer = new SafetySecurityAnalyzer();
      const pngBuf = createMockPng(200, 200);

      const imgAtt: Attachment = {
        id: 'att-img',
        type: 'image',
        original_name: 'diagram.png',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/diagram.png',
      };

      const codeAtt: Attachment = {
        id: 'att-code',
        type: 'file',
        original_name: 'safe.py',
        mime_type: 'text/x-python',
        url: 'https://res.cloudinary.com/testcloud/raw/upload/v1/my_ai_uploads/safe.py',
      };

      const mockImageReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new Uint8Array(pngBuf) })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      const mockCodeReader = {
        read: vi.fn()
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode('print("hello world")\n') })
          .mockResolvedValueOnce({ done: true, value: undefined }),
        cancel: vi.fn(),
      };

      vi.spyOn(global, 'fetch')
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'image/png' }),
          body: { getReader: () => mockImageReader },
        } as unknown as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'text/x-python' }),
          body: { getReader: () => mockCodeReader },
        } as unknown as Response);

      const context = await analyzer.analyze('', [
        {
          id: 'msg-multi',
          role: 'user',
          content: '',
          metadata: {
            attachments: [imgAtt, codeAtt],
          },
          created_at: new Date().toISOString(),
        },
      ]);

      const facts = context.facts as { report: import('@/lib/safety/types').SafetyReport };
      expect(facts.report).toBeDefined();
      expect(facts.report.status).toBe('completed');
      expect(facts.report.riskLevel).toBe('low');
      expect(facts.report.score).toBe(0);
    });
  });
});
