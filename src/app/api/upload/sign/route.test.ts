import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { POST } from './route';
import { rateLimiter } from '@/lib/api/rate-limiter';
import { createClient } from '@/lib/supabase/server';
import crypto from 'crypto';

vi.mock('@/lib/supabase/server', () => ({
  createClient: vi.fn(),
}));

vi.mock('@/lib/api/rate-limiter', () => ({
  rateLimiter: {
    check: vi.fn(),
  },
}));

describe('POST /api/upload/sign', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = {
      ...originalEnv,
      NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME: 'test_cloud',
      NEXT_PUBLIC_CLOUDINARY_API_KEY: 'test_key',
      CLOUDINARY_API_SECRET: 'test_secret',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('rejects unauthenticated requests with 401', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: null } }),
      },
    });

    const res = await POST(new Request('http://localhost/api/upload/sign', { method: 'POST' }));
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe('Unauthorized');
  });

  it('Upload signing endpoint rejects requests when rate limited with 429', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: false,
      retryAfter: 30,
    });

    const res = await POST(new Request('http://localhost/api/upload/sign', { method: 'POST' }));
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe('30');
    const body = await res.json();
    expect(body.error).toBe('Too many requests. Please wait a moment.');
  });

  it('Upload signing endpoint succeeds with 200 and valid signature when allowed', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const res = await POST(new Request('http://localhost/api/upload/sign', { method: 'POST' }));
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.apiKey).toBe('test_key');
    expect(body.cloudName).toBe('test_cloud');
    expect(body.folder).toBe('my_ai_uploads');
    expect(body.allowed_formats).toBe('jpg,png,webp');
    expect(body.timestamp).toBeDefined();
    expect(body.signature).toBeDefined();

    // Verify SHA-1 signature matches expectations
    const stringToSign = `allowed_formats=jpg,png,webp&folder=my_ai_uploads&timestamp=${body.timestamp}`;
    const expectedSignature = crypto
      .createHash('sha1')
      .update(stringToSign + 'test_secret')
      .digest('hex');

    expect(body.signature).toBe(expectedSignature);
  });

  it('returns 500 when Cloudinary config is missing', async () => {
    delete process.env.CLOUDINARY_API_SECRET;

    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const res = await POST(new Request('http://localhost/api/upload/sign', { method: 'POST' }));
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe('Upload service is not configured');
  });

  it('signs raw PDF document uploads with documents folder', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const res = await POST(
      new Request('http://localhost/api/upload/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_type: 'raw',
          mime_type: 'application/pdf',
          filename: 'report.pdf',
          file_size: 1024 * 1024,
        }),
      })
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.folder).toBe('my_ai_uploads/documents');
    expect(body.resource_type).toBe('raw');
    expect(body.upload_url).toBe('https://api.cloudinary.com/v1_1/test_cloud/raw/upload');
    expect(body.allowed_formats).toBeUndefined();

    const stringToSign = `folder=my_ai_uploads/documents&timestamp=${body.timestamp}`;
    const expectedSig = crypto
      .createHash('sha1')
      .update(stringToSign + 'test_secret')
      .digest('hex');
    expect(body.signature).toBe(expectedSig);
  });

  it('signs raw TXT and HTML document uploads', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      auth: {
        getUser: vi.fn().mockResolvedValue({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const txtRes = await POST(
      new Request('http://localhost/api/upload/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_type: 'raw',
          mime_type: 'text/plain',
          filename: 'notes.txt',
          file_size: 50000,
        }),
      })
    );
    expect(txtRes.status).toBe(200);

    const htmlRes = await POST(
      new Request('http://localhost/api/upload/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_type: 'raw',
          mime_type: 'text/html',
          filename: 'page.html',
          file_size: 50000,
        }),
      })
    );
    expect(htmlRes.status).toBe(200);
  });

  it('rejects unsupported document MIME types for raw upload', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const res = await POST(
      new Request('http://localhost/api/upload/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_type: 'raw',
          mime_type: 'application/x-msdownload',
          filename: 'malware.exe',
          file_size: 1024,
        }),
      })
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/unsupported/i);
  });

  it('rejects oversized document uploads', async () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      auth: {
        getUser: vi.fn().mockResolvedValueOnce({ data: { user: { id: 'user-123' } } }),
      },
    });

    (rateLimiter.check as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      allowed: true,
      remaining: 9,
      reset: Date.now() + 60000,
    });

    const res = await POST(
      new Request('http://localhost/api/upload/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          resource_type: 'raw',
          mime_type: 'application/pdf',
          filename: 'huge.pdf',
          file_size: 15 * 1024 * 1024,
        }),
      })
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/exceeds maximum allowed size/i);
  });
});
