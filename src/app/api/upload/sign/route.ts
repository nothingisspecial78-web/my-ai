import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@/lib/supabase/server';
import { rateLimiter } from '@/lib/api/rate-limiter';
import { ATTACHMENT_LIMITS, classifyAttachment } from '@/lib/attachments';

export async function POST(req: Request) {
  try {
    // Authenticate user
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Rate limiting check
    const rateCheck = await rateLimiter.check(user.id);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: 'Too many requests. Please wait a moment.' },
        {
          status: 429,
          headers: {
            'Retry-After': String(rateCheck.retryAfter),
          },
        }
      );
    }

    // Read config
    const cloudName = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.NEXT_PUBLIC_CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      console.error('Cloudinary configuration is missing');
      return NextResponse.json({ error: 'Upload service is not configured' }, { status: 500 });
    }

    // Parse optional request body for resource_type / mime_type / file_size / filename
    let resourceType: 'image' | 'raw' = 'image';
    let mimeType: string | undefined;
    let fileSize: number | undefined;
    let filename: string | undefined;

    try {
      if (req.headers.get('content-type')?.includes('application/json')) {
        const body = await req.json();
        if (body && typeof body === 'object') {
          if (body.resource_type === 'raw' || body.resource_type === 'image') {
            resourceType = body.resource_type;
          }
          if (typeof body.mime_type === 'string') mimeType = body.mime_type;
          if (typeof body.file_size === 'number') fileSize = body.file_size;
          if (typeof body.filename === 'string') filename = body.filename;
        }
      }
    } catch {
      // Ignore body parsing failure; default to image
    }

    const timestamp = Math.round(new Date().getTime() / 1000);
    const paramsToSign: Record<string, string | number> = {
      timestamp,
    };

    let folder = 'my_ai_uploads';
    let uploadUrl = `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`;
    let allowedFormats: string | undefined = 'jpg,png,webp';

    if (resourceType === 'raw') {
      folder = 'my_ai_uploads/documents';
      uploadUrl = `https://api.cloudinary.com/v1_1/${cloudName}/raw/upload`;
      allowedFormats = undefined; // raw uploads do not use allowed_formats in signature

      // Validate MIME type and file size if supplied
      if (mimeType || filename) {
        const classification = classifyAttachment(mimeType || '', filename);
        if (!classification.type || classification.type === 'image') {
          return NextResponse.json(
            { error: classification.error || 'Invalid or unsupported document type.' },
            { status: 400 }
          );
        }

        // Validate size if specified
        if (typeof fileSize === 'number') {
          if (fileSize <= 0) {
            return NextResponse.json({ error: 'File cannot be empty.' }, { status: 400 });
          }
          const docLimit = classification.type === 'pdf'
            ? ATTACHMENT_LIMITS.pdf.maxSize
            : ATTACHMENT_LIMITS.text.maxSize;
          if (fileSize > docLimit) {
            const mb = Math.round(docLimit / (1024 * 1024));
            return NextResponse.json(
              { error: `File exceeds maximum allowed size of ${mb}MB for ${classification.type.toUpperCase()} files.` },
              { status: 400 }
            );
          }
        }
      }

      paramsToSign.folder = folder;
    } else {
      // image upload
      folder = 'my_ai_uploads';
      paramsToSign.folder = folder;
      paramsToSign.allowed_formats = 'jpg,png,webp';

      // Validate image size if specified
      if (typeof fileSize === 'number') {
        if (fileSize <= 0) {
          return NextResponse.json({ error: 'File cannot be empty.' }, { status: 400 });
        }
        if (fileSize > ATTACHMENT_LIMITS.image.maxSize) {
          return NextResponse.json(
            { error: 'Image size exceeds maximum allowed size of 5MB.' },
            { status: 400 }
          );
        }
      }
    }

    // Sort keys alphabetically
    const sortedKeys = Object.keys(paramsToSign).sort();
    const stringToSign = sortedKeys.map(key => `${key}=${paramsToSign[key]}`).join('&');

    // Create SHA-1 signature
    const signature = crypto
      .createHash('sha1')
      .update(stringToSign + apiSecret)
      .digest('hex');

    return NextResponse.json({
      timestamp,
      signature,
      apiKey,
      cloudName,
      folder,
      resource_type: resourceType,
      upload_url: uploadUrl,
      ...(allowedFormats ? { allowed_formats: allowedFormats } : {}),
    });
  } catch (error) {
    console.error('Error generating upload signature:', error);
    return NextResponse.json({ error: 'Failed to generate upload signature' }, { status: 500 });
  }
}
