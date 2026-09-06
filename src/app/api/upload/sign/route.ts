import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { createClient } from '@/lib/supabase/server';

export async function POST(req: Request) {
  try {
    // Authenticate user
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Read config
    const cloudName = process.env.NEXT_PUBLIC_CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.NEXT_PUBLIC_CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      console.error('Cloudinary configuration is missing');
      return NextResponse.json({ error: 'Upload service is not configured' }, { status: 500 });
    }

    const timestamp = Math.round(new Date().getTime() / 1000);
    // We strictly enforce a preset or specific folder if needed.
    // For signed uploads, parameters must be sorted alphabetically before signing.
    const folder = 'my_ai_uploads';
    const paramsToSign: Record<string, string | number> = {
      timestamp,
      folder,
      // Add secure server-side constraints
      allowed_formats: 'jpg,png,webp'
    };

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
      allowed_formats: paramsToSign.allowed_formats
    });
  } catch (error) {
    console.error('Error generating upload signature:', error);
    return NextResponse.json({ error: 'Failed to generate upload signature' }, { status: 500 });
  }
}
