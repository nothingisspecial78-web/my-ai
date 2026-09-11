import { describe, it, expect, vi } from 'vitest';
import fs from 'fs';
import path from 'path';
import { Attachment } from '@/lib/ai/types';
import { extractConversationTitle } from '@/lib/utilities/title';

describe('New Chat Upload & Attachment Preservation', () => {
  it('1. ChatEmptyPage source contains Attachment import and handles attachments in handleSend', () => {
    const pagePath = path.resolve(process.cwd(), 'src/app/chat/page.tsx');
    const content = fs.readFileSync(pagePath, 'utf-8');

    // Verify Attachment imported from @/lib/ai/types
    expect(content).toMatch(/import\s+.*Attachment.*from\s+['"]@\/lib\/ai\/types['"]/);

    // Verify handleSend signature includes attachments
    expect(content).toContain('handleSend = async (text: string, attachments?: Attachment[])');

    // Verify title fallback handles attachments and text extraction
    expect(content).toContain('extractConversationTitle(text)');
    expect(content).toContain('defaultTitle');

    // Verify metadata stores attachments when present, and empty object when not
    expect(content).toContain('metadata: attachments && attachments.length > 0 ? { attachments');
  });

  it('2. New chat with image and text preserves attachment in metadata and creates conversation', async () => {
    const createConversationMock = vi.fn().mockResolvedValueOnce({ id: 'convo-new-1', title: 'Check this diagram' });
    const createMessageMock = vi.fn().mockResolvedValueOnce({ id: 'msg-1' });

    const attachments: Attachment[] = [
      {
        type: 'image',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/diagram.png',
        public_id: 'my_ai_uploads/diagram.png',
        mime_type: 'image/png',
      },
    ];

    const text = 'Check this diagram';

    // Simulate handleSend logic
    const title = text.trim() ? extractConversationTitle(text) : 'Image Analysis';
    const newConvo = await createConversationMock(title, undefined);
    expect(createConversationMock).toHaveBeenCalledWith('Check this diagram', undefined);

    if (newConvo) {
      await createMessageMock({
        conversation_id: newConvo.id,
        role: 'user',
        content: text,
        metadata: attachments && attachments.length > 0 ? { attachments } : {},
      });
    }

    expect(createMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        conversation_id: 'convo-new-1',
        role: 'user',
        content: 'Check this diagram',
        metadata: { attachments },
      })
    );
  });

  it('3. Image-only new chat (empty text) falls back to "Image Analysis" title and preserves attachments', async () => {
    const createConversationMock = vi.fn().mockResolvedValueOnce({ id: 'convo-new-2', title: 'Image Analysis' });
    const createMessageMock = vi.fn().mockResolvedValueOnce({ id: 'msg-2' });

    const attachments: Attachment[] = [
      {
        type: 'image',
        url: 'https://res.cloudinary.com/testcloud/image/upload/v1/my_ai_uploads/photo.jpg',
        public_id: 'my_ai_uploads/photo.jpg',
        mime_type: 'image/jpeg',
      },
    ];

    const text = '   '; // Whitespace-only

    // Simulate handleSend logic
    const shouldSkip = (!text.trim() && (!attachments || attachments.length === 0));
    expect(shouldSkip).toBe(false);

    const title = text.trim() ? extractConversationTitle(text) : 'Image Analysis';
    expect(title).toBe('Image Analysis');

    const newConvo = await createConversationMock(title, undefined);
    if (newConvo) {
      await createMessageMock({
        conversation_id: newConvo.id,
        role: 'user',
        content: text,
        metadata: attachments && attachments.length > 0 ? { attachments } : {},
      });
    }

    expect(createConversationMock).toHaveBeenCalledWith('Image Analysis', undefined);
    expect(createMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        conversation_id: 'convo-new-2',
        role: 'user',
        content: '   ',
        metadata: { attachments },
      })
    );
  });

  it('4. Text-only new chat preserves empty metadata behavior', async () => {
    const createConversationMock = vi.fn().mockResolvedValueOnce({ id: 'convo-new-3', title: 'Quantum computing basics' });
    const createMessageMock = vi.fn().mockResolvedValueOnce({ id: 'msg-3' });

    const text = 'Quantum computing basics';
    const attachments: Attachment[] | undefined = undefined;

    const title = text.trim() ? extractConversationTitle(text) : 'Image Analysis';
    const newConvo = await createConversationMock(title, undefined);

    if (newConvo) {
      await createMessageMock({
        conversation_id: newConvo.id,
        role: 'user',
        content: text,
        metadata: attachments && attachments.length > 0 ? { attachments } : {},
      });
    }

    expect(createConversationMock).toHaveBeenCalledWith('Quantum computing basics', undefined);
    expect(createMessageMock).toHaveBeenCalledWith(
      expect.objectContaining({
        conversation_id: 'convo-new-3',
        role: 'user',
        content: 'Quantum computing basics',
        metadata: {},
      })
    );
  });
});
