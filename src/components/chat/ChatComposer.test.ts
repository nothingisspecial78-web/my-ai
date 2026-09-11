import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('ChatComposer Universal Attachments & Accessibility', () => {
  const composerPath = path.resolve(process.cwd(), 'src/components/chat/ChatComposer.tsx');
  const composerContent = fs.readFileSync(composerPath, 'utf-8');

  it('1. Contains native camera input with capture="environment"', () => {
    expect(composerContent).toContain('capture="environment"');
    expect(composerContent).toContain('aria-label="Take Photo"');
    expect(composerContent).toContain('accept="image/jpeg,image/png,image/webp"');
  });

  it('2. Contains image upload file input', () => {
    expect(composerContent).toContain('aria-label="Upload Image"');
    expect(composerContent).toContain('ref={imageInputRef}');
  });

  it('3. Contains universal file input supporting PDF, TXT, HTML', () => {
    expect(composerContent).toContain('aria-label="Upload File"');
    expect(composerContent).toContain('accept=".pdf,.txt,.html,.htm,application/pdf,text/plain,text/html"');
    expect(composerContent).toContain('ref={fileInputRef}');
  });

  it('4. Accessible + Add menu implements ARIA menu specification', () => {
    expect(composerContent).toContain('role="menu"');
    expect(composerContent).toContain('role="menuitem"');
    expect(composerContent).toContain('aria-haspopup="menu"');
    expect(composerContent).toContain('aria-expanded={isMenuOpen}');
    expect(composerContent).toContain('aria-orientation="vertical"');
    expect(composerContent).toContain('aria-label="Attachment options"');
  });

  it('5. Supports keyboard navigation (Escape, ArrowDown, ArrowUp)', () => {
    expect(composerContent).toContain("e.key === 'Escape'");
    expect(composerContent).toContain("e.key === 'ArrowDown'");
    expect(composerContent).toContain("e.key === 'ArrowUp'");
  });

  it('6. Enforces MAX_ATTACHMENTS_PER_MESSAGE constraint', () => {
    expect(composerContent).toContain('MAX_ATTACHMENTS_PER_MESSAGE');
    expect(composerContent).toContain('attachments.length >= MAX_ATTACHMENTS_PER_MESSAGE');
  });

  it('7. Displays document preview chips with remove button', () => {
    expect(composerContent).toContain('formatFileSize(att.size)');
    expect(composerContent).toContain('Remove image');
    expect(composerContent).toContain('Remove ${name}');
  });
});
