import { describe, it, expect } from 'vitest';
import { extractDocxSource, MockSupabaseKnowledgeBase, calculateHash } from './ingest';
import fs from 'fs';
import path from 'path';

describe('Phase 4.5.1: Real Source Ingestion', () => {
  it('1. Extracts DOCX and preserves Arabic text', async () => {
    const filePath = path.resolve(process.cwd(), 'data/الطب النبوي لابن القيم_260908_112010.docx');
    
    // Check if real file exists, else skip
    if (!fs.existsSync(filePath)) {
      console.warn('Real DOCX file not found at:', filePath);
      return;
    }

    const fileBuffer = fs.readFileSync(filePath);
    const source = await extractDocxSource(filePath, fileBuffer);
    
    expect(source.title).toBe('الطب النبوي');
    expect(source.author).toBe('ابن قيم الجوزية');
    expect(source.file_hash).toBeTruthy();
    
    // Check that we have a substantial number of sections and chunks
    expect(source.sections.length).toBeGreaterThan(0);
    expect(source.sections[0].chunks.length).toBeGreaterThan(0);
    
    // Insert into mock database
    const db = new MockSupabaseKnowledgeBase();
    await db.ingestSource(source);
    
    const chunks = db.chunks.filter(c => c.source_id === db.sources[0].id);
    expect(chunks.length).toBeGreaterThan(0);
    
    // Verify properties
    expect(chunks[0].raw_arabic_text).toBeTruthy();
    expect(chunks[0].reviewed_arabic_text).toBeNull();
    expect(chunks[0].status).toBe('unverified');
    
    // Idempotency: Duplicate detection
    await expect(db.ingestSource(source)).rejects.toThrow(/Duplicate source/);
  }, 30000);
});
