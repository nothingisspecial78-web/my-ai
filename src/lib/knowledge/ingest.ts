import crypto from 'crypto';
import path from 'path';
import mammoth from 'mammoth';

export interface KBSection {
  title: string;
  sequence_num: number;
  chunks: KBChunk[];
}

export interface KBChunk {
  sequence_num: number;
  raw_arabic_text: string;
  pdf_page?: number | null;
  printed_page?: string | null;
}

export interface KBSource {
  title: string;
  author: string;
  file_name: string;
  file_hash: string;
  sections: KBSection[];
}

export function calculateHash(content: string | Buffer): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Deterministic DOCX extraction for Tibb al-Nabi.
 */
export async function extractDocxSource(filePath: string, fileBuffer: Buffer): Promise<KBSource> {
  const hash = calculateHash(fileBuffer);

  // Extract paragraphs as simple text separated by double-newlines
  // mammoth provides HTML, but we can also use extractRawText to get plain text.
  // Using HTML is better if we need to detect specific formatting (e.g. bold page numbers).
  // For safety and strict text extraction, we use extractRawText and split by double-newline.
  const result = await mammoth.extractRawText({ buffer: fileBuffer });
  const rawText = result.value;

  // Split by double newline (mammoth default behavior for paragraphs is double newline if we use rawText, 
  // or single newline. Actually mammoth `extractRawText` typically returns single `\n\n` for paragraphs).
  const lines = rawText.split(/\n+/);

  let currentSectionTitle = 'مقدمة'; // Default first section if no heading
  let currentSectionChunks: KBChunk[] = [];
  const sections: KBSection[] = [];
  
  let sectionSeq = 1;
  let chunkSeq = 1;
  let currentPrintedPage: string | null = null;

  const flushSection = () => {
    if (currentSectionChunks.length > 0) {
      sections.push({
        title: currentSectionTitle,
        sequence_num: sectionSeq++,
        chunks: currentSectionChunks,
      });
    }
    currentSectionChunks = [];
    chunkSeq = 1;
  };

  const chapterRegex = /^(?:فصل|فَصْلٌ?|فصل:|فصل\s+)\s*(?:في|فِي)?\s*(.*)/i;
  // Volume/Page number pattern like (371/7) or (379/7)
  const pageRegex = /^\s*\(\s*(\d+\/\d+)\s*\)\s*$/;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Ignore table of contents noise like "الموضوع الصفحة" or short index entries if desired,
    // but the instruction says "DO NOT summarize the book. Do NOT invent missing information."
    // "Preserve paragraph boundaries." We will just process deterministically.

    if (pageRegex.test(trimmed)) {
      // Detected a page/volume marker
      const match = trimmed.match(pageRegex);
      if (match) {
        currentPrintedPage = match[1];
      }
      continue;
    }

    if (chapterRegex.test(trimmed) || trimmed === 'مقدمة' || trimmed === 'المقدمة') {
      flushSection();
      currentSectionTitle = trimmed;
      // We also push the chapter title as a chunk to preserve the exact text
      currentSectionChunks.push({
        sequence_num: chunkSeq++,
        raw_arabic_text: trimmed,
        printed_page: currentPrintedPage,
        pdf_page: null
      });
    } else {
      currentSectionChunks.push({
        sequence_num: chunkSeq++,
        raw_arabic_text: trimmed,
        printed_page: currentPrintedPage,
        pdf_page: null
      });
    }
  }
  flushSection();

  return {
    title: 'الطب النبوي',
    author: 'ابن قيم الجوزية',
    file_name: path.basename(filePath),
    file_hash: hash,
    sections,
  };
}

export class MockSupabaseKnowledgeBase {
  sources: Record<string, unknown>[] = [];
  sections: Record<string, unknown>[] = [];
  chunks: Record<string, unknown>[] = [];

  async ingestSource(source: KBSource) {
    // 1. Idempotency: Duplicate Check
    const existingSource = this.sources.find(s => s.file_hash === source.file_hash);
    if (existingSource) {
      throw new Error(`Duplicate source: file_hash ${source.file_hash} already ingested.`);
    }

    // 2. Insert Source
    const sourceId = crypto.randomUUID();
    this.sources.push({
      id: sourceId,
      title: source.title,
      author: source.author,
      file_name: source.file_name,
      file_hash: source.file_hash,
      status: 'unverified'
    });

    // 3. Insert Sections & Chunks transactionally (simulated)
    for (const section of source.sections) {
      const sectionId = crypto.randomUUID();
      this.sections.push({
        id: sectionId,
        source_id: sourceId,
        title: section.title,
        sequence_num: section.sequence_num
      });

      for (const chunk of section.chunks) {
        this.chunks.push({
          id: crypto.randomUUID(),
          source_id: sourceId,
          section_id: sectionId,
          sequence_num: chunk.sequence_num,
          raw_arabic_text: chunk.raw_arabic_text,
          reviewed_arabic_text: null, // Initial state must be NULL
          status: 'unverified'
        });
      }
    }

    return sourceId;
  }
}
