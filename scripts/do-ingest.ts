import fs from 'fs';
import path from 'path';
import { extractDocxSource, MockSupabaseKnowledgeBase } from '../src/lib/knowledge/ingest';

async function run() {
  const filePath = path.resolve(process.cwd(), 'data/الطب النبوي لابن القيم_260908_112010.docx');
  console.log('Reading DOCX from:', filePath);
  const fileBuffer = fs.readFileSync(filePath);
  
  const startTime = Date.now();
  console.log('Extracting source...');
  const source = await extractDocxSource(filePath, fileBuffer);
  
  const db = new MockSupabaseKnowledgeBase();
  console.log('Ingesting source...');
  await db.ingestSource(source);
  
  let totalChunks = 0;
  for (const s of source.sections) {
    totalChunks += s.chunks.length;
  }
  
  console.log('--- INGESTION REPORT ---');
  console.log('SOURCE FILE: الطب النبوي لابن القيم_260908_112010.docx');
  console.log('SOURCE TYPE: DOCX');
  console.log('SOURCE HASH:', source.file_hash);
  console.log('TITLE:', source.title);
  console.log('AUTHOR:', source.author);
  console.log('SECTIONS:', source.sections.length);
  console.log('CHUNKS (Paragraphs):', totalChunks);
  console.log('TIME MS:', Date.now() - startTime);

  // Check some chunks
  let provenanceCount = 0;
  for (const c of db.chunks) {
    if (c.printed_page) provenanceCount++;
  }
  console.log('PROVENANCE (Chunks w/ page):', provenanceCount);
}

run().catch(console.error);
