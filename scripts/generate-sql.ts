import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { extractDocxSource } from '../src/lib/knowledge/ingest';

async function run() {
  const filePath = path.resolve(process.cwd(), 'data/الطب النبوي لابن القيم_260908_112010.docx');
  const fileBuffer = fs.readFileSync(filePath);
  
  const source = await extractDocxSource(filePath, fileBuffer);
  
  let totalChunks = 0;
  for (const s of source.sections) {
    totalChunks += s.chunks.length;
  }
  console.log(`Source extracted: ${source.sections.length} sections, ${totalChunks} chunks. Hash: ${source.file_hash}`);

  const sourceId = crypto.randomUUID();
  
  const escapeSql = (str: string) => str.replace(/'/g, "''");

  let sql = `
DO $$ 
DECLARE
  v_source_id UUID := '${sourceId}';
  v_section_id UUID;
BEGIN
  IF EXISTS (SELECT 1 FROM kb_sources WHERE file_hash = '${escapeSql(source.file_hash)}') THEN
    RAISE EXCEPTION 'Duplicate source: file_hash ${escapeSql(source.file_hash)} already ingested.';
  END IF;

  INSERT INTO kb_sources (id, title, author, file_name, file_hash)
  VALUES (v_source_id, '${escapeSql(source.title)}', '${escapeSql(source.author)}', '${escapeSql(source.file_name)}', '${escapeSql(source.file_hash)}');
`;

  for (const section of source.sections) {
    const sectionId = crypto.randomUUID();
    sql += `
  v_section_id := '${sectionId}';
  INSERT INTO kb_sections (id, source_id, title, sequence_num)
  VALUES (v_section_id, v_source_id, '${escapeSql(section.title)}', ${section.sequence_num});
`;
    if (section.chunks.length > 0) {
      sql += `  INSERT INTO kb_chunks (id, source_id, section_id, sequence_num, raw_arabic_text, status) VALUES\n`;
      const chunkValues = section.chunks.map(chunk => {
        return `  (gen_random_uuid(), v_source_id, v_section_id, ${chunk.sequence_num}, '${escapeSql(chunk.raw_arabic_text)}', 'unverified')`;
      });
      sql += chunkValues.join(',\n') + ';\n';
    }
  }

  sql += `
END $$;
`;

  fs.writeFileSync(path.resolve(process.cwd(), 'data/ingest.sql'), sql, 'utf8');
  console.log('Saved to data/ingest.sql');
}

run().catch(console.error);
