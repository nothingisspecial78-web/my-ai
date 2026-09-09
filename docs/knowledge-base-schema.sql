-- ==============================================================================
-- DESIGN PROPOSAL — NOT EXECUTED
-- Phase 4.4: Knowledge Base Architecture for Tibb al-Nabi
-- DO NOT RUN AGAINST SUPABASE YET.
-- ==============================================================================

-- 1. ENUMS & CUSTOM TYPES
-- ==============================================================================

-- Represents the status of the OCR/Extraction pipeline and human review.
CREATE TYPE verification_status AS ENUM ('unverified', 'needs_review', 'verified');

-- Represents the distinct layers of evidence to prevent LLM hallucination/merging.
CREATE TYPE evidence_layer AS ENUM (
    'revelation',           -- Qur'an
    'hadith',               -- Prophetic traditions
    'classical_scholarly',  -- e.g., Ibn al-Qayyim's commentary
    'traditional_medical',  -- Historical practices
    'modern_scientific',    -- Scientific evidence (future)
    'modern_clinical'       -- Clinical guidance (future)
);

-- Supported languages for translations
CREATE TYPE kb_language AS ENUM ('arabic', 'english', 'malayalam');

-- 2. SOURCES (The physical book / PDF)
-- ==============================================================================
CREATE TABLE kb_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    author TEXT,
    original_language kb_language DEFAULT 'arabic',
    edition TEXT,
    publisher TEXT,
    publication_year INT,
    file_name TEXT,
    file_hash TEXT UNIQUE, -- Ensures we don't ingest the same PDF twice
    version_tag TEXT NOT NULL DEFAULT 'v1', -- Used if we re-extract the same book
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
-- Comment: Stores authoritative metadata. Edition and year are nullable since historical texts often have varying modern editions.

-- 3. SECTIONS (Chapters / Babs / Fasls)
-- ==============================================================================
CREATE TABLE kb_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES kb_sources(id) ON DELETE CASCADE NOT NULL,
    parent_id UUID REFERENCES kb_sections(id) ON DELETE CASCADE, -- Supports hierarchical chapters
    title TEXT NOT NULL,
    sequence_num INT NOT NULL, -- Logical ordering within the parent
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
-- Index for quick hierarchical traversal
CREATE INDEX idx_kb_sections_hierarchy ON kb_sections(source_id, parent_id);

-- 4. CHUNKS (The atomic unit of retrieval)
-- ==============================================================================
CREATE TABLE kb_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES kb_sources(id) ON DELETE CASCADE NOT NULL,
    section_id UUID REFERENCES kb_sections(id) ON DELETE SET NULL,
    
    -- Citation location tracking
    pdf_page INT,           -- The absolute page in the uploaded PDF file
    printed_page TEXT,      -- The printed page string (e.g., "123" or "IV")
    sequence_num INT NOT NULL, -- Order of this chunk within the section
    
    -- Arabic Text Preservation (Crucial)
    raw_arabic_text TEXT NOT NULL, -- Immutable extraction result from OCR
    reviewed_arabic_text TEXT,     -- Corrected version after human review (overrides raw in UI)
    
    status verification_status DEFAULT 'unverified' NOT NULL,
    
    -- Evidence Layer defaults for this chunk (can be overridden by claims)
    primary_layer evidence_layer DEFAULT 'classical_scholarly',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
-- Indexes for sequence ordering and retrieval
CREATE INDEX idx_kb_chunks_source_seq ON kb_chunks(source_id, sequence_num);
CREATE INDEX idx_kb_chunks_section ON kb_chunks(section_id);
-- Future FTS index placeholder
-- CREATE INDEX idx_kb_chunks_arabic_fts ON kb_chunks USING GIN (to_tsvector('arabic', coalesce(reviewed_arabic_text, raw_arabic_text)));

-- 5. TRANSLATIONS
-- ==============================================================================
CREATE TABLE kb_translations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chunk_id UUID REFERENCES kb_chunks(id) ON DELETE CASCADE NOT NULL,
    language kb_language NOT NULL,
    translated_text TEXT NOT NULL,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(chunk_id, language) -- Only one translation per language per chunk
);

-- 6. TOPICS (Taxonomy)
-- ==============================================================================
CREATE TABLE kb_topics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE, -- e.g., 'Honey', 'Hijamah'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Mapping chunks to topics
CREATE TABLE kb_chunk_topics (
    chunk_id UUID REFERENCES kb_chunks(id) ON DELETE CASCADE NOT NULL,
    topic_id UUID REFERENCES kb_topics(id) ON DELETE CASCADE NOT NULL,
    confidence FLOAT DEFAULT 1.0, -- Useful if auto-tagged by AI during Phase 4.5
    PRIMARY KEY (chunk_id, topic_id)
);

-- 7. CLAIMS (Future Roadmap Placeholder)
-- ==============================================================================
-- Comment: Designed but left unpopulated during MVP. This prevents "Honey cures X" 
-- from being an undifferentiated fact, linking it exactly to the layer claiming it.
CREATE TABLE kb_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chunk_id UUID REFERENCES kb_chunks(id) ON DELETE CASCADE NOT NULL,
    claim_text TEXT NOT NULL,
    layer evidence_layer NOT NULL,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- ==============================================================================
-- RLS PROPOSALS
-- ==============================================================================
-- Knowledge Base is STRICTLY READ-ONLY for users.
-- Only the service_role (Ingestion Pipeline) can insert/update/delete.
-- 
-- ALTER TABLE kb_sources ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY "Users can read verified sources" ON kb_sources FOR SELECT USING (auth.role() = 'authenticated');
-- 
-- ALTER TABLE kb_chunks ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY "Users can read chunks" ON kb_chunks FOR SELECT USING (auth.role() = 'authenticated');
--
-- Admin policies would simply use service_role bypassing RLS.
