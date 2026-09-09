-- Migration: Phase 4.5 Knowledge Base Schema

-- 1. ENUMS & CUSTOM TYPES
CREATE TYPE verification_status AS ENUM ('unverified', 'needs_review', 'verified');

CREATE TYPE evidence_layer AS ENUM (
    'revelation',
    'hadith',
    'classical_scholarly',
    'traditional_medical',
    'modern_scientific',
    'modern_clinical'
);

CREATE TYPE kb_language AS ENUM ('arabic', 'english', 'malayalam');

-- 2. SOURCES (The physical book / PDF)
CREATE TABLE public.kb_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    author TEXT,
    original_language kb_language DEFAULT 'arabic',
    edition TEXT,
    publisher TEXT,
    publication_year INT,
    file_name TEXT,
    file_hash TEXT UNIQUE,
    version_tag TEXT NOT NULL DEFAULT 'v1',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. SECTIONS (Chapters / Babs / Fasls)
CREATE TABLE public.kb_sections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES public.kb_sources(id) ON DELETE CASCADE NOT NULL,
    parent_id UUID REFERENCES public.kb_sections(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    sequence_num INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_kb_sections_hierarchy ON public.kb_sections(source_id, parent_id);

-- 4. CHUNKS (The atomic unit of retrieval)
CREATE TABLE public.kb_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES public.kb_sources(id) ON DELETE CASCADE NOT NULL,
    section_id UUID REFERENCES public.kb_sections(id) ON DELETE SET NULL,
    pdf_page INT,
    printed_page TEXT,
    sequence_num INT NOT NULL,
    raw_arabic_text TEXT NOT NULL,
    reviewed_arabic_text TEXT,
    status verification_status DEFAULT 'unverified' NOT NULL,
    primary_layer evidence_layer DEFAULT 'classical_scholarly',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_kb_chunks_source_seq ON public.kb_chunks(source_id, sequence_num);
CREATE INDEX idx_kb_chunks_section ON public.kb_chunks(section_id);

-- 5. TRANSLATIONS
CREATE TABLE public.kb_translations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chunk_id UUID REFERENCES public.kb_chunks(id) ON DELETE CASCADE NOT NULL,
    language kb_language NOT NULL,
    translated_text TEXT NOT NULL,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(chunk_id, language)
);

-- 6. TOPICS (Taxonomy)
CREATE TABLE public.kb_topics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE public.kb_chunk_topics (
    chunk_id UUID REFERENCES public.kb_chunks(id) ON DELETE CASCADE NOT NULL,
    topic_id UUID REFERENCES public.kb_topics(id) ON DELETE CASCADE NOT NULL,
    confidence FLOAT DEFAULT 1.0,
    PRIMARY KEY (chunk_id, topic_id)
);

-- 7. CLAIMS
CREATE TABLE public.kb_claims (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chunk_id UUID REFERENCES public.kb_chunks(id) ON DELETE CASCADE NOT NULL,
    claim_text TEXT NOT NULL,
    layer evidence_layer NOT NULL,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 8. ROW LEVEL SECURITY (RLS)
ALTER TABLE public.kb_sources ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read verified sources" ON public.kb_sources FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_sections ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read verified sections" ON public.kb_sections FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_chunks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read chunks" ON public.kb_chunks FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_translations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read translations" ON public.kb_translations FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_topics ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read topics" ON public.kb_topics FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_chunk_topics ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read chunk topics" ON public.kb_chunk_topics FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_claims ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read claims" ON public.kb_claims FOR SELECT USING (auth.role() = 'authenticated');

-- Note: Normal users cannot INSERT/UPDATE/DELETE.
-- Ingestion scripts using `service_role` will bypass RLS automatically.
