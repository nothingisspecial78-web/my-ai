-- Phase 4.6: SOURCE, EVIDENCE & CITATION ARCHITECTURE

-- 1. Update evidence_layer enum if possible (Postgres 10+)
ALTER TYPE evidence_layer RENAME VALUE 'revelation' TO 'quran';

-- 2. HADITH ARCHITECTURE
CREATE TABLE public.kb_hadiths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection TEXT NOT NULL,
    book_number TEXT,
    chapter_number TEXT,
    hadith_number TEXT,
    alternate_numbering TEXT,
    arabic_matn TEXT NOT NULL,
    narrator_chain TEXT,
    source_edition TEXT,
    external_identifier TEXT,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE public.kb_hadith_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hadith_id UUID REFERENCES public.kb_hadiths(id) ON DELETE CASCADE NOT NULL,
    scholar_authority TEXT NOT NULL,
    grade TEXT NOT NULL,
    notes TEXT,
    reference_source TEXT,
    status verification_status DEFAULT 'unverified' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. QURAN ARCHITECTURE
CREATE TABLE public.kb_quran_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    surah_number INT NOT NULL,
    ayah_number INT NOT NULL,
    arabic_text TEXT,
    source_version TEXT DEFAULT 'Hafs',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(surah_number, ayah_number, source_version)
);

-- 4. CLAIMS ARCHITECTURE (Extending existing)
-- Modify existing kb_claims table to decouple it from chunk_id as the ONLY source, 
-- or create a linking table. Since we must be ADDITIVE and not drop columns unnecessarily,
-- we'll make chunk_id nullable and add a provenance/evidence linking table.

ALTER TABLE public.kb_claims ALTER COLUMN chunk_id DROP NOT NULL;
ALTER TABLE public.kb_claims ADD COLUMN language kb_language DEFAULT 'english' NOT NULL;
ALTER TABLE public.kb_claims ADD COLUMN claim_type TEXT DEFAULT 'general' NOT NULL;
ALTER TABLE public.kb_claims ADD COLUMN qualification_condition TEXT;
ALTER TABLE public.kb_claims ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL;

-- Claim Provenance (Linking claim to multiple evidence sources)
CREATE TABLE public.kb_claim_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID REFERENCES public.kb_claims(id) ON DELETE CASCADE NOT NULL,
    source_id UUID REFERENCES public.kb_sources(id) ON DELETE CASCADE,
    section_id UUID REFERENCES public.kb_sections(id) ON DELETE CASCADE,
    chunk_id UUID REFERENCES public.kb_chunks(id) ON DELETE CASCADE,
    hadith_id UUID REFERENCES public.kb_hadiths(id) ON DELETE CASCADE,
    quran_ref_id UUID REFERENCES public.kb_quran_references(id) ON DELETE CASCADE,
    location_detail TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CHECK (
        source_id IS NOT NULL OR 
        chunk_id IS NOT NULL OR 
        hadith_id IS NOT NULL OR 
        quran_ref_id IS NOT NULL
    )
);

-- Claim Relationships
CREATE TYPE claim_relationship_type AS ENUM (
    'supports',
    'contradicts',
    'qualifies',
    'explains',
    'interprets',
    'updates',
    'disputes',
    'corroborates',
    'contextualizes'
);

CREATE TABLE public.kb_claim_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_claim_id UUID REFERENCES public.kb_claims(id) ON DELETE CASCADE NOT NULL,
    target_claim_id UUID REFERENCES public.kb_claims(id) ON DELETE CASCADE NOT NULL,
    relationship_type claim_relationship_type NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(source_claim_id, target_claim_id, relationship_type)
);

-- 5. ROW LEVEL SECURITY (RLS)

ALTER TABLE public.kb_hadiths ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read hadiths" ON public.kb_hadiths FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_hadith_assessments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read hadith assessments" ON public.kb_hadith_assessments FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_quran_references ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read quran references" ON public.kb_quran_references FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_claim_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read claim evidence" ON public.kb_claim_evidence FOR SELECT USING (auth.role() = 'authenticated');

ALTER TABLE public.kb_claim_relationships ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read claim relationships" ON public.kb_claim_relationships FOR SELECT USING (auth.role() = 'authenticated');
