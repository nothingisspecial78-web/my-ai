-- Migration: Phase 4.6 Safety & Security Analysis Architecture
-- Additive tables for persistent safety analysis records and findings

-- 1. SAFETY ANALYSES (Core audit record)
CREATE TABLE public.safety_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    conversation_id UUID REFERENCES public.conversations(id) ON DELETE SET NULL,
    input_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    risk_level TEXT NOT NULL,
    confidence_level TEXT NOT NULL,
    score INT,
    summary TEXT,
    limitations JSONB DEFAULT '[]'::jsonb NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_safety_analyses_user ON public.safety_analyses(user_id);
CREATE INDEX idx_safety_analyses_conversation ON public.safety_analyses(conversation_id);

-- 2. SAFETY FINDINGS (Observable signals & threat indicators)
CREATE TABLE public.safety_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES public.safety_analyses(id) ON DELETE CASCADE NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence_level TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_safety_findings_analysis ON public.safety_findings(analysis_id);

-- 3. SAFETY EVIDENCE (Underlying raw evidence / analyzer details)
CREATE TABLE public.safety_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES public.safety_analyses(id) ON DELETE CASCADE NOT NULL,
    finding_id UUID REFERENCES public.safety_findings(id) ON DELETE SET NULL,
    source_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    description TEXT,
    data JSONB DEFAULT '{}'::jsonb NOT NULL,
    is_ai_generated BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_safety_evidence_analysis ON public.safety_evidence(analysis_id);

-- 4. SAFETY RECOMMENDATIONS (Proportional, actionable advice)
CREATE TABLE public.safety_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id UUID REFERENCES public.safety_analyses(id) ON DELETE CASCADE NOT NULL,
    action TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);
CREATE INDEX idx_safety_recommendations_analysis ON public.safety_recommendations(analysis_id);

-- 5. ROW LEVEL SECURITY (RLS)
-- Strict isolation: users can ONLY read their own safety analyses and associated findings
ALTER TABLE public.safety_analyses ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own safety analyses" 
    ON public.safety_analyses 
    FOR SELECT 
    USING (auth.uid() = user_id);

ALTER TABLE public.safety_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own safety findings" 
    ON public.safety_findings 
    FOR SELECT 
    USING (EXISTS (
        SELECT 1 FROM public.safety_analyses a 
        WHERE a.id = safety_findings.analysis_id 
        AND a.user_id = auth.uid()
    ));

ALTER TABLE public.safety_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own safety evidence" 
    ON public.safety_evidence 
    FOR SELECT 
    USING (EXISTS (
        SELECT 1 FROM public.safety_analyses a 
        WHERE a.id = safety_evidence.analysis_id 
        AND a.user_id = auth.uid()
    ));

ALTER TABLE public.safety_recommendations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own safety recommendations" 
    ON public.safety_recommendations 
    FOR SELECT 
    USING (EXISTS (
        SELECT 1 FROM public.safety_analyses a 
        WHERE a.id = safety_recommendations.analysis_id 
        AND a.user_id = auth.uid()
    ));

-- Normal users CANNOT insert, update, or delete safety records directly.
-- Server-side analysis services operate through authorized identity or service role.
