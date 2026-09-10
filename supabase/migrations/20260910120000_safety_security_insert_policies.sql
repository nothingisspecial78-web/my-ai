-- Additive RLS policies for Safety & Security tables
-- Allows authenticated users (via SSR server client) to insert records matching their authenticated user_id

CREATE POLICY "Users can insert own safety analyses"
    ON public.safety_analyses
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can insert own safety findings"
    ON public.safety_findings
    FOR INSERT
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.safety_analyses a
        WHERE a.id = safety_findings.analysis_id
        AND a.user_id = auth.uid()
    ));

CREATE POLICY "Users can insert own safety evidence"
    ON public.safety_evidence
    FOR INSERT
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.safety_analyses a
        WHERE a.id = safety_evidence.analysis_id
        AND a.user_id = auth.uid()
    ));

CREATE POLICY "Users can insert own safety recommendations"
    ON public.safety_recommendations
    FOR INSERT
    WITH CHECK (EXISTS (
        SELECT 1 FROM public.safety_analyses a
        WHERE a.id = safety_recommendations.analysis_id
        AND a.user_id = auth.uid()
    ));
