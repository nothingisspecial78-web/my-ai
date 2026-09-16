-- Migration: Google Sheets Integration Architecture
-- Tables: user_google_sheets_integrations, safety_analysis_exports
-- Strictly bounded external analytics export destination

CREATE TABLE IF NOT EXISTS public.user_google_sheets_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'disconnected',
    spreadsheet_id TEXT,
    spreadsheet_name TEXT,
    sheet_name TEXT DEFAULT 'Security Telemetry',
    encrypted_refresh_token TEXT,
    token_iv TEXT,
    token_tag TEXT,
    last_synced_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_google_sheets_user ON public.user_google_sheets_integrations(user_id);

ALTER TABLE public.user_google_sheets_integrations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own google sheets integration"
    ON public.user_google_sheets_integrations
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own google sheets integration"
    ON public.user_google_sheets_integrations
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own google sheets integration"
    ON public.user_google_sheets_integrations
    FOR UPDATE
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own google sheets integration"
    ON public.user_google_sheets_integrations
    FOR DELETE
    USING (auth.uid() = user_id);

-- Durable idempotency tracking for external exports
CREATE TABLE IF NOT EXISTS public.safety_analysis_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    analysis_id TEXT NOT NULL,
    destination TEXT NOT NULL DEFAULT 'google_sheets',
    spreadsheet_id TEXT NOT NULL,
    sheet_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'exported',
    exported_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT uq_user_analysis_destination UNIQUE (user_id, analysis_id, destination)
);

CREATE INDEX IF NOT EXISTS idx_safety_analysis_exports_lookup ON public.safety_analysis_exports(user_id, analysis_id);

ALTER TABLE public.safety_analysis_exports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own exports"
    ON public.safety_analysis_exports
    FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own exports"
    ON public.safety_analysis_exports
    FOR INSERT
    WITH CHECK (auth.uid() = user_id);
