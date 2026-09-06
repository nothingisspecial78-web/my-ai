-- Create themes table
CREATE TABLE public.themes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT,
    icon TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    is_system BOOLEAN NOT NULL DEFAULT false,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- RLS
ALTER TABLE public.themes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view enabled system themes"
    ON public.themes FOR SELECT
    USING (auth.role() = 'authenticated' AND enabled = true AND is_system = true);

-- Update conversations table to link to themes
ALTER TABLE public.conversations
    ADD COLUMN theme_id UUID REFERENCES public.themes(id) ON DELETE SET NULL;

CREATE INDEX idx_conversations_theme_id ON public.conversations(theme_id);

-- Insert Demo Themes
INSERT INTO public.themes (id, name, slug, description, icon, is_system, config)
VALUES
(
    '11111111-1111-1111-1111-111111111111',
    'General AI',
    'general',
    'Standard versatile AI assistant.',
    'Globe',
    true,
    '{"instructions": "You are a helpful general-purpose AI assistant."}'::jsonb
),
(
    '22222222-2222-2222-2222-222222222222',
    'Mathematics',
    'mathematics',
    'Strict mathematical reasoning and step-by-step proofs.',
    'Calculator',
    true,
    '{"instructions": "You are an expert mathematical engine. Always provide step-by-step proofs, formulas, and exact calculations.", "rules": ["Never guess arithmetic", "Always show working"]}'::jsonb
),
(
    '33333333-3333-3333-3333-333333333333',
    'Programming',
    'programming',
    'Software engineering, debugging, and code generation.',
    'Code',
    true,
    '{"instructions": "You are an expert software engineer. Provide concise code, best practices, and security-first logic.", "rules": ["Use TypeScript where applicable", "Do not omit important imports"]}'::jsonb
),
(
    '44444444-4444-4444-4444-444444444444',
    'Study',
    'study',
    'Socratic tutor that helps you learn without giving away direct answers.',
    'BookOpen',
    true,
    '{"instructions": "You are a Socratic tutor. Guide the student to the answer using questions and hints.", "rules": ["Do not give the direct answer immediately", "Ask probing questions"]}'::jsonb
);
