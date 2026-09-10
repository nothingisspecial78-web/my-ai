-- Migration: Add Safety Checkup and Security Checkup system themes
-- Inserts the official system themes for the Safety and Security Analysis architecture

INSERT INTO public.themes (id, name, slug, description, icon, is_system, config)
VALUES
(
    '55555555-5555-5555-5555-555555555555',
    'Safety Checkup',
    'safety-checkup',
    'Analyze URLs, messages, links, and text for scams, phishing, and malware threats.',
    'ShieldCheck',
    true,
    '{"instructions": "You are a digital safety assistant. Review the provided deterministic safety analysis and explain the risk level, observable indicators, and actionable recommendations clearly to the user."}'::jsonb
),
(
    '66666666-6666-6666-6666-666666666666',
    'Security Checkup',
    'security-checkup',
    'Technical inspection of suspicious links, headers, code, and threat indicators.',
    'ShieldAlert',
    true,
    '{"instructions": "You are a cybersecurity expert. Provide technical risk breakdowns and defensive recommendations based on observable threat signals."}'::jsonb
)
ON CONFLICT (slug) DO NOTHING;
