-- Phase 1: Shared Conversations Schema

CREATE TABLE shared_conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_conversation_id UUID REFERENCES conversations(id) ON DELETE SET NULL,
  owner_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  messages JSONB NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX idx_shared_conversations_slug ON shared_conversations(slug);

ALTER TABLE shared_conversations ENABLE ROW LEVEL SECURITY;

-- Owner policies
CREATE POLICY "Users can insert own shared conversations" 
  ON shared_conversations FOR INSERT 
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY "Users can view own shared conversations" 
  ON shared_conversations FOR SELECT 
  USING (auth.uid() = owner_id);

CREATE POLICY "Users can delete own shared conversations" 
  ON shared_conversations FOR DELETE 
  USING (auth.uid() = owner_id);

-- Secure Public Access Mechanism
-- Instead of a blanket RLS policy (USING true), we use a SECURITY DEFINER function.
-- This function bypasses RLS but only returns specific safe columns (title, messages, created_at)
-- for a specific slug. It completely hides owner_id, original_conversation_id, and id.
CREATE OR REPLACE FUNCTION get_shared_conversation_public(p_slug TEXT)
RETURNS TABLE (
  title TEXT,
  messages JSONB,
  created_at TIMESTAMP WITH TIME ZONE
)
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN QUERY
  SELECT s.title, s.messages, s.created_at
  FROM shared_conversations s
  WHERE s.slug = p_slug;
END;
$$ LANGUAGE plpgsql;
