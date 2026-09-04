-- Allow users to update their own assistant messages within their own non-deleted conversations
DROP POLICY IF EXISTS "Users can update own messages" ON messages;
DROP POLICY IF EXISTS "Users can update own assistant messages" ON messages;

CREATE POLICY "Users can update own assistant messages"
  ON messages FOR UPDATE
  USING (
    auth.uid() = user_id AND
    role = 'assistant' AND
    EXISTS (
      SELECT 1 FROM conversations
      WHERE conversations.id = messages.conversation_id
      AND conversations.user_id = auth.uid()
      AND conversations.deleted_at IS NULL
    )
  )
  WITH CHECK (
    auth.uid() = user_id AND
    role = 'assistant' AND
    EXISTS (
      SELECT 1 FROM conversations
      WHERE conversations.id = messages.conversation_id
      AND conversations.user_id = auth.uid()
      AND conversations.deleted_at IS NULL
    )
  );
