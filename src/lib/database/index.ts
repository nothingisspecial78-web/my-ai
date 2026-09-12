'use server';

import { createClient } from '@/lib/supabase/server';
import { Database } from '@/types/database';
import { SupabaseClient } from '@supabase/supabase-js';
import { unstable_noStore as noStore } from 'next/cache';

type Profile = Database['public']['Tables']['profiles']['Row'];
type Conversation = Database['public']['Tables']['conversations']['Row'];
type Message = Database['public']['Tables']['messages']['Row'];

export async function getProfile(userId: string): Promise<Profile | null> {
  noStore();
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', userId)
    .single();

  if (error) {
    console.error('Error fetching profile:', error);
    return null;
  }
  return data;
}

export async function getConversations(): Promise<Conversation[]> {
  noStore();
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('conversations')
    .select('*')
    .is('deleted_at', null)
    .order('updated_at', { ascending: false });

  if (error) {
    console.error('Error fetching conversations:', error);
    return [];
  }
  return data;
}

export async function getPaginatedConversations(
  limit: number = 20,
  cursor?: string
): Promise<{ data: Conversation[]; nextCursor: string | null }> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  
  let query = supabase
    .from('conversations')
    .select('*')
    .is('deleted_at', null)
    .order('updated_at', { ascending: false })
    .limit(limit);

  if (cursor) {
    query = query.lt('updated_at', cursor);
  }

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching paginated conversations:', error);
    return { data: [], nextCursor: null };
  }

  const nextCursor = data.length === limit ? data[data.length - 1].updated_at : null;
  return { data, nextCursor };
}

export async function searchConversations(query: string, limit: number = 20): Promise<Conversation[]> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user || !query.trim()) return [];

  const sanitizedQuery = `%${query.trim().replace(/[%_]/g, '\\$&')}%`;

  // We want conversations matching the title, OR conversations containing messages matching the query.
  // We can do this efficiently using a subquery for messages.
  // Note: For V1, ilike is acceptable. For V2, we would use full-text search.
  const { data, error } = await supabase
    .from('conversations')
    .select('*, messages!inner(content)')
    .is('deleted_at', null)
    .or(`title.ilike.${sanitizedQuery},messages.content.ilike.${sanitizedQuery}`)
    .order('updated_at', { ascending: false })
    .limit(limit);

  if (error) {
    // If the inner join approach is too complex for the current schema or RLS,
    // fallback to a safe title-only search to avoid breaking the app.
    console.warn('Search with messages failed, falling back to title search', error);
    const fallback = await supabase
      .from('conversations')
      .select('*')
      .is('deleted_at', null)
      .ilike('title', sanitizedQuery)
      .order('updated_at', { ascending: false })
      .limit(limit);
      
    return fallback.data || [];
  }
  
  // The join might return duplicate conversations if multiple messages match.
  // We must deduplicate them by ID.
  const uniqueConversations = Array.from(new Map(data.map(c => [c.id, {
    id: c.id,
    created_at: c.created_at,
    updated_at: c.updated_at,
    title: c.title,
    user_id: c.user_id,
    theme_id: c.theme_id,
    deleted_at: c.deleted_at
  }])).values());

  return uniqueConversations;
}

export async function getConversation(conversationId: string): Promise<Conversation | null> {
  noStore();
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('conversations')
    .select('*')
    .eq('id', conversationId)
    .is('deleted_at', null)
    .single();

  if (error) {
    console.error('Error fetching conversation:', error);
    return null;
  }
  return data;
}

export async function createConversation(title: string, theme_id?: string): Promise<Conversation | null> {
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();
  
  if (!user) return null;

  const { data, error } = await supabase
    .from('conversations')
    .insert({
      user_id: user.id,
      title,
      theme_id: theme_id || null,
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating conversation:', error);
    return null;
  }
  return data;
}

export async function createConversationWithMessage(params: {
  title: string;
  theme_id?: string;
  content: string;
  metadata?: Database['public']['Tables']['messages']['Insert']['metadata'];
}): Promise<{ conversation: Conversation; message: Message } | null> {
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) return null;

  const { data: conversation, error: convoError } = await supabase
    .from('conversations')
    .insert({
      user_id: user.id,
      title: params.title,
      theme_id: params.theme_id || null,
    })
    .select()
    .single();

  if (convoError || !conversation) {
    console.error('Error creating conversation:', convoError);
    return null;
  }

  const { data: message, error: msgError } = await supabase
    .from('messages')
    .insert({
      conversation_id: conversation.id,
      user_id: user.id,
      role: 'user',
      content: params.content,
      metadata: params.metadata || {},
    })
    .select()
    .single();

  if (msgError || !message) {
    console.error('Error creating initial message:', msgError);
    return null;
  }

  return { conversation, message };
}

export async function updateConversation(conversationId: string, updates: Partial<Database['public']['Tables']['conversations']['Update']>): Promise<Conversation | null> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('conversations')

    .update({ ...updates, updated_at: new Date().toISOString() })
    .eq('id', conversationId)
    .select()
    .single();

  if (error) {
    console.error('Error updating conversation:', error);
    return null;
  }
  return data;
}

export async function deleteConversation(conversationId: string): Promise<boolean> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { error } = await supabase
    .from('conversations')

    .update({ deleted_at: new Date().toISOString() })
    .eq('id', conversationId);

  if (error) {
    console.error('Error soft deleting conversation:', error);
    return false;
  }
  return true;
}


export async function getMessages(conversationId: string): Promise<Message[]> {
  noStore();
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('messages')
    .select('*')
    .eq('conversation_id', conversationId)
    .order('created_at', { ascending: true });

  if (error) {
    console.error('Error fetching messages:', error);
    return [];
  }
  return data;
}

export async function createMessage(
  message: Omit<Database['public']['Tables']['messages']['Insert'], 'user_id'> & { user_id?: string }
): Promise<Message | null> {
  console.log("=== CREATE MESSAGE CALLED ===", message.role, message.content.substring(0, 50));
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    console.error('createMessage: unauthorized');
    return null;
  }
  
  // Note: RLS policies will handle verifying conversation ownership
  // Force user_id to match the authenticated user
  const secureMessage = {
    ...message,
    user_id: user.id
  };

  const { data, error } = await supabase
    .from('messages')
    .insert(secureMessage)
    .select()
    .single();

  if (error) {
    console.error('Error creating message:', error);
    return null;
  }
  
  // The database trigger 'update_conversation_timestamp' will automatically
  // bump the conversation's updated_at timestamp on insert.

  return data;
}

export async function deleteMessage(messageId: string): Promise<boolean> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  
  // Note: RLS policies ("Users can delete own messages") will handle verifying ownership
  const { error } = await supabase
    .from('messages')
    .delete()
    .eq('id', messageId);

  if (error) {
    console.error('Error deleting message:', error);
    return false;
  }
  
  return true;
}

export async function replaceAssistantMessage(
  messageId: string,
  updates: {
    content: string;
    model?: string | null;
    provider?: string | null;
    input_tokens?: number | null;
    output_tokens?: number | null;
    metadata?: Database['public']['Tables']['messages']['Update']['metadata'];
  }
): Promise<Message | null> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    console.error('replaceAssistantMessage unauthorized: no session');
    return null;
  }

  // 1. Fetch and verify message ownership and assistant role
  const { data: message, error: fetchError } = await supabase
    .from('messages')
    .select('*')
    .eq('id', messageId)
    .eq('user_id', user.id)
    .eq('role', 'assistant')
    .single();

  if (fetchError || !message) {
    console.error('replaceAssistantMessage verification failed: message not found or not owned assistant message');
    return null;
  }

  // 2. Verify parent conversation ownership and non-deleted status
  const conversation = await getConversation(message.conversation_id);
  if (!conversation || conversation.user_id !== user.id) {
    console.error('replaceAssistantMessage verification failed: parent conversation unauthorized or deleted');
    return null;
  }

  // 3. Delete any stale descendant messages in this conversation created after this assistant message
  const { error: descendantDeleteError } = await supabase
    .from('messages')
    .delete()
    .eq('conversation_id', message.conversation_id)
    .eq('user_id', user.id)
    .gt('created_at', message.created_at);

  if (descendantDeleteError) {
    console.error('Error deleting descendant messages during replace:', descendantDeleteError);
  }

  // 4. Update the message
  const { data, error } = await supabase
    .from('messages')
    .update({
      content: updates.content,
      model: updates.model ?? null,
      provider: updates.provider ?? null,
      input_tokens: updates.input_tokens ?? null,
      output_tokens: updates.output_tokens ?? null,
      metadata: updates.metadata ?? {},
    })
    .eq('id', messageId)
    .eq('user_id', user.id)
    .eq('role', 'assistant')
    .select()
    .single();

  if (error) {
    console.error('Error replacing assistant message:', error);
    return null;
  }

  // 5. Update parent conversation updated_at
  await updateConversation(message.conversation_id, {});

  return data;
}

export async function updateProfile(
  updates: {
    full_name?: string | null;
    avatar_url?: string | null;
  }
): Promise<Profile | null> {
  
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    console.error('updateProfile: unauthorized');
    return null;
  }

  // Server-side validation and normalization
  const sanitized: { full_name?: string | null; avatar_url?: string | null; updated_at: string } = {
    updated_at: new Date().toISOString(),
  };

  if ('full_name' in updates) {
    if (updates.full_name === null) {
      sanitized.full_name = null;
    } else if (typeof updates.full_name === 'string') {
      const trimmed = updates.full_name.trim().substring(0, 100);
      sanitized.full_name = trimmed || null;
    }
  }

  if ('avatar_url' in updates) {
    if (updates.avatar_url === null) {
      sanitized.avatar_url = null;
    } else if (typeof updates.avatar_url === 'string') {
      const trimmed = updates.avatar_url.trim().substring(0, 500);
      // Basic URL validation
      if (trimmed && (trimmed.startsWith('https://') || trimmed.startsWith('http://'))) {
        sanitized.avatar_url = trimmed;
      } else {
        sanitized.avatar_url = null;
      }
    }
  }

  // RLS ensures auth.uid() = id
  const { data, error } = await supabase
    .from('profiles')
    .update(sanitized)
    .eq('id', user.id)
    .select()
    .single();

  if (error) {
    console.error('Error updating profile:', error);
    return null;
  }

  return data;
}


export async function getThemes() {
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('themes')
    .select('*')
    .eq('enabled', true)
    .eq('is_system', true)
    .order('name');
  
  if (error) {
    console.error('Error fetching themes:', error);
    return [];
  }
  return data;
}

export async function getThemeById(id: string) {
  const supabase = (await createClient()) as SupabaseClient<Database>;
  const { data, error } = await supabase
    .from('themes')
    .select('*')
    .eq('id', id)
    .single();
    
  if (error) {
    console.error('Error fetching theme:', error);
    return null;
  }
  return data;
}
