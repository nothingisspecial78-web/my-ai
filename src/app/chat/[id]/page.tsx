import { notFound } from 'next/navigation';
import { getConversation, getMessages } from '@/lib/database';
import { resolveAuthorizedTheme } from '@/lib/theme/resolver';
import { ChatClient } from './ChatClient';

export const dynamic = 'force-dynamic';
export default async function ChatIdPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  
  const conversation = await getConversation(id);
  
  if (!conversation) {
    notFound();
  }

  const messages = await getMessages(id);
  const theme = await resolveAuthorizedTheme(conversation.theme_id);

  return (
    <ChatClient
      key={conversation.id}
      conversation={conversation}
      initialMessages={messages}
      theme={theme}
    />
  );
}
