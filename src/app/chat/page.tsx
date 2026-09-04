'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChatComposer } from '@/components/chat/ChatComposer';
import { WelcomeScreen } from '@/components/chat/WelcomeScreen';
import { useChatPreferences } from '@/hooks/use-chat-preferences';
import { extractConversationTitle } from '@/lib/utilities/title';

export default function ChatEmptyPage() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);
  const { preferences } = useChatPreferences();

  const handleSend = async (text: string) => {
    if (isNavigating) return;
    setIsNavigating(true);
    try {
      const { createConversation, createMessage } = await import('@/lib/database');
      
      const title = extractConversationTitle(text);
      
      const newConvo = await createConversation(title);
      if (newConvo) {
        await createMessage({
          conversation_id: newConvo.id,
          role: 'user',
          content: text,
          metadata: {},
        });
        
        router.push(`/chat/${newConvo.id}`);
      }
    } catch (e) {
      console.error(e);
      alert('Failed to start conversation.');
      setIsNavigating(false);
    }
  };

  return (
    <div className="flex h-full w-full flex-col relative">
      <div className="flex-1 overflow-y-auto w-full">
        <WelcomeScreen onSuggestionClick={handleSend} disabled={isNavigating} />
      </div>

      <div className="mt-auto w-full bg-gradient-to-t from-white via-white to-transparent dark:from-gray-900 dark:via-gray-900 dark:to-transparent">
        <ChatComposer 
          onSend={handleSend} 
          disabled={isNavigating}
          enterToSend={preferences.enterToSend}
        />
      </div>
    </div>
  );
}
