'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChatComposer } from '@/components/chat/ChatComposer';
import { WelcomeScreen } from '@/components/chat/WelcomeScreen';
import { ThemeSelector } from '@/components/chat/ThemeSelector';
import { useChatPreferences } from '@/hooks/use-chat-preferences';
import { extractConversationTitle } from '@/lib/utilities/title';
import { CANONICAL_THEME_MAP } from '@/lib/theme/catalog';

export default function ChatEmptyPage() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);
  const [selectedThemeId, setSelectedThemeId] = useState<string | null>(null);
  const { preferences } = useChatPreferences();

  const activeThemeSlug = (selectedThemeId && CANONICAL_THEME_MAP[selectedThemeId]?.slug) || 'general';

  const handleSend = async (text: string) => {
    if (isNavigating) return;
    setIsNavigating(true);
    try {
      const { createConversation, createMessage } = await import('@/lib/database');
      
      const title = extractConversationTitle(text);
      
      const newConvo = await createConversation(title, selectedThemeId || undefined);
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
    <div data-theme={activeThemeSlug} className="flex h-full w-full flex-col relative bg-[var(--theme-bg)] transition-colors">
      <div className="flex-1 overflow-y-auto w-full">
        <WelcomeScreen onSuggestionClick={handleSend} disabled={isNavigating} />
      </div>

      <div className="mt-auto w-full bg-gradient-to-t from-[var(--theme-bg)] via-[var(--theme-bg)] to-transparent">
        <div className="max-w-3xl mx-auto px-4 pb-2 flex justify-start">
          <ThemeSelector 
            selectedThemeId={selectedThemeId} 
            onSelect={setSelectedThemeId} 
            disabled={isNavigating}
          />
        </div>
        <ChatComposer 
          onSend={handleSend} 
          disabled={isNavigating}
          enterToSend={preferences.enterToSend}
        />
      </div>
    </div>
  );
}
