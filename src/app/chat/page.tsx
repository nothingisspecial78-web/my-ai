'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChatComposer } from '@/components/chat/ChatComposer';
import { WelcomeScreen } from '@/components/chat/WelcomeScreen';
import { ThemeSelector } from '@/components/chat/ThemeSelector';
import { useChatPreferences } from '@/hooks/use-chat-preferences';
import { extractConversationTitle } from '@/lib/utilities/title';
import { CANONICAL_THEME_MAP, GENERAL_AI_THEME } from '@/lib/theme/catalog';

import { Attachment } from '@/lib/ai/types';
import { Json } from '@/types/database';

export default function ChatEmptyPage() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);
  const [selectedThemeId, setSelectedThemeId] = useState<string | null>(null);
  const { preferences } = useChatPreferences();

  const activeTheme = (selectedThemeId && CANONICAL_THEME_MAP[selectedThemeId]) || GENERAL_AI_THEME;

  const handleSend = async (text: string, attachments?: Attachment[]) => {
    if ((!text.trim() && (!attachments || attachments.length === 0)) || isNavigating) return;
    setIsNavigating(true);
    try {
      const { createConversation, createMessage } = await import('@/lib/database');
      
      let defaultTitle = 'New conversation';
      if (attachments && attachments.length > 0) {
        const firstType = attachments[0].type;
        if (firstType === 'pdf') defaultTitle = 'PDF Analysis';
        else if (firstType === 'html') defaultTitle = 'HTML Analysis';
        else if (firstType === 'text') defaultTitle = 'Document Analysis';
        else defaultTitle = 'Image Analysis';
      }
      const title = text.trim() ? extractConversationTitle(text) : defaultTitle;
      
      const newConvo = await createConversation(title, selectedThemeId || undefined);
      if (newConvo) {
        await createMessage({
          conversation_id: newConvo.id,
          role: 'user',
          content: text,
          metadata: attachments && attachments.length > 0 ? { attachments: attachments as unknown as Json } : {},
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
    <div data-theme={activeTheme.slug} className="flex h-full w-full flex-col relative bg-[var(--theme-bg)] transition-colors">
      <div className="flex-1 overflow-y-auto w-full">
        <WelcomeScreen onSuggestionClick={handleSend} disabled={isNavigating} theme={activeTheme} />
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
