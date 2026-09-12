'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ChatComposer } from '@/components/chat/ChatComposer';
import { WelcomeScreen } from '@/components/chat/WelcomeScreen';
import { ThemeSelector } from '@/components/chat/ThemeSelector';
import { useChatPreferences } from '@/hooks/use-chat-preferences';
import { extractConversationTitle } from '@/lib/utilities/title';
import { CANONICAL_THEME_MAP, GENERAL_AI_THEME } from '@/lib/theme/catalog';
import { ChatClient } from './[id]/ChatClient';
import { createConversationWithMessage, createConversation, createMessage } from '@/lib/database';

import { Attachment } from '@/lib/ai/types';
import { Database, Json } from '@/types/database';

type DBConversation = Database['public']['Tables']['conversations']['Row'];
type DBMessage = Database['public']['Tables']['messages']['Row'];

export default function ChatEmptyPage() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);
  const [selectedThemeId, setSelectedThemeId] = useState<string | null>(null);
  const [optimisticMessage, setOptimisticMessage] = useState<{ text: string; attachments?: Attachment[] } | null>(null);
  const [activeSession, setActiveSession] = useState<{
    conversation: DBConversation;
    initialMessages: DBMessage[];
  } | null>(null);
  const { preferences } = useChatPreferences();

  const activeTheme = (selectedThemeId && CANONICAL_THEME_MAP[selectedThemeId]) || GENERAL_AI_THEME;

  const handleSend = async (text: string, attachments?: Attachment[]) => {
    if ((!text.trim() && (!attachments || attachments.length === 0)) || isNavigating) return;
    setIsNavigating(true);
    setOptimisticMessage({ text, attachments });
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }

    try {
      let defaultTitle = 'New conversation';
      if (attachments && attachments.length > 0) {
        const firstType = attachments[0].type;
        if (firstType === 'pdf') defaultTitle = 'PDF Analysis';
        else if (firstType === 'html') defaultTitle = 'HTML Analysis';
        else if (firstType === 'text') defaultTitle = 'Document Analysis';
        else defaultTitle = 'Image Analysis';
      }
      const title = text.trim() ? extractConversationTitle(text) : defaultTitle;
      const metadata = attachments && attachments.length > 0 ? { attachments: attachments as unknown as Json } : {};

      // Fast atomic database persistence in a single round-trip
      const result = await createConversationWithMessage({
        title,
        theme_id: selectedThemeId || undefined,
        content: text,
        metadata: attachments && attachments.length > 0 ? { attachments: attachments as unknown as Json } : {},
      });

      if (result) {
        // In-place transition without waiting for slow RSC page fetch
        setActiveSession({
          conversation: result.conversation,
          initialMessages: [result.message],
        });
        if (typeof window !== 'undefined') {
          window.history.replaceState(null, '', `/chat/${result.conversation.id}`);
        }
        router.refresh();
      } else {
        // Fallback to sequential creation
        const newConvo = await createConversation(title, selectedThemeId || undefined);
        if (newConvo) {
          const newMsg = await createMessage({
            conversation_id: newConvo.id,
            role: 'user',
            content: text,
            metadata: metadata,
          });
          if (newMsg) {
            setActiveSession({
              conversation: newConvo,
              initialMessages: [newMsg],
            });
            if (typeof window !== 'undefined') {
              window.history.replaceState(null, '', `/chat/${newConvo.id}`);
            }
            router.refresh();
          } else {
            router.push(`/chat/${newConvo.id}`);
          }
        }
      }
    } catch (e) {
      console.error(e);
      alert('Failed to start conversation.');
      setIsNavigating(false);
      setOptimisticMessage(null);
    }
  };

  // If a chat was started from this empty page, seamlessly render ChatClient in-place!
  if (activeSession) {
    return (
      <ChatClient
        conversation={activeSession.conversation}
        initialMessages={activeSession.initialMessages}
        theme={activeTheme}
      />
    );
  }

  return (
    <div data-theme={activeTheme.slug} className="flex h-full w-full flex-col relative bg-[var(--theme-bg)] transition-colors overflow-hidden">
      <div className="flex-1 min-h-0 overflow-y-auto w-full">
        {optimisticMessage ? (
          <div className="max-w-4xl mx-auto p-4 space-y-4">
            <div className="flex justify-end">
              <div className="bg-[var(--theme-bubble-user)] text-[var(--theme-bubble-user-text)] px-5 py-3 rounded-2xl rounded-br-sm shadow-sm max-w-[85%] text-[15px]">
                {optimisticMessage.text}
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-600 dark:text-cyan-400 p-2">
              <span className="animate-spin inline-block w-3 h-3 border-2 border-cyan-500 border-t-transparent rounded-full" />
              <span>Initializing Before You Click security scanner...</span>
            </div>
          </div>
        ) : (
          <WelcomeScreen onSuggestionClick={handleSend} disabled={isNavigating} theme={activeTheme} />
        )}
      </div>

      <div className="mt-auto w-full bg-gradient-to-t from-[var(--theme-bg)] via-[var(--theme-bg)] to-transparent shrink-0">
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
