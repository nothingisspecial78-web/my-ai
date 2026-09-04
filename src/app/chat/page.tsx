'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Sparkles, BookOpen, PenTool, Code } from 'lucide-react';
import { ChatComposer } from '@/components/chat/ChatComposer';
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
      
      // Derive a deterministic title from the user's first prompt
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
        router.refresh();
      }
    } catch (e) {
      console.error(e);
      alert('Failed to start conversation.');
      setIsNavigating(false);
    }
  };

  const suggestions = [
    { title: 'Explain something', icon: <Sparkles size={18} className="text-blue-500" /> },
    { title: 'Help me learn', icon: <BookOpen size={18} className="text-green-500" /> },
    { title: 'Help me code', icon: <Code size={18} className="text-purple-500" /> },
    { title: 'Write something', icon: <PenTool size={18} className="text-amber-500" /> },
  ];

  return (
    <div className="flex h-full w-full flex-col relative">
      <div className="flex-1 overflow-y-auto px-4 flex flex-col items-center justify-center">
        
        <div className="max-w-2xl w-full text-center space-y-8 fade-in-up">
          {/* Hero */}
          <div className="space-y-4">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-500 text-white shadow-lg shadow-blue-500/20">
              <Sparkles size={32} />
            </div>
            <h1 className="text-4xl md:text-5xl font-semibold tracking-tight text-gray-900 dark:text-white">
              Welcome to MyAI
            </h1>
            <p className="text-lg text-gray-500 dark:text-gray-400 max-w-md mx-auto">
              Your intelligent assistant for learning, creating and exploring.
            </p>
          </div>

          {/* Suggestions Grid */}
          <div className="pt-8">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">What would you like to do?</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-w-xl mx-auto">
              {suggestions.map((s, i) => (
                <button
                  key={i}
                  onClick={() => handleSend(s.title)}
                  disabled={isNavigating}
                  className="flex items-center gap-3 p-4 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900/50 hover:bg-gray-50 dark:hover:bg-gray-800 hover:border-blue-300 dark:hover:border-blue-800 transition-all text-left group"
                >
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gray-100 dark:bg-gray-800 group-hover:scale-110 transition-transform">
                    {s.icon}
                  </div>
                  <div className="font-medium text-gray-900 dark:text-gray-100">{s.title}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

      </div>

      <div className="mt-auto w-full bg-gradient-to-t from-white via-white to-transparent dark:from-gray-900 dark:via-gray-900 dark:to-transparent">
        <ChatComposer 
          onSend={handleSend} 
          disabled={isNavigating}
          enterToSend={preferences.enterToSend}
        />
      </div>

      <style jsx>{`
        .fade-in-up {
          animation: fadeInUp 0.6s ease-out forwards;
        }
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
