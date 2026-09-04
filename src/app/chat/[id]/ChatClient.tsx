'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { Sparkles, Loader2, StopCircle } from 'lucide-react';
import { ChatComposer } from '@/components/chat/ChatComposer';
import { Message } from '@/components/chat/Message';
import { Database } from '@/types/database';
import { createMessage, replaceAssistantMessage, updateConversation } from '@/lib/database';
import { AIStreamEvent } from '@/lib/ai/types';
import { useChatPreferences } from '@/hooks/use-chat-preferences';
import { extractConversationTitle } from '@/lib/utilities/title';

type DBConversation = Database['public']['Tables']['conversations']['Row'];
type DBMessage = Database['public']['Tables']['messages']['Row'];

interface ChatClientProps {
  conversation: DBConversation;
  initialMessages: DBMessage[];
}

export function ChatClient({ conversation, initialMessages }: ChatClientProps) {
  const router = useRouter();
  const [messages, setMessages] = useState<DBMessage[]>(initialMessages);
  const [isSending, setIsSending] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  
  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  // Keep track of the original conversation slice being regenerated for safe rollback
  const regeneratingOriginalSliceRef = useRef<DBMessage[] | null>(null);
  // Track whether auto-title has been generated for this session
  const autoTitleDoneRef = useRef(false);

  const { preferences } = useChatPreferences();

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    // If the last message is from the user and we are not sending, generate a response automatically.
    // This handles the case where a new chat is created from the empty state and forwarded here.
    if (messages.length > 0 && messages[messages.length - 1].role === 'user' && !isSending && !isThinking) {
      triggerGeneration();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialMessages]);

  // Handle Escape key to stop generation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isSending) {
        e.preventDefault();
        stopGeneration();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSending]);

  const stopGeneration = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsSending(false);
    setIsThinking(false);
    setErrorMessage('Generation stopped.');
  };

  async function handleRegenerate(msgId: string) {
    if (isSending) return;
    setIsSending(true);
    
    const targetMsg = messages.find(m => m.id === msgId);
    if (!targetMsg || targetMsg.role !== 'assistant') return;

    triggerGeneration(msgId);
  }

  /**
   * Auto-title: Asynchronously derive and persist a title from the first user message.
   * Best-effort — failures do not affect message saving or generation.
   */
  async function maybeAutoTitle(userText: string) {
    if (autoTitleDoneRef.current) return;
    
    // Only auto-title if current title looks like a default/new conversation
    const currentTitle = conversation.title;
    const isDefaultTitle = currentTitle === 'New conversation';
    if (!isDefaultTitle) {
      autoTitleDoneRef.current = true;
      return;
    }

    autoTitleDoneRef.current = true;

    try {
      const newTitle = extractConversationTitle(userText);
      if (newTitle && newTitle !== 'New conversation') {
        await updateConversation(conversation.id, { title: newTitle });
        router.refresh();
      }
    } catch {
      // Title generation is best-effort. Failure does not affect anything else.
    }
  }

  async function triggerGeneration(regenerateMessageId?: string) {
    setIsSending(true);
    setIsThinking(true);
    setErrorMessage(null);

    const isRegen = Boolean(regenerateMessageId);

    if (isRegen) {
      const targetIndex = messages.findIndex(m => m.id === regenerateMessageId);
      if (targetIndex === -1) {
        setIsSending(false);
        setIsThinking(false);
        return;
      }
      const targetMessage = messages[targetIndex];
      regeneratingOriginalSliceRef.current = [...messages];
      // Optimistically truncate descendants and clear the target assistant message content
      setMessages(prev => [
        ...prev.slice(0, targetIndex),
        { ...targetMessage, content: '' }
      ]);
    }

    const tempAiId = isRegen && regenerateMessageId ? regenerateMessageId : `temp-ai-${Date.now()}`;
    let responseText = '';
    let usageMetadata: { input_tokens?: number, output_tokens?: number } | null = null;
    let modelMetadata: { model: string, provider: string } | null = null;
    let isError = false;
    let wasAborted = false;

    if (!isRegen) {
      // Optimistic AI Message (empty initially for normal send)
      const optimisticMsg: DBMessage = {
        id: tempAiId,
        conversation_id: conversation.id,
        user_id: conversation.user_id,
        role: 'assistant',
        content: '',
        metadata: {},
        created_at: new Date().toISOString(),
        model: null,
        provider: null,
        input_tokens: null,
        output_tokens: null,
      };
      
      setMessages(prev => [...prev, optimisticMsg]);
    }

    abortControllerRef.current = new AbortController();

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          conversationId: conversation.id,
          regenerateMessageId: isRegen ? regenerateMessageId : undefined,
        }),
        signal: abortControllerRef.current.signal,
      });

      if (!response.ok) {
        let errMsg = 'Failed to generate response';
        try {
          const errJson = await response.json();
          if (errJson.error) errMsg = errJson.error;
        } catch {
          // If not JSON, try text
          const errText = await response.text();
          if (errText) errMsg = errText;
        }
        throw new Error(errMsg);
      }

      setIsThinking(false);

      if (response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          
          // Parse NDJSON lines
          const lines = buffer.split('\n');
          buffer = lines.pop() || ''; // Keep the last incomplete line in buffer

          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              const event: AIStreamEvent = JSON.parse(line);
              
              if (event.type === 'start') {
                // stream started
              } else if (event.type === 'chunk') {
                responseText += event.text;
                // Update UI progressively
                setMessages(prev => prev.map(m => m.id === tempAiId ? { ...m, content: responseText } : m));
              } else if (event.type === 'done') {
                usageMetadata = event.usage || null;
                modelMetadata = event.metadata || null;
              } else if (event.type === 'error') {
                isError = true;
                throw new Error(event.error);
              }
            } catch (e) {
              if (isError) throw e;
              console.error('Failed to parse NDJSON line', line, e);
            }
          }
        }
      }
    } catch (err: unknown) {
      const isAbort = err instanceof Error && (err.name === 'AbortError' || err.message === 'Aborted by user');
      if (isAbort) {
        wasAborted = true;
      } else {
        console.error(err);
        isError = true;
        const msg = err instanceof Error ? err.message : 'Network Error';
        setErrorMessage(msg);
      }
    } finally {
      setIsSending(false);
      setIsThinking(false);
      abortControllerRef.current = null;

      if (isRegen && regenerateMessageId) {
        const originalSlice = regeneratingOriginalSliceRef.current;
        regeneratingOriginalSliceRef.current = null;

        if (wasAborted || isError || !responseText.trim()) {
          // Rollback UI to the original conversation slice
          if (originalSlice) {
            setMessages(originalSlice);
          }
        } else {
          // Success: update the assistant message in Supabase
          const updatedMsg = await replaceAssistantMessage(regenerateMessageId, {
            content: responseText,
            metadata: modelMetadata || {},
            model: modelMetadata?.model || null,
            provider: modelMetadata?.provider || null,
            input_tokens: usageMetadata?.input_tokens || null,
            output_tokens: usageMetadata?.output_tokens || null,
          });

          if (updatedMsg) {
            setMessages(prev => prev.map(m => m.id === regenerateMessageId ? updatedMsg : m));
            router.refresh();
          } else {
            // DB update failed: rollback UI
            if (originalSlice) {
              setMessages(originalSlice);
            }
            setErrorMessage('Failed to save regenerated response to database.');
          }
        }
      } else {
        // Normal Send persistence
        if (responseText.trim().length > 0 && !wasAborted && !isError) {
          const savedAiMsg = await createMessage({
            conversation_id: conversation.id,
            user_id: conversation.user_id,
            role: 'assistant',
            content: responseText,
            metadata: modelMetadata || {},
            model: modelMetadata?.model || null,
            provider: modelMetadata?.provider || null,
            input_tokens: usageMetadata?.input_tokens || null,
            output_tokens: usageMetadata?.output_tokens || null,
          });

          if (savedAiMsg) {
            setMessages(prev => prev.map(m => m.id === tempAiId ? savedAiMsg : m));
            router.refresh();
          }
        } else if (isError || wasAborted) {
          // If normal generation failed or was aborted, remove placeholder
          setMessages(prev => prev.filter(m => m.id !== tempAiId));
        }
      }
    }
  }

  const handleSend = async (text: string) => {
    if (!text.trim() || isSending) return;
    
    setIsSending(true);
    setErrorMessage(null);

    // 1. Optimistic User Message
    const tempUserId = `temp-user-${Date.now()}`;
    const userMsg: DBMessage = {
      id: tempUserId,
      conversation_id: conversation.id,
      user_id: conversation.user_id,
      role: 'user',
      content: text,
      metadata: {},
      created_at: new Date().toISOString(),
      model: null,
      provider: null,
      input_tokens: null,
      output_tokens: null,
    };
    
    setMessages(prev => [...prev, userMsg]);

    try {
      // 2. Persist User Message
      const savedUserMsg = await createMessage({
        conversation_id: conversation.id,
        role: 'user',
        content: text,
        metadata: {},
      });

      if (!savedUserMsg) throw new Error('Failed to save user message');

      setMessages(prev => prev.map(m => m.id === tempUserId ? savedUserMsg : m));
      
      // 3. Auto-title (best-effort, non-blocking — fire and forget)
      maybeAutoTitle(text);
      
      // 4. Trigger Generation (does NOT wait for title)
      // triggerGeneration will manage its own finally block to clear isSending
      triggerGeneration();
    } catch (err) {
      console.error(err);
      setMessages(prev => prev.filter(m => m.id !== tempUserId));
      setErrorMessage('Failed to send message. Please try again.');
      setIsSending(false);
    }
  };

  return (
    <div className="flex h-full w-full flex-col relative">
      <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-gray-200 dark:border-gray-800 bg-white/80 dark:bg-gray-900/80 px-4 backdrop-blur-md hidden md:flex">
        <div className="flex items-center gap-2">
          <h1 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate max-w-md">
            {conversation.title}
          </h1>
          {isThinking && <Loader2 size={12} className="animate-spin text-gray-400" />}
        </div>
        <div className="flex items-center gap-2">
          {isSending && (
            <button 
              onClick={stopGeneration}
              aria-label="Stop generation"
              className="flex items-center gap-1 text-xs font-medium text-gray-500 hover:text-gray-900 dark:hover:text-white transition-colors mr-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
            >
              <StopCircle size={14} /> Stop
            </button>
          )}
          <div className="flex items-center gap-1.5 rounded-full bg-blue-50 dark:bg-blue-900/20 px-2.5 py-1 border border-blue-100 dark:border-blue-800/30">
            <Sparkles size={14} className="text-blue-500" />
            <span className="text-xs font-medium text-blue-700 dark:text-blue-400">MyAI Premium</span>
          </div>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto w-full">
        <div className="flex flex-col pb-6">
          {messages.map((msg, idx) => (
            <Message 
              key={msg.id} 
              id={msg.id}
              role={msg.role as 'user' | 'assistant' | 'system'} 
              content={msg.content} 
              isLast={idx === messages.length - 1}
              onRegenerate={msg.role === 'assistant' ? handleRegenerate : undefined}
              timestamp={msg.created_at}
              showTimestamp={preferences.showTimestamps}
              isThinking={isThinking && msg.role === 'assistant' && msg.content === ''}
            />
          ))}
          {errorMessage && (
            <div className="mx-auto my-4 max-w-2xl px-4 w-full" role="alert" aria-live="assertive">
              <div className="rounded-md bg-red-50 p-4 dark:bg-red-900/30 border border-red-100 dark:border-red-800/50">
                <div className="flex">
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800 dark:text-red-300">
                      Error
                    </h3>
                    <div className="mt-2 text-sm text-red-700 dark:text-red-400">
                      <p>{errorMessage}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} className="h-px w-full" />
        </div>
      </div>

      <div className="w-full bg-gradient-to-t from-white via-white to-transparent dark:from-gray-900 dark:via-gray-900 dark:to-transparent mt-auto">
        <ChatComposer 
          onSend={handleSend} 
          disabled={isSending}
          enterToSend={preferences.enterToSend}
        />
      </div>
    </div>
  );
}
