import { Message } from './types';

export interface ContextOptions {
  maxCharacters?: number;
}

/**
 * Prepares the conversation context by ensuring the total length
 * of messages does not exceed the budget.
 * 
 * Always includes the most recent user request.
 * Removes older messages first to fit within the limit.
 */
export function prepareContext(messages: Message[], options?: ContextOptions): Message[] {
  const maxCharacters = options?.maxCharacters || 30000;
  
  // Filter out empty or malformed messages
  const validMessages = messages.filter(
    msg => typeof msg.content === 'string' && msg.content.trim().length > 0
  );

  if (validMessages.length === 0) return [];
  
  const latestMessage = validMessages[validMessages.length - 1];
  let currentLength = latestMessage.content.length;
  
  const preservedMessages: Message[] = [latestMessage];
  
  // Iterate backwards starting from the second to last message
  for (let i = validMessages.length - 2; i >= 0; i--) {
    const msg = validMessages[i];
    if (currentLength + msg.content.length > maxCharacters) {
      break;
    }
    preservedMessages.unshift(msg);
    currentLength += msg.content.length;
  }
  
  return preservedMessages;
}
