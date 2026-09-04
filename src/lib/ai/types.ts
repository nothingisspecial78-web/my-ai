export type Role = 'user' | 'assistant' | 'system';

export interface Message {
  id: string;
  conversation_id: string;
  user_id: string;
  role: Role;
  content: string;
  model?: string;
  provider?: string;
  input_tokens?: number;
  output_tokens?: number;
  metadata?: Record<string, unknown>;
  created_at: Date;
}

export interface Conversation {
  id: string;
  user_id: string;
  title: string;
  created_at: Date;
  updated_at: Date;
  deleted_at?: Date | null;
}

export type AIStreamStartEvent = {
  type: 'start';
};

export type AIStreamChunkEvent = {
  type: 'chunk';
  text: string;
};

export type AIStreamDoneEvent = {
  type: 'done';
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
  metadata?: {
    model: string;
    provider: string;
  };
};

export type AIStreamErrorEvent = {
  type: 'error';
  error: string;
};

export type AIStreamEvent = 
  | AIStreamStartEvent 
  | AIStreamChunkEvent 
  | AIStreamDoneEvent 
  | AIStreamErrorEvent;

export interface AIProvider {
  name: string;

  /**
   * Generates a stream of AIStreamEvents.
   * Can accept an optional AbortSignal to propagate cancellation.
   */
  generateStream(
    messages: Message[], 
    options?: { userId?: string; conversationId?: string; signal?: AbortSignal }
  ): AsyncGenerator<AIStreamEvent, void, unknown>;
}
