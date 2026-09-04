'use client';

import { useSyncExternalStore, useCallback } from 'react';

interface ChatPreferences {
  enterToSend: boolean;
  showTimestamps: boolean;
}

const STORAGE_KEY = 'myai-chat-preferences';

const DEFAULTS: ChatPreferences = {
  enterToSend: true,
  showTimestamps: false,
};

function readPreferences(): ChatPreferences {
  if (typeof window === 'undefined') return DEFAULTS;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw);
    return {
      enterToSend: typeof parsed.enterToSend === 'boolean' ? parsed.enterToSend : DEFAULTS.enterToSend,
      showTimestamps: typeof parsed.showTimestamps === 'boolean' ? parsed.showTimestamps : DEFAULTS.showTimestamps,
    };
  } catch {
    return DEFAULTS;
  }
}

function writePreferences(prefs: ChatPreferences): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // localStorage may be full or unavailable
  }
}

// Module-level store for useSyncExternalStore
let listeners: Array<() => void> = [];
let cachedSnapshot: ChatPreferences | null = null;

function emitChange() {
  cachedSnapshot = null; // invalidate cache so getSnapshot re-reads
  for (const listener of listeners) {
    listener();
  }
}

function subscribe(listener: () => void) {
  listeners = [...listeners, listener];
  return () => {
    listeners = listeners.filter(l => l !== listener);
  };
}

function getSnapshot(): ChatPreferences {
  if (cachedSnapshot === null) {
    cachedSnapshot = readPreferences();
  }
  return cachedSnapshot;
}

function getServerSnapshot(): ChatPreferences {
  return DEFAULTS;
}

export function useChatPreferences() {
  const preferences = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const setPreferences = useCallback((update: Partial<ChatPreferences>) => {
    const current = readPreferences();
    const next = { ...current, ...update };
    writePreferences(next);
    emitChange();
  }, []);

  return {
    preferences,
    setPreferences,
  };
}
