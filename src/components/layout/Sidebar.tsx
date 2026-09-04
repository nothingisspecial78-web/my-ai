'use client';

import { useState, useMemo, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { 
  MessageSquare, 
  Plus, 
  Search, 
  Settings, 
  LogOut, 
  Menu,
  X,
  PanelLeftClose,
  PanelLeftOpen,
  Edit2,
  Trash2,
  Loader2
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { createClient } from '@/lib/supabase/client';
import { SettingsModal } from '@/components/settings/SettingsModal';
import { Database } from '@/types/database';
import { groupConversations } from '@/lib/utilities/date';
import { getPaginatedConversations, createConversation, updateConversation, deleteConversation, searchConversations } from '@/lib/database';

type Conversation = Database['public']['Tables']['conversations']['Row'];

export function Sidebar({ className, initialConversations = [], initialCursor = null }: { className?: string, initialConversations?: Conversation[], initialCursor?: string | null }) {
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Conversation[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  
  const [isCreating, setIsCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState('');
  
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  
  const [conversations, setConversations] = useState<Conversation[]>(initialConversations);
  const [cursor, setCursor] = useState<string | null>(initialCursor);
  const [prevInitial, setPrevInitial] = useState(initialConversations);
  const [isLoadingMore, setIsLoadingMore] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);

  // Sync with server component refreshes without useEffect
  if (initialConversations !== prevInitial) {
    setPrevInitial(initialConversations);
    setConversations(initialConversations);
    setCursor(initialCursor || null);
  }

  const pathname = usePathname();
  const router = useRouter();

  // Move handleNewChat before useEffect
  const handleNewChat = async () => {
    if (isCreating) return;
    setIsCreating(true);
    try {
      const newConvo = await createConversation('New conversation');
      if (newConvo) {
        setConversations(prev => [newConvo, ...prev]);
        router.push(`/chat/${newConvo.id}`);
        router.refresh();
      }
    } finally {
      setIsCreating(false);
    }
  };

  // Keyboard Shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl/Cmd + K
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isCollapsed) setIsCollapsed(false);
        if (!isMobileOpen && window.innerWidth < 768) setIsMobileOpen(true);
        setTimeout(() => searchInputRef.current?.focus(), 50);
      }
      // Ctrl/Cmd + Shift + O
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        handleNewChat();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isCollapsed, isMobileOpen]);

  // Debounced Search
  useEffect(() => {
    if (!searchQuery.trim()) {
      setTimeout(() => {
        setSearchResults([]);
        setIsSearching(false);
      }, 0);
      return;
    }
    
    const timeoutId = setTimeout(async () => {
      setIsSearching(true);
      try {
        const results = await searchConversations(searchQuery);
        setSearchResults(results);
      } catch (err) {
        console.error(err);
      } finally {
        setIsSearching(false);
      }
    }, 400);

    return () => clearTimeout(timeoutId);
  }, [searchQuery]);

  const handleLogout = async () => {
    const supabase = createClient();
    await supabase.auth.signOut();
    router.push('/login');
  };

  const handleDelete = async (id: string) => {
    const success = await deleteConversation(id);
    if (success) {
      setConversations(prev => prev.filter(c => c.id !== id));
      setSearchResults(prev => prev.filter(c => c.id !== id));
    }
    setDeleteConfirmId(null);
    if (pathname === `/chat/${id}`) {
      router.push('/chat');
    }
    router.refresh();
  };

  const handleRenameStart = (id: string, currentTitle: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setEditingId(id);
    setEditTitle(currentTitle);
    setDeleteConfirmId(null);
  };

  const handleRenameSubmit = async (id: string) => {
    if (!editTitle.trim()) {
      setEditingId(null);
      return;
    }
    setEditingId(null);
    const updated = await updateConversation(id, { title: editTitle });
    if (updated) {
      setConversations(prev => prev.map(c => c.id === id ? updated : c));
      setSearchResults(prev => prev.map(c => c.id === id ? updated : c));
    }
    router.refresh();
  };

  const handleLoadMore = async () => {
    if (!cursor || isLoadingMore) return;
    setIsLoadingMore(true);
    try {
      const res = await getPaginatedConversations(30, cursor);
      setConversations(prev => [...prev, ...res.data]);
      setCursor(res.nextCursor);
    } finally {
      setIsLoadingMore(false);
    }
  };

  const grouped = useMemo(() => groupConversations(conversations), [conversations]);

  const activeDisplayList = searchQuery.trim() ? searchResults : [];

  const SidebarContent = (
    <div className="flex h-full w-full flex-col bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800 transition-colors duration-200">
      {/* Header */}
      <div className="flex items-center justify-between p-4">
        <Link href="/chat" className={cn("flex items-center gap-2 font-semibold text-lg text-gray-900 dark:text-white transition-opacity", isCollapsed && "opacity-0 md:hidden")}>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 text-white">
            <span className="font-bold">M</span>
          </div>
          MyAI
        </Link>
        <button 
          onClick={() => setIsCollapsed(!isCollapsed)}
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="hidden md:flex h-8 w-8 items-center justify-center rounded-md text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          {isCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
        <button 
          onClick={() => setIsMobileOpen(false)}
          aria-label="Close sidebar menu"
          className="md:hidden flex h-8 w-8 items-center justify-center rounded-md text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <X size={20} />
        </button>
      </div>

      {/* New Chat & Search */}
      <div className="px-3 pb-4 space-y-2">
        <button 
          onClick={handleNewChat}
          disabled={isCreating}
          aria-label="New chat"
          className={cn("flex w-full items-center gap-2 rounded-lg bg-white dark:bg-gray-900 px-3 py-2.5 text-sm font-medium text-gray-900 dark:text-white shadow-sm border border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500", isCollapsed && "justify-center md:px-0")}
        >
          {isCreating ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
          {!isCollapsed && <span>New Chat</span>}
        </button>
        
        {!isCollapsed && (
          <div className="relative group">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-blue-500 transition-colors" />
            <input 
              ref={searchInputRef}
              type="text" 
              placeholder="Search chats..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 py-2 pl-9 pr-8 text-sm text-gray-900 dark:text-white placeholder:text-gray-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
              >
                <X size={14} />
              </button>
            )}
          </div>
        )}
      </div>

      {/* Conversation List */}
      <div className="flex-1 overflow-y-auto px-3 py-2 scrollbar-thin scrollbar-thumb-gray-300 dark:scrollbar-thumb-gray-700">
        {!isCollapsed ? (
          searchQuery.trim() ? (
            <div className="space-y-1">
              {isSearching ? (
                <div className="flex justify-center p-4 text-gray-500">
                  <Loader2 size={18} className="animate-spin" />
                </div>
              ) : activeDisplayList.length === 0 ? (
                <div className="text-center p-4 text-sm text-gray-500">
                  No conversations found
                </div>
              ) : (
                <>
                  <h3 className="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Search Results</h3>
                  {activeDisplayList.map(chat => (
                    <Link
                      key={chat.id}
                      href={`/chat/${chat.id}`}
                      className={cn(
                        "flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors",
                        pathname === `/chat/${chat.id}` && "bg-gray-200 dark:bg-gray-800 font-medium text-gray-900 dark:text-white"
                      )}
                    >
                      <MessageSquare size={16} className="shrink-0 opacity-70" />
                      <span className="truncate">{chat.title}</span>
                    </Link>
                  ))}
                </>
              )}
            </div>
          ) : (
            <div className="space-y-6">
              {(['Today', 'Yesterday', 'Previous 7 Days', 'Older'] as const).map((groupName) => {
                const items = grouped[groupName];
                if (items.length === 0) return null;
                
                return (
                  <div key={groupName} className="space-y-1">
                    <h3 className="px-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{groupName}</h3>
                    {items.map(chat => (
                      <div key={chat.id} className="group relative flex items-center">
                        {editingId === chat.id ? (
                          <div className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 bg-white dark:bg-gray-900 border border-blue-500">
                            <MessageSquare size={16} className="shrink-0 opacity-70 text-gray-400" />
                            <input 
                              autoFocus
                              className="flex-1 bg-transparent text-sm text-gray-900 dark:text-white focus:outline-none min-w-0"
                              value={editTitle}
                              onChange={(e) => setEditTitle(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') handleRenameSubmit(chat.id);
                                if (e.key === 'Escape') setEditingId(null);
                              }}
                              onBlur={() => handleRenameSubmit(chat.id)}
                            />
                          </div>
                        ) : deleteConfirmId === chat.id ? (
                          <div className="flex w-full items-center justify-between gap-2 rounded-lg px-2 py-2 bg-red-50 dark:bg-red-900/20 text-sm">
                            <span className="text-red-700 dark:text-red-400 truncate">Delete chat?</span>
                            <div className="flex items-center gap-2 shrink-0">
                              <button onClick={() => handleDelete(chat.id)} className="text-red-700 dark:text-red-400 hover:underline font-medium">Yes</button>
                              <button onClick={() => setDeleteConfirmId(null)} className="text-gray-600 dark:text-gray-400 hover:underline">No</button>
                            </div>
                          </div>
                        ) : (
                          <Link
                            href={`/chat/${chat.id}`}
                            className={cn(
                              "flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors pr-14 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
                              pathname === `/chat/${chat.id}` && "bg-gray-200 dark:bg-gray-800 font-medium text-gray-900 dark:text-white"
                            )}
                          >
                            <MessageSquare size={16} className="shrink-0 opacity-70" />
                            <span className="truncate">{chat.title}</span>
                          </Link>
                        )}
                        
                        {editingId !== chat.id && deleteConfirmId !== chat.id && (
                          <div className="absolute right-2 flex items-center opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity">
                            <button 
                              onClick={(e) => handleRenameStart(chat.id, chat.title, e)}
                              aria-label="Rename conversation"
                              className="p-1 text-gray-400 hover:text-gray-900 dark:hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                            >
                              <Edit2 size={14} />
                            </button>
                            <button 
                              onClick={(e) => { e.preventDefault(); e.stopPropagation(); setDeleteConfirmId(chat.id); }}
                              aria-label="Delete conversation"
                              className="p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              
              {cursor && !searchQuery.trim() && (
                <div className="pt-2 pb-4 flex justify-center">
                  <button
                    onClick={handleLoadMore}
                    disabled={isLoadingMore}
                    className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 disabled:opacity-50 transition-colors focus:outline-none focus-visible:underline"
                  >
                    {isLoadingMore ? 'Loading...' : 'Load more'}
                  </button>
                </div>
              )}
            </div>
          )
        ) : (
          <div className="space-y-2 flex flex-col items-center">
             {conversations.slice(0, 10).map(chat => (
                <Link
                  key={chat.id}
                  href={`/chat/${chat.id}`}
                  className={cn(
                    "flex h-10 w-10 items-center justify-center rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
                    pathname === `/chat/${chat.id}` && "bg-gray-200 dark:bg-gray-800 text-gray-900 dark:text-white"
                  )}
                  title={chat.title}
                  aria-label={chat.title}
                >
                  <MessageSquare size={18} className="opacity-70" />
                </Link>
              ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-3 border-t border-gray-200 dark:border-gray-800 space-y-1">
        <button 
          onClick={() => setIsSettingsOpen(true)}
          aria-label="Settings"
          className={cn("flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500", isCollapsed && "justify-center")}
        >
          <Settings size={18} className="shrink-0 opacity-70" />
          {!isCollapsed && <span>Settings</span>}
        </button>
        <button 
          onClick={handleLogout}
          aria-label="Log out"
          className={cn("flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500", isCollapsed && "justify-center")}
        >
          <LogOut size={18} className="shrink-0 opacity-70" />
          {!isCollapsed && <span>Log out</span>}
        </button>
      </div>
    </div>
  );

  return (
    <>
      <div className="md:hidden fixed top-0 left-0 z-40 w-full h-14 bg-white/80 dark:bg-gray-900/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 flex items-center px-4">
        <button onClick={() => setIsMobileOpen(true)} aria-label="Open sidebar menu" className="text-gray-600 dark:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded">
          <Menu size={24} />
        </button>
        <div className="flex-1 text-center font-medium text-gray-900 dark:text-white">
          MyAI
        </div>
        <div className="w-6" />
      </div>

      {isMobileOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={() => setIsMobileOpen(false)} aria-hidden="true" />
          <div className="relative w-72 max-w-[85%] bg-white dark:bg-gray-950 h-full shadow-xl flex-shrink-0 flex flex-col">
            {SidebarContent}
          </div>
        </div>
      )}

      <div className={cn("hidden md:flex h-screen flex-shrink-0 transition-all duration-300 ease-in-out", isCollapsed ? "w-[72px]" : "w-64", className)}>
        {SidebarContent}
      </div>

      <SettingsModal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
    </>
  );
}
