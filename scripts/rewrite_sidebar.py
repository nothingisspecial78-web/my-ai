import os

def write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.strip() + '\n')
    print(f"Updated {path}")

sidebar_tsx = """
'use client';

import { useState, useMemo, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { 
  MessageSquare, 
  Settings, 
  LogOut, 
  Menu,
  Edit2,
  Trash2,
  Plus
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { createClient } from '@/lib/supabase/client';
import { SettingsModal } from '@/components/settings/SettingsModal';
import { Database } from '@/types/database';
import { groupConversations } from '@/lib/utilities/date';
import { getPaginatedConversations, createConversation, updateConversation, deleteConversation } from '@/lib/database';

type Conversation = Database['public']['Tables']['conversations']['Row'];

export function Sidebar({ className, initialConversations = [], initialCursor = null }: { className?: string, initialConversations?: Conversation[], initialCursor?: string | null }) {
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [conversations, setConversations] = useState<Conversation[]>(initialConversations);
  const [cursor, setCursor] = useState<string | null>(initialCursor);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  
  const [isCreating, setIsCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [userInitial, setUserInitial] = useState<string>('U');

  const pathname = usePathname();
  const router = useRouter();
  
  useEffect(() => {
    async function fetchUser() {
      const supabase = createClient();
      const { data: { user } } = await supabase.auth.getUser();
      if (user && user.email) {
        setUserEmail(user.email);
        setUserInitial(user.email.charAt(0).toUpperCase());
      }
    }
    fetchUser();
  }, []);

  const handleLogout = async () => {
    const supabase = createClient();
    await supabase.auth.signOut();
    router.push('/login');
  };

  const handleLoadMore = async () => {
    if (!cursor || isLoadingMore) return;
    setIsLoadingMore(true);
    try {
      const { data: more, nextCursor } = await getPaginatedConversations(20, cursor);
      setConversations(prev => [...prev, ...more]);
      setCursor(nextCursor);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoadingMore(false);
    }
  };

  const handleNewChat = async () => {
    if (isCreating) return;
    setIsCreating(true);
    try {
      const newConvo = await createConversation('New conversation');
      if (newConvo) {
        setConversations(prev => [newConvo, ...prev]);
        router.push(`/chat/${newConvo.id}`);
      }
    } finally {
      setIsCreating(false);
    }
  };

  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        handleNewChat();
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isCreating, router]);

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
    try {
      setConversations(prev => prev.map(c => c.id === id ? { ...c, title: editTitle } : c));
      setEditingId(null);
      const updated = await updateConversation(id, { title: editTitle });
      if (updated) {
        setConversations(prev => prev.map(c => c.id === id ? updated : c));
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      setConversations(prev => prev.filter(c => c.id !== id));
      setDeleteConfirmId(null);
      await deleteConversation(id);
      if (pathname === `/chat/${id}`) {
        router.push('/chat');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const grouped = useMemo(() => groupConversations(conversations), [conversations]);
  const groupKeys = ['Today', 'Yesterday', 'Previous 7 Days', 'Older'] as const;

  const SidebarContent = (
    <div className="flex h-full w-full flex-col bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800">
      
      {/* Header */}
      <div className="p-4 pb-2">
        <Link href="/chat" className="flex items-center gap-2 mb-6 ml-1">
          <div className="flex h-7 w-7 items-center justify-center rounded bg-blue-600 text-white">
            <SparklesIcon />
          </div>
          <span className="font-semibold text-lg tracking-tight text-gray-900 dark:text-white">MyAI</span>
        </Link>
        
        <button
          onClick={handleNewChat}
          disabled={isCreating}
          className="flex w-full items-center justify-between gap-2 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 shadow-sm"
        >
          <div className="flex items-center gap-2">
            <Plus size={16} />
            <span>New Conversation</span>
          </div>
          <div className="flex items-center gap-1 rounded bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 text-[10px] font-bold text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-gray-700">
            <span>\u2318</span>
            <span>K</span>
          </div>
        </button>
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto px-3 pb-4 space-y-6 scrollbar-thin scrollbar-thumb-gray-200 dark:scrollbar-thumb-gray-800">
        {groupKeys.map(groupName => {
          const groupChats = grouped[groupName];
          if (groupChats.length === 0) return null;

          return (
            <div key={groupName} className="space-y-1">
              <h3 className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 mb-2 mt-4 tracking-wider">
                {groupName}
              </h3>
              <div className="space-y-0.5">
                {groupChats.map(chat => (
                  <div key={chat.id} className="group relative">
                    {editingId === chat.id ? (
                      <div className="flex w-full items-center gap-2 rounded-lg px-3 py-2 bg-white dark:bg-gray-900 border border-blue-500 shadow-sm">
                        <MessageSquare size={14} className="shrink-0 text-gray-400" />
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
                      <div className="flex w-full items-center justify-between gap-2 rounded-lg px-3 py-2 bg-red-50 dark:bg-red-900/20 text-sm">
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
                          "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-200/50 dark:hover:bg-gray-800/50 transition-colors pr-10 focus:outline-none",
                          pathname === `/chat/${chat.id}` && "bg-gray-200/80 dark:bg-gray-800 font-medium text-gray-900 dark:text-white shadow-sm"
                        )}
                      >
                        <span className="truncate">{chat.title}</span>
                      </Link>
                    )}
                    
                    {editingId !== chat.id && deleteConfirmId !== chat.id && (
                      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                        <button 
                          onClick={(e) => handleRenameStart(chat.id, chat.title, e)}
                          aria-label="Rename conversation"
                          className="p-1.5 text-gray-400 hover:text-gray-900 dark:hover:text-white focus:outline-none"
                        >
                          <Edit2 size={12} />
                        </button>
                        <button 
                          onClick={(e) => { e.preventDefault(); e.stopPropagation(); setDeleteConfirmId(chat.id); }}
                          aria-label="Delete conversation"
                          className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400 focus:outline-none"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
        
        {cursor && (
          <div className="pt-4 pb-4 flex justify-center">
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

      {/* Footer / User Profile */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-800">
        <div className="flex items-center gap-3 cursor-pointer hover:bg-gray-200/50 dark:hover:bg-gray-800/50 p-2 rounded-xl transition-colors group relative">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-purple-600 text-white font-bold text-sm shrink-0">
            {userInitial}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-gray-900 dark:text-white truncate">
              {userEmail ? userEmail.split('@')[0] : 'User'}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">
              {userEmail || 'Loading...'}
            </div>
          </div>
          
          <div className="absolute right-0 bottom-full mb-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg py-1 w-48 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all origin-bottom-left z-50">
            <button 
              onClick={() => setIsSettingsOpen(true)}
              className="flex w-full items-center gap-2 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              <Settings size={14} /> Settings
            </button>
            <button 
              onClick={handleLogout}
              className="flex w-full items-center gap-2 px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              <LogOut size={14} /> Log out
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Nav */}
      <div className="md:hidden fixed top-0 left-0 z-40 w-full h-14 bg-white/80 dark:bg-gray-900/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 flex items-center px-4">
        <button onClick={() => setIsMobileOpen(true)} aria-label="Open sidebar menu" className="text-gray-600 dark:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded">
          <Menu size={24} />
        </button>
        <div className="flex-1 text-center font-medium text-gray-900 dark:text-white flex items-center justify-center gap-2">
          <div className="flex h-5 w-5 items-center justify-center rounded bg-blue-600 text-white">
            <SparklesIcon />
          </div>
          MyAI
        </div>
        <div className="w-6" />
      </div>

      {/* Mobile Drawer */}
      {isMobileOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={() => setIsMobileOpen(false)} aria-hidden="true" />
          <div className="relative w-80 max-w-[85%] bg-gray-50 h-full shadow-xl flex-shrink-0 flex flex-col">
            {SidebarContent}
          </div>
        </div>
      )}

      {/* Desktop Sidebar */}
      <div className="hidden md:flex h-screen flex-shrink-0 w-80">
        {SidebarContent}
      </div>

      <SettingsModal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
    </>
  );
}

function SparklesIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L14.645 9.355L22 12L14.645 14.645L12 22L9.355 14.645L2 12L9.355 9.355L12 2Z" fill="currentColor"/>
    </svg>
  );
}
"""

write_file('src/components/layout/Sidebar.tsx', sidebar_tsx)
