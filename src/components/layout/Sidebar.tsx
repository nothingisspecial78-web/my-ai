'use client';

import { useState, useMemo, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { 
  Settings, 
  LogOut, 
  Menu,
  Edit2,
  Trash2,
  Plus,
  Search,
  Loader2,
  X,
  Globe,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { createClient } from '@/lib/supabase/client';
import { SettingsModal } from '@/components/settings/SettingsModal';
import { Database } from '@/types/database';
import { groupConversations } from '@/lib/utilities/date';
import { getPaginatedConversations, updateConversation, deleteConversation, searchConversations } from '@/lib/database';
import { resolveThemeSync } from '@/lib/theme/catalog';

type Conversation = Database['public']['Tables']['conversations']['Row'];

const THEME_ICONS: Record<string, LucideIcon> = {
  Globe,
  Calculator,
  Code,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Sparkles,
};

function ConversationThemeIndicator({
  themeId,
  isActive
}: {
  themeId: string | null | undefined;
  isActive: boolean;
}) {
  const theme = resolveThemeSync(themeId);
  const iconKey = theme.visual?.iconName || theme.icon || 'Globe';
  const IconComponent = THEME_ICONS[iconKey] || Globe;

  return (
    <span
      data-testid="sidebar-theme-indicator"
      data-theme={theme.slug}
      data-theme-name={theme.name}
      className={cn(
        "flex items-center gap-1.5 text-[11px] leading-tight select-none",
        isActive
          ? "text-gray-600 dark:text-gray-400"
          : "text-gray-400 dark:text-gray-500"
      )}
    >
      <span className="shrink-0 flex items-center justify-center text-theme-accent" aria-hidden="true">
        <IconComponent size={12} strokeWidth={2} />
      </span>
      <span className="truncate">{theme.name}</span>
    </span>
  );
}

function ThemeIconForId({
  themeId,
  size = 14,
  className
}: {
  themeId: string | null | undefined;
  size?: number;
  className?: string;
}) {
  const theme = resolveThemeSync(themeId);
  const iconKey = theme.visual?.iconName || theme.icon || 'Globe';
  const IconComponent = THEME_ICONS[iconKey] || Globe;
  return (
    <span data-theme={theme.slug} className="shrink-0 inline-flex items-center justify-center text-theme-accent" aria-hidden="true">
      <IconComponent size={size} className={className} />
    </span>
  );
}

export function Sidebar({ initialConversations = [], initialCursor = null }: { initialConversations?: Conversation[], initialCursor?: string | null }) {
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [conversations, setConversations] = useState<Conversation[]>(initialConversations);
  const [cursor, setCursor] = useState<string | null>(initialCursor);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [isCreating] = useState(false);
  
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Conversation[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [userInitial, setUserInitial] = useState<string>('U');

  const pathname = usePathname();
  const router = useRouter();

  // Handle Escape key for mobile drawer and user menu
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (isUserMenuOpen) setIsUserMenuOpen(false);
        if (isMobileOpen) setIsMobileOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobileOpen, isUserMenuOpen]);
  
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

  const handleNewChat = () => {
    router.push('/chat');
    setIsMobileOpen(false);
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

  const activeDisplayList = searchQuery.trim() ? searchResults : [];

  const SidebarContent = (
    <div className="flex h-full w-full flex-col bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800">
      
      {/* Header */}
      <div className="p-4 pb-2 space-y-4">
        <Link href="/chat" className="flex items-center gap-2.5 mb-2 ml-1" aria-label="Before You Click - Return to chat">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg overflow-hidden shrink-0 shadow-sm">
            <img src="/logo.png" alt="Before You Click" className="h-full w-full object-cover" />
          </div>
          <span className="font-semibold text-base sm:text-lg tracking-tight text-gray-900 dark:text-white truncate">Before You Click</span>
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

        <div className="relative group">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-blue-500 transition-colors" />
          <input 
            type="text" 
            placeholder="Search chats..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 py-2 pl-9 pr-8 text-sm text-gray-900 dark:text-white placeholder:text-gray-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all shadow-sm"
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
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto px-3 pb-4 space-y-6 scrollbar-thin scrollbar-thumb-gray-200 dark:scrollbar-thumb-gray-800">
        
        {searchQuery.trim() ? (
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
                <h3 className="px-3 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 mt-4">Search Results</h3>
                {activeDisplayList.map(chat => (
                  <Link
                    key={chat.id}
                    href={`/chat/${chat.id}`}
                    onClick={() => setIsMobileOpen(false)}
                    className={cn(
                      "flex w-full flex-col gap-0.5 rounded-lg px-3 py-2 transition-colors pr-10 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
                      pathname === `/chat/${chat.id}`
                        ? "bg-gray-200/80 dark:bg-gray-800 font-medium text-gray-900 dark:text-white shadow-sm"
                        : "text-gray-700 dark:text-gray-300 hover:bg-gray-200/50 dark:hover:bg-gray-800/50"
                    )}
                  >
                    <span className="truncate text-sm leading-snug">{chat.title}</span>
                    <ConversationThemeIndicator themeId={chat.theme_id} isActive={pathname === `/chat/${chat.id}`} />
                  </Link>
                ))}
              </>
            )}
          </div>
        ) : (
          groupKeys.map(groupName => {
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
                          <ThemeIconForId themeId={chat.theme_id} size={14} className="shrink-0 text-gray-400" />
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
                            <button onClick={() => handleDelete(chat.id)} className="text-red-700 dark:text-red-400 hover:underline font-medium min-h-[32px] px-2 py-1 flex items-center focus:outline-none focus-visible:ring-1 focus-visible:ring-red-500 rounded">Yes</button>
                            <button onClick={() => setDeleteConfirmId(null)} className="text-gray-600 dark:text-gray-400 hover:underline min-h-[32px] px-2 py-1 flex items-center focus:outline-none focus-visible:ring-1 focus-visible:ring-gray-500 rounded">No</button>
                          </div>
                        </div>
                      ) : (
                        <Link
                          href={`/chat/${chat.id}`}
                          onClick={() => setIsMobileOpen(false)}
                          className={cn(
                            "flex w-full flex-col gap-0.5 rounded-lg px-3 py-2 transition-colors pr-10 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
                            pathname === `/chat/${chat.id}`
                              ? "bg-gray-200/80 dark:bg-gray-800 font-medium text-gray-900 dark:text-white shadow-sm"
                              : "text-gray-700 dark:text-gray-300 hover:bg-gray-200/50 dark:hover:bg-gray-800/50"
                          )}
                        >
                          <span className="truncate text-sm leading-snug">{chat.title}</span>
                          <ConversationThemeIndicator themeId={chat.theme_id} isActive={pathname === `/chat/${chat.id}`} />
                        </Link>
                      )}
                      
                      {editingId !== chat.id && deleteConfirmId !== chat.id && (
                        <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center opacity-100 sm:opacity-0 sm:group-hover:opacity-100 sm:focus-within:opacity-100 focus-within:opacity-100 transition-opacity">
                          <button 
                            type="button"
                            onClick={(e) => handleRenameStart(chat.id, chat.title, e)}
                            aria-label="Rename conversation"
                            className="flex h-8 w-8 items-center justify-center text-gray-400 hover:text-gray-900 dark:hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 bg-gray-50/90 dark:bg-gray-950/90 rounded"
                          >
                            <Edit2 size={13} aria-hidden="true" />
                          </button>
                          <button 
                            type="button"
                            onClick={(e) => { e.preventDefault(); e.stopPropagation(); setDeleteConfirmId(chat.id); }}
                            aria-label="Delete conversation"
                            className="flex h-8 w-8 items-center justify-center text-gray-400 hover:text-red-600 dark:hover:text-red-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 bg-gray-50/90 dark:bg-gray-950/90 rounded ml-1"
                          >
                            <Trash2 size={13} aria-hidden="true" />
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            );
          })
        )}
        
        {cursor && !searchQuery.trim() && (
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
        <div className="relative">
          <button
            type="button"
            onClick={() => setIsUserMenuOpen(prev => !prev)}
            aria-haspopup="menu"
            aria-expanded={isUserMenuOpen}
            aria-label="User account menu"
            className="flex w-full items-center gap-3 hover:bg-gray-200/50 dark:hover:bg-gray-800/50 p-2 rounded-xl transition-colors text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-purple-600 text-white font-bold text-sm shrink-0" aria-hidden="true">
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
          </button>
          
          {isUserMenuOpen && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setIsUserMenuOpen(false)} aria-hidden="true" />
              <div
                role="menu"
                aria-label="User account options"
                className="absolute right-0 bottom-full mb-2 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg py-1 w-48 z-50 origin-bottom-left"
              >
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { setIsSettingsOpen(true); setIsUserMenuOpen(false); }}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none focus-visible:bg-gray-100 dark:focus-visible:bg-gray-800"
                >
                  <Settings size={14} aria-hidden="true" /> Settings
                </button>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { setIsUserMenuOpen(false); handleLogout(); }}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-red-600 dark:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none focus-visible:bg-gray-100 dark:focus-visible:bg-gray-800"
                >
                  <LogOut size={14} aria-hidden="true" /> Log out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Nav */}
      <div className="md:hidden fixed top-0 left-0 z-40 w-full h-14 bg-white/80 dark:bg-gray-900/80 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 flex items-center px-3">
        <button
          type="button"
          onClick={() => setIsMobileOpen(true)}
          aria-label="Open sidebar menu"
          className="flex h-10 w-10 items-center justify-center text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg"
        >
          <Menu size={24} aria-hidden="true" />
        </button>
        <div className="flex-1 text-center font-medium text-gray-900 dark:text-white flex items-center justify-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-lg overflow-hidden shrink-0 shadow-sm" aria-hidden="true">
            <img src="/logo.png" alt="" className="h-full w-full object-cover" />
          </div>
          <span className="truncate">Before You Click</span>
        </div>
        <div className="w-10" />
      </div>

      {/* Mobile Drawer */}
      {isMobileOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex" role="dialog" aria-modal="true" aria-label="Navigation drawer">
          <div className="fixed inset-0 bg-black/50 transition-opacity" onClick={() => setIsMobileOpen(false)} aria-hidden="true" />
          <div className="relative w-80 max-w-[85%] bg-gray-50 dark:bg-gray-950 h-full shadow-xl flex-shrink-0 flex flex-col z-10">
            <div className="absolute top-2.5 right-2.5 z-10">
              <button
                type="button"
                onClick={() => setIsMobileOpen(false)}
                aria-label="Close sidebar"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <X size={20} aria-hidden="true" />
              </button>
            </div>
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
