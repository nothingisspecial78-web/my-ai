'use client';

import { useState, useEffect } from 'react';
import { X, User, Palette, MessageSquare, Info, Loader2, Check } from 'lucide-react';
import { useTheme } from 'next-themes';
import { cn } from '@/lib/utils';
import { createClient } from '@/lib/supabase/client';
import { updateProfile } from '@/lib/database';
import { useChatPreferences } from '@/hooks/use-chat-preferences';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState<'account' | 'appearance' | 'chat' | 'about'>('account');
  const { theme, setTheme } = useTheme();
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [fullName, setFullName] = useState('');
  const [originalFullName, setOriginalFullName] = useState('');
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [profileSaved, setProfileSaved] = useState(false);

  // Model info from safe API
  const [modelInfo, setModelInfo] = useState<{ mode: string; model: string; provider: string } | null>(null);

  // Chat preferences
  const { preferences, setPreferences } = useChatPreferences();

  useEffect(() => {
    if (isOpen) {
      const supabase = createClient();
      supabase.auth.getUser().then(({ data }) => {
        if (data.user) {
          setUserEmail(data.user.email ?? null);
        }
      });

      // Fetch profile
      const fetchProfile = async () => {
        const supabase = createClient();
        const { data: { user } } = await supabase.auth.getUser();
        if (user) {
          const { data: profile } = await supabase
            .from('profiles')
            .select('full_name')
            .eq('id', user.id)
            .single();
          if (profile) {
            setFullName(profile.full_name || '');
            setOriginalFullName(profile.full_name || '');
          }
        }
      };
      fetchProfile();

      // Fetch model info from safe server API
      fetch('/api/settings/model')
        .then(r => r.ok ? r.json() : null)
        .then(data => { if (data) setModelInfo(data); })
        .catch(() => { /* non-critical */ });
    }
  }, [isOpen]);

  // Escape key handler
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleSaveProfile = async () => {
    if (isSavingProfile || fullName.trim() === originalFullName) return;
    setIsSavingProfile(true);
    setProfileSaved(false);
    try {
      const updated = await updateProfile({ full_name: fullName.trim() || null });
      if (updated) {
        setOriginalFullName(updated.full_name || '');
        setProfileSaved(true);
        setTimeout(() => setProfileSaved(false), 2000);
      }
    } catch {
      // non-critical
    } finally {
      setIsSavingProfile(false);
    }
  };

  if (!isOpen) return null;

  const hasProfileChanges = fullName.trim() !== originalFullName;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6" role="dialog" aria-modal="true" aria-label="Settings">
      <div 
        className="fixed inset-0 bg-black/40 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      
      <div className="relative w-full max-w-2xl bg-white dark:bg-gray-900 rounded-2xl shadow-2xl overflow-hidden flex flex-col md:flex-row h-[80vh] max-h-[600px] border border-gray-200 dark:border-gray-800 animate-in fade-in zoom-in-95 duration-200">
        
        {/* Sidebar */}
        <div className="w-full md:w-48 lg:w-56 bg-gray-50 dark:bg-gray-950 p-4 border-r border-gray-200 dark:border-gray-800 flex flex-col shrink-0">
          <div className="flex items-center justify-between md:mb-6 mb-2">
            <h2 className="font-semibold text-gray-900 dark:text-white px-2">Settings</h2>
            <button 
              onClick={onClose} 
              aria-label="Close settings"
              className="md:hidden p-1 text-gray-500 hover:text-gray-900 dark:hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
            >
              <X size={20} />
            </button>
          </div>
          
          <nav role="tablist" aria-orientation="vertical" className="flex md:flex-col gap-1 overflow-x-auto md:overflow-visible pb-2 md:pb-0">
            <TabButton active={activeTab === 'account'} onClick={() => setActiveTab('account')} icon={User} label="Account" id="tab-account" panelId="panel-account" />
            <TabButton active={activeTab === 'appearance'} onClick={() => setActiveTab('appearance')} icon={Palette} label="Appearance" id="tab-appearance" panelId="panel-appearance" />
            <TabButton active={activeTab === 'chat'} onClick={() => setActiveTab('chat')} icon={MessageSquare} label="Chat" id="tab-chat" panelId="panel-chat" />
            <TabButton active={activeTab === 'about'} onClick={() => setActiveTab('about')} icon={Info} label="About" id="tab-about" panelId="panel-about" />
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 bg-white dark:bg-gray-900 relative">
          <button 
            onClick={onClose} 
            aria-label="Close settings"
            className="hidden md:flex absolute top-4 right-4 p-2 text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X size={20} />
          </button>

          <div className="max-w-md mt-2 md:mt-8 space-y-8">
            {activeTab === 'account' && (
              <div role="tabpanel" id="panel-account" aria-labelledby="tab-account" className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">Account</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage your personal information.</p>
                </div>
                
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="h-16 w-16 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center text-blue-600 dark:text-blue-300 text-xl font-medium">
                      {fullName ? fullName.charAt(0).toUpperCase() : (userEmail ? userEmail.charAt(0).toUpperCase() : 'U')}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900 dark:text-white">{fullName || 'Your Profile'}</div>
                      <div className="text-sm text-gray-500">{userEmail || 'Loading...'}</div>
                    </div>
                  </div>
                  
                  <div className="space-y-1">
                    <label htmlFor="fullName" className="text-sm font-medium text-gray-700 dark:text-gray-300">Full Name</label>
                    <input 
                      id="fullName"
                      type="text" 
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      maxLength={100}
                      placeholder="Enter your name"
                      className="w-full bg-white dark:bg-gray-950 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                    />
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="email" className="text-sm font-medium text-gray-700 dark:text-gray-300">Email Address</label>
                    <input 
                      id="email"
                      type="text" 
                      readOnly 
                      value={userEmail || 'Loading...'} 
                      className="w-full bg-gray-50 dark:bg-gray-950 border border-gray-200 dark:border-gray-800 rounded-lg px-3 py-2 text-gray-500 dark:text-gray-400 cursor-not-allowed text-sm"
                    />
                  </div>

                  {hasProfileChanges && (
                    <button
                      onClick={handleSaveProfile}
                      disabled={isSavingProfile}
                      className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900"
                    >
                      {isSavingProfile ? (
                        <><Loader2 size={14} className="animate-spin" /> Saving...</>
                      ) : profileSaved ? (
                        <><Check size={14} /> Saved</>
                      ) : (
                        'Save Changes'
                      )}
                    </button>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'appearance' && (
              <div role="tabpanel" id="panel-appearance" aria-labelledby="tab-appearance" className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">Appearance</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Customize how Before You Click looks.</p>
                </div>
                
                <div className="space-y-3" role="radiogroup" aria-label="Theme preference">
                  <ThemeOption label="Light" value="light" selected={theme === 'light'} onChange={() => setTheme('light')} />
                  <ThemeOption label="Dark" value="dark" selected={theme === 'dark'} onChange={() => setTheme('dark')} />
                  <ThemeOption label="System" value="system" selected={theme === 'system'} onChange={() => setTheme('system')} />
                </div>
              </div>
            )}

            {activeTab === 'chat' && (
              <div role="tabpanel" id="panel-chat" aria-labelledby="tab-chat" className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">Chat Preferences</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Customize your conversation experience.</p>
                </div>
                
                <div className="space-y-4">
                  <ToggleOption 
                    label="Enter to send" 
                    description="Send messages by pressing Enter. Use Shift+Enter for newline."
                    checked={preferences.enterToSend}
                    onChange={(v) => setPreferences({ enterToSend: v })}
                  />
                  <ToggleOption 
                    label="Show timestamps" 
                    description="Display the time for every message."
                    checked={preferences.showTimestamps}
                    onChange={(v) => setPreferences({ showTimestamps: v })}
                  />
                </div>
              </div>
            )}

            {activeTab === 'about' && (
              <div role="tabpanel" id="panel-about" aria-labelledby="tab-about" className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white">About Before You Click</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Version and system information.</p>
                </div>
                
                <div className="space-y-4">
                  <InfoRow label="Version" value="1.0.0" />
                  <InfoRow label="AI Provider" value={modelInfo?.provider || 'Loading...'} />
                  <InfoRow label="AI Model" value={modelInfo?.model || 'Loading...'} />
                  <InfoRow label="Mode" value={modelInfo?.mode || 'Loading...'} />
                </div>

                <div className="pt-4 border-t border-gray-200 dark:border-gray-800">
                  <p className="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">
                    Before You Click is an intelligent AI assistant that helps you think, understand, create, and stay safer before you click. 
                    AI responses may contain inaccuracies. Always verify important information.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label, id, panelId }: { active: boolean, onClick: () => void, icon: React.ElementType, label: string, id: string, panelId: string }) {
  return (
    <button
      role="tab"
      id={id}
      aria-selected={active}
      aria-controls={panelId}
      onClick={onClick}
      className={cn(
        "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
        active 
          ? "bg-gray-200 dark:bg-gray-800 text-gray-900 dark:text-white" 
          : "text-gray-600 dark:text-gray-400 hover:bg-gray-200/50 dark:hover:bg-gray-800/50 hover:text-gray-900 dark:hover:text-white"
      )}
    >
      <Icon size={16} />
      <span>{label}</span>
    </button>
  );
}

function ThemeOption({ label, value, selected, onChange }: { label: string, value: string, selected: boolean, onChange: () => void }) {
  return (
    <label className="flex items-center justify-between p-3 border border-gray-200 dark:border-gray-800 rounded-lg cursor-pointer hover:border-blue-500 dark:hover:border-blue-500 transition-colors bg-gray-50 dark:bg-gray-950/50 focus-within:ring-2 focus-within:ring-blue-500">
      <span className="text-sm font-medium text-gray-900 dark:text-white">{label}</span>
      <input 
        type="radio" 
        name="theme-preference"
        value={value} 
        checked={selected} 
        onChange={onChange} 
        className="sr-only" 
      />
      <div className={cn(
        "h-5 w-5 rounded-full border flex items-center justify-center transition-colors",
        selected ? "border-blue-600 bg-blue-600" : "border-gray-300 dark:border-gray-700"
      )}>
        {selected && <div className="h-2 w-2 rounded-full bg-white" />}
      </div>
    </label>
  );
}

function ToggleOption({ label, description, checked, onChange }: { label: string, description: string, checked: boolean, onChange: (c: boolean) => void }) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="pr-4" id={`desc-${label.replace(/\s+/g, '-')}`}>
        <div className="text-sm font-medium text-gray-900 dark:text-white">{label}</div>
        <div className="text-xs text-gray-500 dark:text-gray-400">{description}</div>
      </div>
      <button 
        role="switch"
        aria-checked={checked}
        aria-describedby={`desc-${label.replace(/\s+/g, '-')}`}
        onClick={() => onChange(!checked)}
        className={cn(
          "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900",
          checked ? "bg-blue-600" : "bg-gray-200 dark:bg-gray-700"
        )}
      >
        <span 
          className={cn(
            "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
            checked ? "translate-x-6" : "translate-x-1"
          )} 
        />
      </button>
    </div>
  );
}

function InfoRow({ label, value }: { label: string, value: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span className="text-sm text-gray-500 dark:text-gray-400">{label}</span>
      <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
    </div>
  );
}
