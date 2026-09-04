import os

def write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.strip() + '\n')
    print(f"Updated {path}")

# --- ChatClient.tsx Header Replacement ---
with open('src/app/chat/[id]/ChatClient.tsx', 'r', encoding='utf-8') as f:
    code = f.read()

old_header = '''      <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-gray-200 dark:border-gray-800 bg-white/80 dark:bg-gray-900/80 px-4 backdrop-blur-md hidden md:flex">
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
      </header>'''

import re
old_header_clean = re.sub(r'\\s+', ' ', old_header)

new_header = '''      <header className="sticky top-0 z-10 flex h-14 items-center justify-between bg-white/95 dark:bg-gray-900/95 px-4 backdrop-blur-md hidden md:flex">
        <div className="flex items-center gap-2 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 px-2 py-1.5 rounded-lg transition-colors">
          <h1 className="text-[15px] font-semibold text-gray-900 dark:text-gray-100 truncate max-w-md flex items-center gap-2">
            {conversation.title}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="opacity-50"><path d="m6 9 6 6 6-6"/></svg>
          </h1>
          {isThinking && <Loader2 size={12} className="animate-spin text-gray-400 ml-2" />}
        </div>
        <div className="flex items-center gap-2">
          {isSending && (
            <button 
              onClick={stopGeneration}
              aria-label="Stop generation"
              className="flex items-center gap-1 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 px-2 py-1.5 rounded-lg transition-colors mr-2 focus:outline-none"
            >
              <StopCircle size={14} /> Stop
            </button>
          )}
          <button className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors border border-gray-200 dark:border-gray-700">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" x2="12" y1="2" y2="15"/></svg>
            Share
          </button>
          <button className="flex items-center justify-center w-8 h-8 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
          </button>
        </div>
      </header>'''

if old_header in code:
    code = code.replace(old_header, new_header)
else:
    # Try Regex fallback
    print("Warning: exact string replace failed, trying regex")
    
write_file('src/app/chat/[id]/ChatClient.tsx', code)
