export const MOCK_CONVERSATIONS = [
  {
    id: 'mock-1',
    title: 'Explain Quantum Computing',
    group: 'Today',
  },
  {
    id: 'mock-2',
    title: 'Next.js App Router Guide',
    group: 'Today',
  },
  {
    id: 'mock-3',
    title: 'Dinner Recipes',
    group: 'Yesterday',
  },
  {
    id: 'mock-4',
    title: 'Debugging Python Script',
    group: 'Previous 7 Days',
  },
  {
    id: 'mock-5',
    title: 'Workout Plan',
    group: 'Older',
  },
];

export const MOCK_MESSAGES: Array<{ id: string, role: 'user' | 'assistant' | 'system', content: string, created_at: string }> = [
  {
    id: 'msg-1',
    role: 'user',
    content: 'Explain how React Server Components work. Keep it simple.',
    created_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
  },
  {
    id: 'msg-2',
    role: 'assistant',
    content: `React Server Components (RSC) represent a fundamental shift in how we build React applications. Here is a simple breakdown:

### 1. Traditional React (Client Components)
In the past, your entire React app ran in the browser. The server sent down an empty HTML shell and a large JavaScript bundle. The browser then ran that JS to render the UI.

### 2. React Server Components
With RSC, components can render *exclusively* on the server. The server sends fully formed UI (as a special data format) to the browser. 

**Benefits:**
- **Zero Bundle Size:** The JS for these components is never sent to the browser.
- **Direct Backend Access:** You can query databases directly inside the component without creating an API endpoint.
- **Better Performance:** The client has less work to do.

Here is an example:

\`\`\`tsx
// This runs only on the server
export default async function UserProfile() {
  const user = await db.query('SELECT * FROM users WHERE id = 1');
  
  return (
    <div className="profile">
      <h1>{user.name}</h1>
      <p>{user.bio}</p>
    </div>
  );
}
\`\`\`

You only use Client Components (with \`'use client'\`) when you need interactivity, like \`onClick\`, \`useState\`, or browser APIs.`,
    created_at: new Date(Date.now() - 1000 * 60 * 4).toISOString(),
  },
];
