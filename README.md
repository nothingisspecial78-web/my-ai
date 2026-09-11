# Before You Click

Before You Click is an intelligent AI assistant that helps you think, understand, create, and stay safer before you click. Built with Next.js, React, Tailwind CSS, shadcn/ui, Supabase, and Google Gemini.

## Architecture & Clean Separation

This project follows a clean, modular architecture:

- `src/app`: Next.js App Router for routes, pages, and API endpoints.
- `src/components`: UI components organized by domain.
- `src/lib/ai`: Provider-agnostic AI integration layer.
- `src/lib/supabase`: Supabase database and authentication clients.
- `src/lib/auth`: Authentication helpers and middleware.
- `src/lib/database`: Database queries and data access logic.
- `src/hooks`: Custom React hooks for state and side-effects.
- `src/types`: Global TypeScript types and interfaces.
- `supabase/migrations`: SQL migrations for the Supabase database.

## Setup & Configuration

### Prerequisites
- Node.js (v18+)
- Supabase account & project

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Variables
Copy `.env.example` to `.env.local`:
```bash
cp .env.example .env.local
```
Fill in the following variables:
- `NEXT_PUBLIC_SUPABASE_URL`: Your Supabase project URL.
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`: Your Supabase anonymous key.
- `AI_PROVIDER_API_KEY`: API key for your chosen AI provider (e.g., Gemini).
- `AI_MODE`: Set to `mock` for local development without an API key, or leave blank to use the real provider.

### 3. Supabase Configuration & Migrations
The database schema uses PostgreSQL with strict Row Level Security (RLS).
1. Go to your Supabase project SQL Editor.
2. Run the migration script located in `supabase/migrations/20260831000000_initial_schema.sql`.
3. This script will automatically create the tables, indexes, triggers, and secure RLS policies.

### 4. Authentication Setup
Before You Click uses Supabase Auth.
- Users can sign up via `/signup`.
- The database triggers an automatic profile creation on user signup.
- The Next.js middleware in `src/middleware.ts` protects private routes (like `/chat`) and redirects unauthenticated users to `/login`.

### 5. Security & Row Level Security (RLS)
Security is implemented primarily at the database layer using Postgres RLS.
- **Profiles:** Users can only view and update their own profile.
- **Conversations:** Users can only view, insert, update, and delete conversations where `user_id` matches their authenticated UID.
- **Messages:** Policies strictly verify that a user can only interact with messages linked to a conversation they own. A subquery checks `auth.uid() = conversations.user_id`.

**Security Verification Example:**
1. User A logs in. They can fetch conversations because `auth.uid() = user_id`.
2. User A attempts to read User B's conversation. The `SELECT` policy fails because the `user_id` does not match, returning no rows.
3. User A attempts to insert a message into User B's conversation. The `INSERT` policy `WITH CHECK` fails because the subquery verifies the conversation does not belong to User A.

### 6. Local Development
Start the Next.js development server:
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) with your browser.
