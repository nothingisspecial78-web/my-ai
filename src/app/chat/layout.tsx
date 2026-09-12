import { Sidebar } from "@/components/layout/Sidebar";
import { getPaginatedConversations } from "@/lib/database";

export default async function ChatLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { data: conversations, nextCursor } = await getPaginatedConversations(30);

  return (
    <div className="flex fixed inset-0 h-full h-dvh w-full bg-white dark:bg-gray-900 overflow-hidden text-gray-900 dark:text-gray-100">
      <Sidebar initialConversations={conversations} initialCursor={nextCursor} />
      <main className="flex-1 flex flex-col min-w-0 pt-14 md:pt-0 h-full relative overflow-hidden">
        {children}
      </main>
    </div>
  );
}
