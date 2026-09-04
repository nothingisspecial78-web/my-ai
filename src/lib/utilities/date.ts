import { Database } from '@/types/database';

type Conversation = Database['public']['Tables']['conversations']['Row'];

export interface GroupedConversations {
  Today: Conversation[];
  Yesterday: Conversation[];
  'Previous 7 Days': Conversation[];
  Older: Conversation[];
}

export function groupConversations(conversations: Conversation[]): GroupedConversations {
  const groups: GroupedConversations = {
    Today: [],
    Yesterday: [],
    'Previous 7 Days': [],
    Older: [],
  };

  const now = new Date();
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterdayStart = new Date(todayStart.getTime() - 24 * 60 * 60 * 1000);
  const previous7DaysStart = new Date(todayStart.getTime() - 7 * 24 * 60 * 60 * 1000);

  for (const convo of conversations) {
    if (convo.deleted_at) continue;

    const updatedAt = new Date(convo.updated_at);

    if (updatedAt >= todayStart) {
      groups.Today.push(convo);
    } else if (updatedAt >= yesterdayStart) {
      groups.Yesterday.push(convo);
    } else if (updatedAt >= previous7DaysStart) {
      groups['Previous 7 Days'].push(convo);
    } else {
      groups.Older.push(convo);
    }
  }

  return groups;
}
