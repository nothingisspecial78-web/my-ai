/**
 * Extracts a clean, concise conversation title from the user's first message.
 * Returns a 3-6 word title suitable for sidebar display.
 * This is a deterministic heuristic; LLM-based titles can be added later.
 */
export function extractConversationTitle(prompt: string): string {
  let title = prompt.trim();

  // Remove markdown formatting
  title = title.replace(/[*_~`#>\[\]()!]/g, '');

  // Remove common filler prefixes (case-insensitive)
  const fillerPrefixes = [
    /^(can you |could you |please |hey |hi |hello |help me |i want to |i need to |i'd like to |i would like to |tell me |show me |let's |let me know )/i,
    /^(explain |describe |write |create |generate |make |build |help |find |give me |what is |what are |what's |how do i |how to |how can i |why is |why do |why does |when is |when do |where is |where do |who is |who are )/i,
  ];

  let changed = true;
  while (changed) {
    changed = false;
    for (const prefix of fillerPrefixes) {
      const newTitle = title.replace(prefix, '');
      if (newTitle !== title) {
        title = newTitle;
        changed = true;
      }
    }
  }

  // Trim whitespace again after prefix removal
  title = title.trim();

  // Remove trailing punctuation
  title = title.replace(/[?.!,;:]+$/, '').trim();

  // Take first ~6 words
  const words = title.split(/\s+/).filter(Boolean);
  if (words.length > 6) {
    title = words.slice(0, 6).join(' ');
  } else {
    title = words.join(' ');
  }

  // Capitalize first letter
  if (title.length > 0) {
    title = title.charAt(0).toUpperCase() + title.slice(1);
  }

  // Truncate to 50 chars max
  if (title.length > 50) {
    title = title.substring(0, 47) + '...';
  }

  // Fallback
  if (!title || title.length < 2) {
    return 'New conversation';
  }

  return title;
}
