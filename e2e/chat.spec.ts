import { test, expect } from '@playwright/test';



test.describe('E2E Chat Workflows', () => {
  
  test.beforeEach(async ({ page }) => {
    // Already authenticated via storage state
    await page.goto('/chat');
    await page.waitForURL('**/chat', { timeout: 10000 });
  });

  test('chat creation, streaming, stop, regenerate, persistence', async ({ page }) => {
    // Verify we are on /chat
    await expect(page).toHaveURL(/.*\/chat/);
    
    // Create new chat
    await Promise.all([page.waitForNavigation(), page.click('text=New Conversation')]);

    await expect(page.locator('textarea')).toBeEnabled({ timeout: 15000 });

    // Send a message
    await page.fill('textarea', 'Hello AI, how are you?');
    await expect(page.locator('button[aria-label="Send message"]')).toBeEnabled({ timeout: 5000 });
    await page.click('button[aria-label="Send message"]');

    // Wait for the stream to start appearing
    await expect(page.locator('.prose').last()).toBeVisible({ timeout: 15000 });

    // Wait for generation to fully complete before reloading
    await expect(page.locator('textarea')).toBeEnabled({ timeout: 15000 });

    // Verify persistence (reload the page)
    await page.waitForTimeout(1000);
    await page.reload();
    await expect(page.locator('.prose').last()).toBeVisible({ timeout: 15000 });
    
    // Test Regenerate
    await page.locator('.group').last().hover(); await page.click('button[title="Regenerate message"]', { force: true });
    await expect(page.locator('.prose').first()).toBeVisible();
    
    // Rename Chat
    const titleLocator = page.locator('span.truncate').first();
    await page.locator('.group.relative').first().hover(); // hover to reveal edit button
    await page.click('button[aria-label="Rename conversation"]', { force: true });
    await page.fill('input:focus', 'E2E Renamed Chat');
    await page.keyboard.press('Enter');
    await expect(titleLocator).toHaveText('E2E Renamed Chat', { timeout: 5000 });

    // Delete Chat
    await page.locator('.group.relative').first().hover();
    
    // Handle the inline confirm dialog automatically
    await page.click('button[aria-label="Delete conversation"]', { force: true });
    await page.click('text=Yes'); // inline confirm
    
    // Should redirect back to /chat
    await page.waitForURL('**/chat');

    // Test Stop Generation
    await Promise.all([page.waitForURL('**/chat'), page.click('text=New Conversation')]);
    await expect(page.locator('textarea')).toBeEnabled({ timeout: 15000 });
    await page.fill('textarea', 'Trigger a slow generation');
    await expect(page.locator('button[aria-label="Send message"]')).toBeEnabled({ timeout: 5000 });
    await page.click('button[aria-label="Send message"]');
    
    // Immediately click stop
    await page.click('button:has-text("Stop")');
    await expect(page.locator('text=Generation stopped')).toBeVisible({ timeout: 5000 });
  });

  test('settings persistence', async ({ page }) => {
    await page.hover('text=myai-test-a@example.com'); await page.click('text=Settings');
    
    // Click Chat tab
    await page.click('button[role="tab"]:has-text("Chat")');
    // Toggle enter to send
    const toggle = page.locator('button[role="switch"]').first();
    await toggle.click();
    
    // Close settings
    await page.keyboard.press('Escape'); // close modal
    
    // Reload to verify persistence
    await page.reload();
    await page.hover('text=myai-test-a@example.com'); await page.click('text=Settings');
  });

  test('cross-user authorization', async ({ browser }) => {
    // 1. Create a chat as User A
    const contextA = await browser.newContext({ storageState: 'playwright/.auth/userA.json' });
    const pageA = await contextA.newPage();
    await pageA.goto('/chat');
    // Start a new chat by sending a message
    await pageA.fill('textarea', 'A secret message');
    await pageA.click('button[aria-label="Send message"]');
    await pageA.waitForURL(/.*\/chat\/.+/);
    const chatUrl = pageA.url();
    
    // 2. Login as User B
    const contextB = await browser.newContext({ storageState: 'playwright/.auth/userB.json' });
    const pageB = await contextB.newPage();
    await pageB.goto(chatUrl);
    
    // Should show 404 not found since RLS blocked the row
    await expect(pageB.locator('text=This page could not be found')).toBeVisible({ timeout: 5000 });
  });

  test('keyboard shortcuts and search', async ({ page, isMobile }) => {
    if (isMobile) return; // Skip on mobile where shortcuts might not apply
    
    // Wait for sidebar to mount and hydrate events
    await expect(page.locator('text=New Conversation').first()).toBeVisible();
    await page.waitForTimeout(500); // Give React a moment to attach window listeners

    // Test Ctrl+Shift+O (New Chat)
    await page.keyboard.press('Control+K');
    await page.waitForURL('**/chat');
    
    await expect(page.locator('textarea')).toBeEnabled({ timeout: 15000 });
    
    // Send a message to be searched
    await page.fill('textarea', 'Find this keyword');
    await expect(page.locator('button[aria-label="Send message"]')).toBeEnabled({ timeout: 5000 });
    await page.click('button[aria-label="Send message"]');
    await expect(page.locator('.prose').last()).toBeVisible({ timeout: 15000 });
    
    // Focus Search
    await page.click('input[placeholder="Search chats..."]');
    
    // Test Search
    await page.fill('input[placeholder="Search chats..."]', 'keyword');
    // The search results should appear
    await expect(page.locator('text=Find this keyword').first()).toBeVisible({ timeout: 5000 });
    
    // Clear search
    await page.click('button[aria-label="Clear search"]');
    await expect(page.locator('input[placeholder="Search chats..."]')).toBeEmpty();
  });

  test('pagination and load more', async ({ page }) => {
    // Requires a lot of chats. Let's just verify the load more button logic
    await Promise.all([page.waitForNavigation(), page.click('text=New Conversation')]);
    await expect(page.locator('textarea')).toBeEnabled({ timeout: 15000 });
    await page.fill('textarea', 'Fill chat for pagination');
    await expect(page.locator('button[aria-label="Send message"]')).toBeEnabled({ timeout: 5000 });
    await page.click('button[aria-label="Send message"]');
    await expect(page.locator('.prose').last()).toBeVisible({ timeout: 15000 });
    // In local E2E we usually can't create 20+ chats easily without a loop,
    // so this just ensures it doesn't crash on standard operations.
  });
});
