import { test, expect } from '@playwright/test';

test.describe('E2E Security & RLS Workflows', () => {
  let userAChatId: string;

  test.beforeEach(async ({ browser }) => {
    // Create a chat for User A
    const contextA = await browser.newContext({ storageState: 'playwright/.auth/userA.json' });
    const pageA = await contextA.newPage();
    await pageA.goto('/chat');
    await pageA.click('text=New Chat');
    await pageA.waitForURL(/.*\/chat\/.+/);
    userAChatId = pageA.url().split('/').pop() || '';
    
    // Send a message as User A
    await pageA.fill('textarea', 'Top secret message for User A');
    await pageA.keyboard.press('Enter');
    await expect(pageA.locator('.prose').last()).toBeVisible({ timeout: 10000 });
    await expect(pageA.locator('textarea')).toBeEnabled({ timeout: 15000 });
    await contextA.close();
  });

  test('User B cannot read User A conversations or messages', async ({ browser }) => {
    const contextB = await browser.newContext({ storageState: 'playwright/.auth/userB.json' });
    const page = await contextB.newPage();
    await page.goto('/chat');
    // Attempt UI access
    await page.goto('/chat/' + userAChatId);
    // Should show 404 not found since RLS blocked the row
    await expect(page.locator('text=This page could not be found')).toBeVisible({ timeout: 5000 });

    // Ensure search does not leak User A content
    await page.goto('/chat');
    await page.click('input[placeholder="Search chats..."]');
    await page.fill('input[placeholder="Search chats..."]', 'Top secret');
    await expect(page.locator('text=No conversations found')).toBeVisible();
  });

  test('User B cannot manipulate User A data via API directly', async ({ playwright }) => {
    const contextB = await playwright.request.newContext({ storageState: 'playwright/.auth/userB.json', baseURL: 'http://localhost:3000' });
    // Attempt to regenerate User A message
    const regenRes = await contextB.post('/api/chat', {
      data: {
        conversationId: userAChatId,
      }
    });
    // Should fail authorization
    expect(regenRes.status()).toBe(404);
  });
});
