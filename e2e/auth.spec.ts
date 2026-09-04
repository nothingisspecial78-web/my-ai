import { test, expect } from '@playwright/test';

test.use({ storageState: { cookies: [], origins: [] } });

test('unauthenticated users are redirected from /chat to /login', async ({ page }) => {
  await page.goto('/chat');
  await expect(page).toHaveURL(/.*\/login/);
});

test('unauthenticated users cannot call /api/chat successfully', async ({ request }) => {
  const response = await request.post('/api/chat', {
    data: { conversationId: '123e4567-e89b-12d3-a456-426614174000' }
  });
  expect(response.status()).toBe(401);
});

test('unauthenticated users cannot call /api/settings/model successfully', async ({ request }) => {
  const response = await request.get('/api/settings/model');
  expect(response.status()).toBe(401);
});
