import { test as setup } from '@playwright/test';  
import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });
import * as fs from 'fs';  
  
const authFileA = 'playwright/.auth/userA.json';  
const authFileB = 'playwright/.auth/userB.json';  
  
setup('authenticate', async ({ page }) => {  
  fs.mkdirSync('playwright/.auth', { recursive: true });  
  
  const emailA = process.env.E2E_USER_A_EMAIL;  
  const passwordA = process.env.E2E_USER_A_PASSWORD;  
  const emailB = process.env.E2E_USER_B_EMAIL;  
  const passwordB = process.env.E2E_USER_B_PASSWORD;  
  
  if (!emailA || !passwordA || !emailB || !passwordB) {  
    throw new Error('Missing E2E credentials');  
  }  
  
  await page.goto('/login');  
  await page.fill('input#email', emailA);  
  await page.fill('input#password', passwordA);
  await Promise.all([
    page.waitForNavigation(),
    page.click('button[type="submit"]')
  ]);
  await page.context().storageState({ path: authFileA });  
  
  await page.context().clearCookies();  
  await page.evaluate(() => window.localStorage.clear());  
  
  await page.goto('/login');  
  await page.fill('input#email', emailB);  
  await page.fill('input#password', passwordB);
  await Promise.all([
    page.waitForNavigation(),
    page.click('button[type="submit"]')
  ]);
  await page.context().storageState({ path: authFileB });  
}); 
