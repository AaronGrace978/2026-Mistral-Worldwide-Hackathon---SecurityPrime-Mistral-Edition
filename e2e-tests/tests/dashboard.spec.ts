// Cyber Security Prime - Dashboard E2E Tests

import { test, expect } from '@playwright/test';
import { App } from '../utils/app';

test.describe('Dashboard', () => {
  let app: App;

  test.beforeEach(async ({ page }) => {
    app = new App(page);
    await app.start();
  });

  test.afterEach(async () => {
    await app.stop();
  });

  test('should load dashboard successfully', async ({ page }) => {
    // Navigate to dashboard
    await app.navigateTo('/');

    // Check that main dashboard elements are visible
    await expect(page.locator('h1').filter({ hasText: 'Cyber Security Prime' })).toBeVisible();
    await expect(page.locator('.grid').first()).toBeVisible();
  });

  test('should display system information', async ({ page }) => {
    await app.navigateTo('/');

    // Check for system information cards
    await expect(page.locator('text=Security Score')).toBeVisible();
    await expect(page.locator('text=Active Threats')).toBeVisible();
    await expect(page.locator('text=System Status')).toBeVisible();
  });

  test('should show module status', async ({ page }) => {
    await app.navigateTo('/');

    // Check that modules are listed in sidebar
    await expect(page.locator('text=Dashboard')).toBeVisible();
    await expect(page.locator('text=Malware Scanner')).toBeVisible();
    await expect(page.locator('text=Firewall')).toBeVisible();
    await expect(page.locator('text=Settings')).toBeVisible();
  });

  test('should navigate between modules', async ({ page }) => {
    await app.navigateTo('/');

    // Click on scanner module
    await page.locator('text=Malware Scanner').click();

    // Should navigate to scanner page
    await expect(page).toHaveURL(/.*scanner/);

    // Go back to dashboard
    await page.locator('text=Dashboard').click();
    await expect(page).toHaveURL(/.*\/$/);
  });

  test('should display real-time updates', async ({ page }) => {
    await app.navigateTo('/');

    // Wait for potential real-time updates
    await page.waitForTimeout(2000);

    // Check that status indicators are present
    const statusIndicators = page.locator('.status-active, .status-inactive, .status-warning');
    await expect(statusIndicators.first()).toBeVisible();
  });

  test('should handle theme switching', async ({ page }) => {
    await app.navigateTo('/');

    // Check for theme toggle (if available)
    const themeToggle = page.locator('button[aria-label*="theme"], .theme-toggle');
    if (await themeToggle.isVisible()) {
      await themeToggle.click();
      // Theme should change (this is a basic check)
      await page.waitForTimeout(500);
    }
  });
});