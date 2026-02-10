// Cyber Security Prime - E2E Global Setup

import { chromium } from '@playwright/test';

async function globalSetup() {
  console.log('Starting E2E test setup...');

  // Pre-check that the application can start
  try {
    const browser = await chromium.launch();
    const page = await browser.newPage();

    // Try to access the dev server
    try {
      await page.goto('http://localhost:5173', { timeout: 10000 });
      console.log('✓ Development server is accessible');
    } catch (error) {
      console.warn('⚠ Development server not accessible, tests may fail');
    }

    await browser.close();
  } catch (error) {
    console.error('Failed to setup browser for pre-check:', error);
  }

  console.log('E2E test setup complete');
}

export default globalSetup;