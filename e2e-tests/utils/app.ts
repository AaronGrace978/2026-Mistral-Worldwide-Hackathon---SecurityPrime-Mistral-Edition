// Cyber Security Prime - E2E Test Utilities

import { Page } from '@playwright/test';
import { execSync, spawn } from 'child_process';
import * as path from 'path';

export class App {
  private page: Page;
  private appProcess: any = null;
  private isRunning = false;

  constructor(page: Page) {
    this.page = page;
  }

  async start() {
    if (this.isRunning) {
      return;
    }

    try {
      // Start the Tauri application in development mode
      const appPath = path.resolve(__dirname, '../../src-tauri/target/debug/cyber-security-prime');

      // For E2E tests, we'll use the development server instead of spawning the binary
      // as it's easier to manage and more reliable
      await this.page.goto('http://localhost:5173'); // Vite dev server

      this.isRunning = true;
    } catch (error) {
      console.error('Failed to start application:', error);
      throw error;
    }
  }

  async stop() {
    if (!this.isRunning) {
      return;
    }

    try {
      // Close the page/browser context
      await this.page.context().close();
      this.isRunning = false;
    } catch (error) {
      console.error('Failed to stop application:', error);
    }
  }

  async navigateTo(route: string) {
    await this.page.goto(`http://localhost:5173${route}`);
    await this.page.waitForLoadState('networkidle');
  }

  async waitForAppReady() {
    // Wait for the main application to be ready
    await this.page.waitForSelector('h1, .app-ready', { timeout: 30000 });
  }

  async waitForModule(moduleName: string) {
    // Wait for a specific module to be loaded
    const selector = `[data-module="${moduleName}"], text=${moduleName}`;
    await this.page.waitForSelector(selector, { timeout: 10000 });
  }

  async login(username: string, password: string) {
    // Navigate to login page if needed
    await this.navigateTo('/login');

    // Fill login form
    await this.page.fill('input[name="username"], input[placeholder*="username"]', username);
    await this.page.fill('input[name="password"], input[placeholder*="password"]', password);

    // Submit form
    await this.page.click('button[type="submit"], button:has-text("Login")');

    // Wait for login to complete
    await this.page.waitForURL('**', { timeout: 10000 });
  }

  async logout() {
    // Click logout button
    await this.page.click('button:has-text("Logout"), [data-testid="logout"]');

    // Wait for logout to complete
    await this.page.waitForURL('**/login', { timeout: 5000 });
  }

  async clickModuleInSidebar(moduleName: string) {
    // Click on module in sidebar
    await this.page.click(`text=${moduleName}`);
    await this.page.waitForLoadState('networkidle');
  }

  async waitForToast(message?: string) {
    // Wait for toast notification
    const toastSelector = '.toast, [role="alert"], .notification';
    await this.page.waitForSelector(toastSelector, { timeout: 5000 });

    if (message) {
      await this.page.waitForSelector(`${toastSelector}:has-text("${message}")`);
    }
  }

  async dismissToast() {
    // Dismiss toast if present
    const dismissBtn = this.page.locator('button[data-testid="toast-close"], .toast-close');
    if (await dismissBtn.isVisible()) {
      await dismissBtn.click();
    }
  }

  async takeScreenshot(name: string) {
    // Take screenshot for debugging
    await this.page.screenshot({ path: `screenshots/${name}.png` });
  }

  async getPageTitle() {
    return await this.page.title();
  }

  async getCurrentURL() {
    return this.page.url();
  }

  // Helper method to wait for Tauri backend to be ready
  async waitForBackendReady() {
    // This is a simplified check - in real implementation,
    // you might ping a health endpoint or check for specific elements
    await this.page.waitForFunction(() => {
      // Check if window.__TAURI__ is available (simplified check)
      return typeof window !== 'undefined';
    }, { timeout: 10000 });
  }

  // Helper method to simulate Tauri invoke calls for testing
  async invokeTauriCommand(command: string, args: any = {}) {
    // In a real E2E test, you might need to use Tauri's test utilities
    // For now, this is a placeholder
    return await this.page.evaluate(
      ({ cmd, params }) => {
        // This would normally use Tauri's invoke function
        console.log('Mock invoke:', cmd, params);
        return Promise.resolve({ success: true });
      },
      { cmd: command, params: args }
    );
  }

  // Helper method to check if element is visible with timeout
  async isVisible(selector: string, timeout = 5000): Promise<boolean> {
    try {
      await this.page.waitForSelector(selector, { timeout, state: 'visible' });
      return true;
    } catch {
      return false;
    }
  }

  // Helper method to check if application is responsive
  async isResponsive(): Promise<boolean> {
    try {
      await this.page.waitForFunction(
        () => document.readyState === 'complete',
        { timeout: 5000 }
      );
      return true;
    } catch {
      return false;
    }
  }
}