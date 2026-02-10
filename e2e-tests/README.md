# Cyber Security Prime - End-to-End Tests

This directory contains end-to-end tests for the Cyber Security Prime application.

## Test Structure

- `tests/` - Main test files
- `utils/` - Test utilities and helpers
- `config/` - Test configuration

## Running E2E Tests

### Prerequisites

1. Install dependencies:
```bash
npm install
```

2. Build the application for testing:
```bash
npm run tauri:build -- --debug
```

### Running Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run specific test file
npm run test:e2e -- tests/dashboard.spec.ts

# Run tests in headless mode
npm run test:e2e -- --headless
```

## Test Coverage

### Dashboard Tests
- Load dashboard and verify system information
- Check module status indicators
- Verify real-time updates

### Module Tests
- Scanner: Test malware scanning functionality
- Firewall: Test firewall rule management
- Encryption: Test file encryption/decryption
- Compliance: Test GDPR/HIPAA reporting
- Management: Test enterprise console features
- Isolation: Test sandbox/container management
- Tamper Detection: Test integrity checking

### Security Tests
- Authentication flow
- Authorization checks
- Session management
- Secure communication

### Performance Tests
- Memory usage monitoring
- CPU usage monitoring
- Response time validation
- Concurrent user simulation

## Writing New Tests

### Basic Test Structure

```typescript
import { test, expect } from '@playwright/test';
import { App } from '../utils/app';

test.describe('Module Name', () => {
  let app: App;

  test.beforeEach(async ({ page }) => {
    app = new App(page);
    await app.start();
  });

  test.afterEach(async () => {
    await app.stop();
  });

  test('should perform action', async () => {
    // Test implementation
    await app.navigateTo('module-route');
    await expect(page.locator('.module-element')).toBeVisible();
  });
});
```

### Test Utilities

The `utils/app.ts` file provides helper methods for common operations:

- `start()` - Start the application
- `stop()` - Stop the application
- `navigateTo(route)` - Navigate to a specific route
- `login(username, password)` - Perform login
- `waitForModule(moduleName)` - Wait for a module to be ready

## Continuous Integration

E2E tests are run in CI/CD pipeline:

1. Build application
2. Start application in test mode
3. Run test suite
4. Generate test reports
5. Upload artifacts

## Troubleshooting

### Common Issues

1. **Application fails to start**
   - Check that all dependencies are installed
   - Verify build configuration
   - Check system resources

2. **Tests timeout**
   - Increase timeout values in test config
   - Check for slow operations
   - Verify network connectivity

3. **Element not found**
   - Check CSS selectors
   - Verify element loading timing
   - Update test selectors

### Debug Mode

Run tests with debug flags:

```bash
DEBUG=pw:api npm run test:e2e -- --debug
```

## Contributing

When adding new E2E tests:

1. Follow the existing test structure
2. Use descriptive test names
3. Include proper assertions
4. Add comments for complex operations
5. Update this README if needed