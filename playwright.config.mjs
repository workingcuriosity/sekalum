import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/ui',
  timeout: 20_000,
  reporter: [['list'], ['json', { outputFile: 'test-results/ui-smoke.json' }]],
  use: { baseURL: 'http://127.0.0.1:4173', headless: true, screenshot: 'off', trace: 'retain-on-failure' },
  webServer: { command: 'node tests/ui/fixture-server.mjs', port: 4173, reuseExistingServer: false }
});
