import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '../pkg/shield_browser.js': path.resolve(__dirname, 'tests/__mocks__/shield_browser.js'),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['js/**/*.ts'],
      exclude: ['js/types.ts'],
    },
  },
});
