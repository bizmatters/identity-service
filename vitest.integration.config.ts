import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { config } from 'dotenv';

// Load environment variables from .env file
config();

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/integration/**/*.ts'],
    exclude: ['tests/integration/conftest.ts'], // Exclude configuration file
    testTimeout: 30000,
    hookTimeout: 30000,
    // Run tests sequentially to avoid database conflicts
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
  },
});
