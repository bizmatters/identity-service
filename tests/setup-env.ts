import { config } from 'dotenv';

// Load .env file and preserve NODE_ENV before vitest overrides it
const envResult = config();
if (envResult.parsed?.NODE_ENV) {
  process.env.NODE_ENV = envResult.parsed.NODE_ENV;
}