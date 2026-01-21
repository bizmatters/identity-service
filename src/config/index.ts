// Identity Service Configuration
const nodeEnv = process.env['NODE_ENV'] || 'development';
const isLocal = nodeEnv === 'pr' || nodeEnv === 'local' || nodeEnv === 'test';
const isDev = nodeEnv === 'dev';
const isStaging = nodeEnv === 'staging';
const isProduction = nodeEnv === 'production';

// Environment-specific base URLs
const getBaseURL = () => {
  if (isLocal) return 'http://localhost:3000';
  if (isDev) return 'https://dev.zerotouch.dev';
  if (isStaging) return 'https://staging.zerotouch.dev';
  if (isProduction) return 'https://platform.zerotouch.dev';
  return 'http://localhost:3000'; // fallback
};

const baseURL = getBaseURL();

export const CONFIG = {
  // Auth Configuration - Environment-aware
  NEON_AUTH_REDIRECT_URI: `${baseURL}/auth/callback`,

  NEON_AUTH_CLIENT_ID: isProduction
    ? 'identity-service-prod'
    : isStaging
      ? 'identity-service-staging'
      : isDev
        ? 'identity-service-dev'
        : 'identity-service-pr', // local/test/pr - all resolve to PR environment

  ALLOWED_REDIRECT_URIS: isLocal
    ? ['https://platform.zerotouch.dev/dashboard', 'http://localhost:3000/dashboard']
    : [`${baseURL}/dashboard`],

  DEFAULT_REDIRECT_URI: `${baseURL}/dashboard`,

  // Database Configuration
  DB_POOL_MAX: 3,
  DB_POOL_IDLE_TIMEOUT: 10000,
  DB_POOL_CONNECTION_TIMEOUT: 5000,

  // Session Configuration
  SESSION_TTL: 86400,
  SESSION_ABSOLUTE_TTL: 604800,
  SESSION_COOKIE_NAME: '__Host-platform_session',

  // JWT Configuration
  JWT_EXPIRATION: '10m',
  JWT_KEY_ID_DEFAULT: 'default',

  // Cookie Configuration
  COOKIE_DOMAIN: isLocal ? '' : 'zerotouch.dev',
} as const;