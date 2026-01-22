import { Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

// Environment configuration schema
const EnvConfigSchema = Type.Object({
  // Required - Database
  DATABASE_URL: Type.String({ minLength: 1 }),
  
  // Required - Cache
  REDIS_HOST: Type.String({ minLength: 1 }),
  REDIS_PORT: Type.String({ pattern: '^[0-9]+$' }),
  
  // Required - Neon Auth
  NEON_AUTH_URL: Type.String({ minLength: 1 }),
  
  // Required - JWT
  JWT_PRIVATE_KEY: Type.String({ minLength: 1 }),
  JWT_PUBLIC_KEY: Type.String({ minLength: 1 }),
  JWT_KEY_ID: Type.String({ minLength: 1 }),
  
  // Required - Token Security
  TOKEN_PEPPER: Type.String({ minLength: 1 }),
  
  // Optional with defaults
  NODE_ENV: Type.Optional(Type.String()),
  LOG_LEVEL: Type.Optional(Type.String()),
  SESSION_TTL: Type.Optional(Type.String()),
  SESSION_ABSOLUTE_TTL: Type.Optional(Type.String()),
  SESSION_COOKIE_NAME: Type.Optional(Type.String()),
  JWT_EXPIRATION: Type.Optional(Type.String()),
  PERMISSION_CACHE_TTL: Type.Optional(Type.String()),
  JWT_CACHE_BUFFER: Type.Optional(Type.String()),
  TOKEN_CACHE_TTL: Type.Optional(Type.String()),
  JWKS_CACHE_TTL: Type.Optional(Type.String()),
  DB_POOL_MAX: Type.Optional(Type.String()),
  DB_POOL_IDLE_TIMEOUT: Type.Optional(Type.String()),
  DB_POOL_CONNECTION_TIMEOUT: Type.Optional(Type.String()),
  PORT: Type.Optional(Type.String()),
  REDIS_USERNAME: Type.Optional(Type.String()),
  REDIS_PASSWORD: Type.Optional(Type.String()),
  NEON_AUTH_REDIRECT_URI: Type.Optional(Type.String()),
  ALLOWED_REDIRECT_URIS: Type.Optional(Type.String()),
});

/**
 * Validate environment configuration at startup
 * Implements fail-fast pattern for missing/invalid configuration
 */
export function validateEnvironmentConfig(): void {
  const config: Record<string, string | undefined> = {
    DATABASE_URL: process.env['DATABASE_URL'],
    REDIS_HOST: process.env['REDIS_HOST'],
    REDIS_PORT: process.env['REDIS_PORT'],
    NEON_AUTH_URL: process.env['NEON_AUTH_URL'],
    JWT_PRIVATE_KEY: process.env['JWT_PRIVATE_KEY'],
    JWT_PUBLIC_KEY: process.env['JWT_PUBLIC_KEY'],
    JWT_KEY_ID: process.env['JWT_KEY_ID'],
    TOKEN_PEPPER: process.env['TOKEN_PEPPER'],
    NODE_ENV: process.env['NODE_ENV'],
    LOG_LEVEL: process.env['LOG_LEVEL'],
    SESSION_TTL: process.env['SESSION_TTL'],
    SESSION_ABSOLUTE_TTL: process.env['SESSION_ABSOLUTE_TTL'],
    SESSION_COOKIE_NAME: process.env['SESSION_COOKIE_NAME'],
    JWT_EXPIRATION: process.env['JWT_EXPIRATION'],
    PERMISSION_CACHE_TTL: process.env['PERMISSION_CACHE_TTL'],
    JWT_CACHE_BUFFER: process.env['JWT_CACHE_BUFFER'],
    TOKEN_CACHE_TTL: process.env['TOKEN_CACHE_TTL'],
    JWKS_CACHE_TTL: process.env['JWKS_CACHE_TTL'],
    DB_POOL_MAX: process.env['DB_POOL_MAX'],
    DB_POOL_IDLE_TIMEOUT: process.env['DB_POOL_IDLE_TIMEOUT'],
    DB_POOL_CONNECTION_TIMEOUT: process.env['DB_POOL_CONNECTION_TIMEOUT'],
    PORT: process.env['PORT'],
    REDIS_USERNAME: process.env['REDIS_USERNAME'],
    REDIS_PASSWORD: process.env['REDIS_PASSWORD'],
    NEON_AUTH_REDIRECT_URI: process.env['NEON_AUTH_REDIRECT_URI'],
    ALLOWED_REDIRECT_URIS: process.env['ALLOWED_REDIRECT_URIS'],
  };

  // Validate against schema
  const isValid = Value.Check(EnvConfigSchema, config);
  
  if (!isValid) {
    const errors = [...Value.Errors(EnvConfigSchema, config)];
    const errorMessages = errors.map(err => {
      const path = err.path.replace(/^\//, '');
      return `  - ${path}: ${err.message}`;
    });

    console.error('❌ Environment configuration validation failed:\n');
    console.error(errorMessages.join('\n'));
    console.error('\nRequired environment variables:');
    console.error('  - DATABASE_URL');
    console.error('  - REDIS_HOST');
    console.error('  - REDIS_PORT');
    console.error('  - NEON_AUTH_URL');
    console.error('  - JWT_PRIVATE_KEY');
    console.error('  - JWT_PUBLIC_KEY');
    console.error('  - JWT_KEY_ID');
    console.error('  - TOKEN_PEPPER');
    
    process.exit(1);
  }

  console.log('✅ Environment configuration validated successfully');
}
