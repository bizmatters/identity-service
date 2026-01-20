import { register, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';

// Enable default Node.js metrics collection
collectDefaultMetrics({ register });

// Authentication login metrics
export const authLoginTotal = new Counter({
  name: 'auth_login_total',
  help: 'Total number of login attempts',
  labelNames: ['provider', 'method'] as const,
  registers: [register],
});

export const authLoginSuccessTotal = new Counter({
  name: 'auth_login_success_total',
  help: 'Total number of successful logins',
  labelNames: ['provider', 'method'] as const,
  registers: [register],
});

export const authLoginFailureTotal = new Counter({
  name: 'auth_login_failure_total',
  help: 'Total number of failed logins',
  labelNames: ['provider', 'method', 'reason'] as const,
  registers: [register],
});

// Authentication validation metrics
export const authValidateTotal = new Counter({
  name: 'auth_validate_total',
  help: 'Total number of authentication validation requests',
  labelNames: ['type', 'method'] as const, // type: session|token, method: cookie|bearer
  registers: [register],
});

export const authValidateSuccessTotal = new Counter({
  name: 'auth_validate_success_total',
  help: 'Total number of successful authentication validations',
  labelNames: ['type', 'method'] as const,
  registers: [register],
});

export const authValidateFailureTotal = new Counter({
  name: 'auth_validate_failure_total',
  help: 'Total number of failed authentication validations',
  labelNames: ['type', 'method', 'reason'] as const,
  registers: [register],
});

// Authentication validation duration
export const authValidateDurationSeconds = new Histogram({
  name: 'auth_validate_duration_seconds',
  help: 'Duration of authentication validation requests in seconds',
  labelNames: ['type', 'method'] as const,
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
  registers: [register],
});

// Cache hit rate gauge
export const authCacheHitRate = new Gauge({
  name: 'auth_cache_hit_rate',
  help: 'Authentication cache hit rate (0-1)',
  labelNames: ['cache_type'] as const, // permission|jwt|token
  registers: [register],
});

// JWT metrics
export const jwtMintTotal = new Counter({
  name: 'jwt_mint_total',
  help: 'Total number of JWT tokens minted',
  labelNames: ['type'] as const, // user|service
  registers: [register],
});

export const jwtVerifyTotal = new Counter({
  name: 'jwt_verify_total',
  help: 'Total number of JWT verification attempts',
  labelNames: ['result'] as const, // success|failure
  registers: [register],
});

// Session metrics
export const sessionCreateTotal = new Counter({
  name: 'session_create_total',
  help: 'Total number of sessions created',
  registers: [register],
});

export const sessionDeleteTotal = new Counter({
  name: 'session_delete_total',
  help: 'Total number of sessions deleted',
  labelNames: ['reason'] as const, // logout|expiry|invalidation
  registers: [register],
});

export const activeSessionsGauge = new Gauge({
  name: 'active_sessions_total',
  help: 'Current number of active sessions',
  registers: [register],
});

// API Token metrics
export const apiTokenCreateTotal = new Counter({
  name: 'api_token_create_total',
  help: 'Total number of API tokens created',
  registers: [register],
});

export const apiTokenRevokeTotal = new Counter({
  name: 'api_token_revoke_total',
  help: 'Total number of API tokens revoked',
  registers: [register],
});

export const apiTokenValidateTotal = new Counter({
  name: 'api_token_validate_total',
  help: 'Total number of API token validation attempts',
  labelNames: ['result'] as const, // success|failure
  registers: [register],
});

// Database metrics
export const dbQueryDurationSeconds = new Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of database queries in seconds',
  labelNames: ['operation', 'table'] as const,
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
  registers: [register],
});

export const dbConnectionsActive = new Gauge({
  name: 'db_connections_active',
  help: 'Number of active database connections',
  registers: [register],
});

// Cache metrics
export const cacheOperationTotal = new Counter({
  name: 'cache_operation_total',
  help: 'Total number of cache operations',
  labelNames: ['operation', 'cache_type'] as const, // operation: get|set|del, cache_type: permission|jwt|token|session
  registers: [register],
});

export const cacheOperationDurationSeconds = new Histogram({
  name: 'cache_operation_duration_seconds',
  help: 'Duration of cache operations in seconds',
  labelNames: ['operation', 'cache_type'] as const,
  buckets: [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
  registers: [register],
});

// HTTP request metrics (will be used by middleware)
export const httpRequestDurationSeconds = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'] as const,
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
  registers: [register],
});

export const httpRequestTotal = new Counter({
  name: 'http_request_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'] as const,
  registers: [register],
});

/**
 * Metrics collection utilities
 */
export class MetricsCollector {
  /**
   * Record authentication login attempt
   */
  static recordLoginAttempt(provider: string, method: string, success: boolean, reason?: string): void {
    authLoginTotal.inc({ provider, method });
    
    if (success) {
      authLoginSuccessTotal.inc({ provider, method });
    } else {
      authLoginFailureTotal.inc({ provider, method, reason: reason || 'unknown' });
    }
  }

  /**
   * Record authentication validation with timing
   */
  static recordValidation(
    type: 'session' | 'token',
    method: 'cookie' | 'bearer',
    success: boolean,
    duration: number,
    reason?: string
  ): void {
    authValidateTotal.inc({ type, method });
    authValidateDurationSeconds.observe({ type, method }, duration);
    
    if (success) {
      authValidateSuccessTotal.inc({ type, method });
    } else {
      authValidateFailureTotal.inc({ type, method, reason: reason || 'unknown' });
    }
  }

  /**
   * Update cache hit rate
   */
  static updateCacheHitRate(cacheType: 'permission' | 'jwt' | 'token', hitRate: number): void {
    authCacheHitRate.set({ cache_type: cacheType }, hitRate);
  }

  /**
   * Record JWT operations
   */
  static recordJWTMint(type: 'user' | 'service'): void {
    jwtMintTotal.inc({ type });
  }

  static recordJWTVerify(success: boolean): void {
    jwtVerifyTotal.inc({ result: success ? 'success' : 'failure' });
  }

  /**
   * Record session operations
   */
  static recordSessionCreate(): void {
    sessionCreateTotal.inc();
  }

  static recordSessionDelete(reason: 'logout' | 'expiry' | 'invalidation'): void {
    sessionDeleteTotal.inc({ reason });
  }

  static updateActiveSessionsCount(count: number): void {
    activeSessionsGauge.set(count);
  }

  /**
   * Record API token operations
   */
  static recordTokenCreate(): void {
    apiTokenCreateTotal.inc();
  }

  static recordTokenRevoke(): void {
    apiTokenRevokeTotal.inc();
  }

  static recordTokenValidate(success: boolean): void {
    apiTokenValidateTotal.inc({ result: success ? 'success' : 'failure' });
  }

  /**
   * Record database operations
   */
  static recordDBQuery(operation: string, table: string, duration: number): void {
    dbQueryDurationSeconds.observe({ operation, table }, duration);
  }

  static updateDBConnections(count: number): void {
    dbConnectionsActive.set(count);
  }

  /**
   * Record cache operations
   */
  static recordCacheOperation(
    operation: 'get' | 'set' | 'del',
    cacheType: 'permission' | 'jwt' | 'token' | 'session',
    duration: number
  ): void {
    cacheOperationTotal.inc({ operation, cache_type: cacheType });
    cacheOperationDurationSeconds.observe({ operation, cache_type: cacheType }, duration);
  }

  /**
   * Record HTTP requests
   */
  static recordHTTPRequest(method: string, route: string, statusCode: number, duration: number): void {
    const statusCodeStr = statusCode.toString();
    httpRequestTotal.inc({ method, route, status_code: statusCodeStr });
    httpRequestDurationSeconds.observe({ method, route, status_code: statusCodeStr }, duration);
  }
}

/**
 * Get metrics in Prometheus format
 */
export async function getMetrics(): Promise<string> {
  return register.metrics();
}

/**
 * Clear all metrics (useful for testing)
 */
export function clearMetrics(): void {
  register.clear();
}

/**
 * Get metrics registry (for custom metrics)
 */
export function getRegistry() {
  return register;
}