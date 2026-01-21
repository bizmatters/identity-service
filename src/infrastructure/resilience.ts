import { logger, infraLogger } from './logger.js';

// Retry configuration interface
export interface RetryConfig {
  maxAttempts: number;
  baseDelay: number;
  maxDelay?: number;
  exponential?: boolean;
  jitter?: boolean;
}

// Circuit breaker state
export enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open',
}

// Circuit breaker configuration
export interface CircuitBreakerConfig {
  failureThreshold: number;
  recoveryTimeout: number;
  monitoringPeriod?: number;
}

// Circuit breaker class
export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount = 0;
  private lastFailureTime = 0;
  private successCount = 0;

  constructor(
    private name: string,
    private config: CircuitBreakerConfig
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (Date.now() - this.lastFailureTime < this.config.recoveryTimeout) {
        throw new Error(`Circuit breaker ${this.name} is OPEN`);
      } else {
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
        logger.info({
          message: `Circuit breaker ${this.name} transitioning to HALF_OPEN`,
          event_type: 'circuit_breaker_half_open',
          circuit_name: this.name,
          timestamp: new Date().toISOString(),
        });
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= 3) { // Require 3 successes to close
        this.state = CircuitState.CLOSED;
        this.failureCount = 0;
        logger.info({
          message: `Circuit breaker ${this.name} transitioning to CLOSED`,
          event_type: 'circuit_breaker_closed',
          circuit_name: this.name,
          timestamp: new Date().toISOString(),
        });
      }
    } else if (this.state === CircuitState.CLOSED) {
      this.failureCount = 0;
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      logger.warn({
        message: `Circuit breaker ${this.name} transitioning to OPEN from HALF_OPEN`,
        event_type: 'circuit_breaker_open',
        circuit_name: this.name,
        failure_count: this.failureCount,
        timestamp: new Date().toISOString(),
      });
    } else if (this.state === CircuitState.CLOSED && this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      logger.warn({
        message: `Circuit breaker ${this.name} transitioning to OPEN`,
        event_type: 'circuit_breaker_open',
        circuit_name: this.name,
        failure_count: this.failureCount,
        timestamp: new Date().toISOString(),
      });
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  getFailureCount(): number {
    return this.failureCount;
  }
}

// Retry function with exponential backoff
export async function withRetry<T>(
  operation: () => Promise<T>,
  config: RetryConfig,
  operationName?: string
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    try {
      const result = await operation();
      
      if (attempt > 1 && operationName) {
        logger.info({
          message: `Operation ${operationName} succeeded after retry`,
          event_type: 'retry_success',
          operation_name: operationName,
          attempt_number: attempt,
          timestamp: new Date().toISOString(),
        });
      }
      
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt === config.maxAttempts) {
        if (operationName) {
          logger.error({
            message: `Operation ${operationName} failed after all retries`,
            event_type: 'retry_exhausted',
            operation_name: operationName,
            max_attempts: config.maxAttempts,
            error_message: lastError.message,
            timestamp: new Date().toISOString(),
          });
        }
        break;
      }

      // Calculate delay
      let delay = config.baseDelay;
      if (config.exponential) {
        delay = config.baseDelay * Math.pow(2, attempt - 1);
      }
      
      if (config.maxDelay) {
        delay = Math.min(delay, config.maxDelay);
      }
      
      // Add jitter to prevent thundering herd
      if (config.jitter) {
        delay = delay * (0.5 + Math.random() * 0.5);
      }

      if (operationName) {
        logger.warn({
          message: `Operation ${operationName} failed, retrying`,
          event_type: 'retry_attempt',
          operation_name: operationName,
          attempt_number: attempt,
          max_attempts: config.maxAttempts,
          delay_ms: Math.round(delay),
          error_message: lastError.message,
          timestamp: new Date().toISOString(),
        });
      }

      await sleep(delay);
    }
  }

  throw lastError!;
}

// Sleep utility
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Predefined retry configurations
export const RetryConfigs = {
  // OIDC token exchange: 3 retries with exponential backoff
  NEON_AUTH: {
    maxAttempts: 3,
    baseDelay: 1000, // 1 second
    maxDelay: 8000,  // 8 seconds max
    exponential: true,
    jitter: true,
  } as RetryConfig,

  // Database queries: 2 retries with 100ms delay
  DATABASE: {
    maxAttempts: 2,
    baseDelay: 100,
    exponential: false,
    jitter: false,
  } as RetryConfig,

  // Cache operations: 2 retries with 50ms delay
  CACHE: {
    maxAttempts: 2,
    baseDelay: 50,
    exponential: false,
    jitter: false,
  } as RetryConfig,
};

// Predefined circuit breaker configurations
export const CircuitBreakerConfigs = {
  // Platform_IdP: Open after 5 consecutive failures, half-open after 30s
  NEON_AUTH: {
    failureThreshold: 5,
    recoveryTimeout: 30000, // 30 seconds
  } as CircuitBreakerConfig,

  // Platform_DB: Open after 3 consecutive failures, half-open after 10s
  DATABASE: {
    failureThreshold: 3,
    recoveryTimeout: 10000, // 10 seconds
  } as CircuitBreakerConfig,
};

// Global circuit breakers
export const circuitBreakers = {
  neonAuth: new CircuitBreaker('neon-auth', CircuitBreakerConfigs.NEON_AUTH),
  database: new CircuitBreaker('database', CircuitBreakerConfigs.DATABASE),
};

// Utility functions for common operations
export const resilientOperations = {
  // Neon Auth API call with retry and circuit breaker
  async neonAuthCall<T>(operation: () => Promise<T>, operationName?: string): Promise<T> {
    return circuitBreakers.neonAuth.execute(async () => {
      return withRetry(operation, RetryConfigs.NEON_AUTH, operationName);
    });
  },

  // Database operation with retry
  async databaseCall<T>(operation: () => Promise<T>, operationName?: string): Promise<T> {
    try {
      return await withRetry(operation, RetryConfigs.DATABASE, operationName);
    } catch (error) {
      infraLogger.databaseError(error instanceof Error ? error : new Error(String(error)), operationName);
      throw error;
    }
  },

  // Cache operation with retry
  async cacheCall<T>(operation: () => Promise<T>, operationName?: string): Promise<T> {
    try {
      return await withRetry(operation, RetryConfigs.CACHE, operationName);
    } catch (error) {
      infraLogger.cacheError(error instanceof Error ? error : new Error(String(error)), operationName);
      throw error;
    }
  },
};

// Health check for circuit breakers
export function getCircuitBreakerHealth(): Record<string, { state: CircuitState; failureCount: number }> {
  return {
    neonAuth: {
      state: circuitBreakers.neonAuth.getState(),
      failureCount: circuitBreakers.neonAuth.getFailureCount(),
    },
    database: {
      state: circuitBreakers.database.getState(),
      failureCount: circuitBreakers.database.getFailureCount(),
    },
  };
}