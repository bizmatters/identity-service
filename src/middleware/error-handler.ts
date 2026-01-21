import { FastifyRequest, FastifyReply, FastifyError } from 'fastify';
import { logger } from '../infrastructure/logger.js';

// Error response interface
export interface ErrorResponse {
  error: string;           // Human-readable error message
  code: string;            // Machine-readable error code
  timestamp: number;       // Unix timestamp
  request_id: string;      // Request correlation ID
}

// Custom error classes for different error types
export class AuthenticationError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'AuthenticationError';
    this.code = code;
    this.statusCode = 401;
  }
}

export class AuthorizationError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'AuthorizationError';
    this.code = code;
    this.statusCode = 403;
  }
}

export class ProviderError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'ProviderError';
    this.code = code;
    this.statusCode = 500;
  }
}

export class InfrastructureError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'InfrastructureError';
    this.code = code;
    this.statusCode = 503;
  }
}

// Predefined error instances for common cases (Requirements 10.5, 10.6, 10.7)
export const CommonErrors = {
  // Authentication errors (401)
  SESSION_INVALID: new AuthenticationError('Invalid or expired session', 'SESSION_INVALID'),
  TOKEN_INVALID: new AuthenticationError('Invalid or expired API token', 'TOKEN_INVALID'),
  USER_NOT_MEMBER: new AuthenticationError('User not member of organization', 'USER_NOT_MEMBER'),
  NEON_AUTH_SESSION_INVALID: new AuthenticationError('Neon Auth session invalid', 'NEON_AUTH_SESSION_INVALID'),
  
  // Authorization errors (403)
  INSUFFICIENT_ROLE: new AuthorizationError('User lacks required role for operation', 'INSUFFICIENT_ROLE'),
  ORGANIZATION_ACCESS_DENIED: new AuthorizationError('Organization access denied', 'ORGANIZATION_ACCESS_DENIED'),
  
  // Provider errors (500)
  NEON_AUTH_FAILED: new ProviderError('Authentication provider error', 'NEON_AUTH_FAILED'),
  PLATFORM_IDP_UNAVAILABLE: new ProviderError('Authentication provider error', 'PLATFORM_IDP_UNAVAILABLE'),
  SESSION_VALIDATION_FAILED: new ProviderError('Authentication provider error', 'SESSION_VALIDATION_FAILED'),
  
  // Infrastructure errors (503)
  DATABASE_UNAVAILABLE: new InfrastructureError('Service temporarily unavailable', 'DATABASE_UNAVAILABLE'),
  CACHE_UNAVAILABLE: new InfrastructureError('Service temporarily unavailable', 'CACHE_UNAVAILABLE'),
};

// Error handler middleware for Fastify
export function errorHandler(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply
): void {
  const requestId = request.requestId || 'unknown';
  const timestamp = Math.floor(Date.now() / 1000);

  // Determine status code and error code
  let statusCode: number;
  let errorCode: string;
  let errorMessage: string;

  if (error instanceof AuthenticationError || 
      error instanceof AuthorizationError || 
      error instanceof ProviderError || 
      error instanceof InfrastructureError) {
    // Custom error types
    statusCode = error.statusCode;
    errorCode = error.code;
    errorMessage = error.message;
  } else if (error.statusCode) {
    // Fastify errors with status codes
    statusCode = error.statusCode;
    errorCode = getErrorCodeFromStatus(statusCode);
    errorMessage = getErrorMessageFromStatus(statusCode, error.message);
  } else {
    // Unknown errors - treat as internal server error
    statusCode = 500;
    errorCode = 'INTERNAL_ERROR';
    errorMessage = 'Internal server error';
  }

  // Log error without sensitive data (Requirements 8.1, 8.2)
  const logData: any = {
    message: 'Request error occurred',
    event_type: 'request_error',
    error_code: errorCode,
    error_message: errorMessage,
    status_code: statusCode,
    method: request.method,
    url: request.url,
    user_agent: request.headers['user-agent'],
    ip_address: request.ip,
    request_id: requestId,
    timestamp: new Date().toISOString(),
  };

  // Include stack trace for 500 errors (but not sensitive data)
  if (statusCode >= 500 && error.stack) {
    logData.stack_trace = error.stack;
  }

  // Log at appropriate level
  if (statusCode >= 500) {
    logger.error(logData);
  } else if (statusCode >= 400) {
    logger.warn(logData);
  }

  // Create structured error response
  const errorResponse: ErrorResponse = {
    error: errorMessage,
    code: errorCode,
    timestamp,
    request_id: requestId,
  };

  // Set appropriate headers
  reply.code(statusCode);
  reply.type('application/json');

  // Add retry-after header for 503 errors
  if (statusCode === 503) {
    reply.header('retry-after', '30');
  }

  // Send error response
  reply.send(errorResponse);
}

// Helper function to map HTTP status codes to error codes
function getErrorCodeFromStatus(statusCode: number): string {
  switch (statusCode) {
    case 400:
      return 'BAD_REQUEST';
    case 401:
      return 'UNAUTHORIZED';
    case 403:
      return 'FORBIDDEN';
    case 404:
      return 'NOT_FOUND';
    case 405:
      return 'METHOD_NOT_ALLOWED';
    case 409:
      return 'CONFLICT';
    case 422:
      return 'VALIDATION_ERROR';
    case 429:
      return 'RATE_LIMITED';
    case 500:
      return 'INTERNAL_ERROR';
    case 502:
      return 'BAD_GATEWAY';
    case 503:
      return 'SERVICE_UNAVAILABLE';
    case 504:
      return 'GATEWAY_TIMEOUT';
    default:
      return 'UNKNOWN_ERROR';
  }
}

// Helper function to get user-friendly error messages
function getErrorMessageFromStatus(statusCode: number, originalMessage?: string): string {
  switch (statusCode) {
    case 400:
      return 'Bad request';
    case 401:
      return 'Unauthorized';
    case 403:
      return 'Forbidden';
    case 404:
      return 'Not found';
    case 405:
      return 'Method not allowed';
    case 409:
      return 'Conflict';
    case 422:
      return 'Validation error';
    case 429:
      return 'Too many requests';
    case 500:
      return 'Internal server error';
    case 502:
      return 'Bad gateway';
    case 503:
      return 'Service temporarily unavailable';
    case 504:
      return 'Gateway timeout';
    default:
      return originalMessage || 'Unknown error';
  }
}

// Utility functions for throwing common errors
export const throwError = {
  sessionInvalid: (): never => {
    throw CommonErrors.SESSION_INVALID;
  },
  
  tokenInvalid: (): never => {
    throw CommonErrors.TOKEN_INVALID;
  },
  
  userNotMember: (): never => {
    throw CommonErrors.USER_NOT_MEMBER;
  },
  
  neonAuthFailed: (): never => {
    throw CommonErrors.NEON_AUTH_FAILED;
  },
  
  databaseUnavailable: (): never => {
    throw CommonErrors.DATABASE_UNAVAILABLE;
  },
  
  cacheUnavailable: (): never => {
    throw CommonErrors.CACHE_UNAVAILABLE;
  },
  
  insufficientRole: (): never => {
    throw CommonErrors.INSUFFICIENT_ROLE;
  },
  
  organizationAccessDenied: (): never => {
    throw CommonErrors.ORGANIZATION_ACCESS_DENIED;
  },
};