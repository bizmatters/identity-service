import pino from 'pino';
import { FastifyRequest, FastifyReply } from 'fastify';
import { randomUUID } from 'crypto';

// Logger configuration based on environment
const isDevelopment = process.env['NODE_ENV'] === 'development' || process.env['NODE_ENV'] === 'local';

// Create base logger with structured JSON format
export const logger = pino({
  level: process.env['LOG_LEVEL'] || (isDevelopment ? 'debug' : 'info'),
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  ...(isDevelopment && {
    transport: {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname',
      },
    },
  }),
});

// Request correlation ID middleware for Fastify
export function requestCorrelationMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
  done: () => void
): void {
  // Generate or extract request ID
  const requestId = (request.headers['x-request-id'] as string) || randomUUID();
  
  // Add request ID to request context
  request.requestId = requestId;
  
  // Set response header
  reply.header('x-request-id', requestId);
  
  // Create child logger with request context and add to request
  const childLogger = logger.child({
    request_id: requestId,
    method: request.method,
    url: request.url,
    user_agent: request.headers['user-agent'],
    ip_address: request.ip,
  });
  
  // Override the request log with our structured logger
  (request as any).log = childLogger;
  
  done();
}

// Structured logging helpers for authentication events
export const authLogger = {
  // Authentication success logging (Requirements 8.3)
  sessionCreated: (data: {
    user_id: string;
    org_id: string;
    ip_address: string;
    user_agent?: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'Session created successfully',
      event_type: 'session_created',
      user_id: data.user_id,
      org_id: data.org_id,
      ip_address: data.ip_address,
      user_agent: data.user_agent,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // API token usage logging (Requirements 8.4)
  tokenUsed: (data: {
    token_id: string;
    user_id: string;
    org_id: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'API token used successfully',
      event_type: 'token_used',
      token_id: data.token_id, // Note: token_id, not token_hash
      user_id: data.user_id,
      org_id: data.org_id,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // Authentication failure logging (Requirements 8.1)
  authenticationFailed: (data: {
    reason: string;
    user_context?: string; // email or token prefix
    ip_address?: string;
    request_id?: string;
  }) => {
    logger.error({
      message: 'Authentication failed',
      event_type: 'authentication_failed',
      failure_reason: data.reason,
      user_context: data.user_context,
      ip_address: data.ip_address,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // Session validation success
  sessionValidated: (data: {
    user_id: string;
    org_id: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'Session validated successfully',
      event_type: 'session_validated',
      user_id: data.user_id,
      org_id: data.org_id,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // Token validation success
  tokenValidated: (data: {
    token_id: string;
    user_id: string;
    org_id: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'API token validated successfully',
      event_type: 'token_validated',
      token_id: data.token_id,
      user_id: data.user_id,
      org_id: data.org_id,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // OIDC flow events
  oidcFlowStarted: (data: {
    provider: string;
    redirect_uri: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'OIDC authentication flow started',
      event_type: 'oidc_flow_started',
      provider: data.provider,
      redirect_uri: data.redirect_uri,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  oidcCallbackReceived: (data: {
    provider: string;
    has_code: boolean;
    request_id?: string;
  }) => {
    logger.info({
      message: 'OIDC callback received',
      event_type: 'oidc_callback_received',
      provider: data.provider,
      has_authorization_code: data.has_code,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // Organization events
  organizationSwitched: (data: {
    user_id: string;
    from_org_id: string;
    to_org_id: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'Organization switched',
      event_type: 'organization_switched',
      user_id: data.user_id,
      from_org_id: data.from_org_id,
      to_org_id: data.to_org_id,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // User provisioning
  userProvisioned: (data: {
    user_id: string;
    external_id: string;
    email: string;
    org_id: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'User provisioned via JIT',
      event_type: 'user_provisioned',
      user_id: data.user_id,
      external_id: data.external_id,
      email: data.email,
      org_id: data.org_id,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // JWT operations
  jwtMinted: (data: {
    user_id: string;
    org_id: string;
    expires_at: string;
    request_id?: string;
  }) => {
    logger.debug({
      message: 'Platform JWT minted',
      event_type: 'jwt_minted',
      user_id: data.user_id,
      org_id: data.org_id,
      expires_at: data.expires_at,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },

  // Service account operations
  serviceTokenIssued: (data: {
    service_id: string;
    org_id: string;
    permissions: string[];
    expires_at: string;
    request_id?: string;
  }) => {
    logger.info({
      message: 'Service account token issued',
      event_type: 'service_token_issued',
      service_id: data.service_id,
      org_id: data.org_id,
      permissions: data.permissions,
      expires_at: data.expires_at,
      request_id: data.request_id,
      timestamp: new Date().toISOString(),
    });
  },
};

// Infrastructure logging helpers
export const infraLogger = {
  // Database connection events
  databaseConnected: () => {
    logger.info({
      message: 'Database connection established',
      event_type: 'database_connected',
      timestamp: new Date().toISOString(),
    });
  },

  databaseError: (error: Error, context?: string) => {
    logger.error({
      message: 'Database error occurred',
      event_type: 'database_error',
      error_message: error.message,
      error_context: context,
      timestamp: new Date().toISOString(),
    });
  },

  // Cache connection events
  cacheConnected: () => {
    logger.info({
      message: 'Cache connection established',
      event_type: 'cache_connected',
      timestamp: new Date().toISOString(),
    });
  },

  cacheError: (error: Error, context?: string) => {
    logger.error({
      message: 'Cache error occurred',
      event_type: 'cache_error',
      error_message: error.message,
      error_context: context,
      timestamp: new Date().toISOString(),
    });
  },

  // External service errors
  externalServiceError: (service: string, error: Error, context?: string) => {
    logger.error({
      message: `External service error: ${service}`,
      event_type: 'external_service_error',
      service_name: service,
      error_message: error.message,
      error_context: context,
      timestamp: new Date().toISOString(),
    });
  },
};

// Extend FastifyRequest interface to include requestId
declare module 'fastify' {
  interface FastifyRequest {
    requestId: string;
  }
}