import { FastifyRequest, FastifyReply } from 'fastify';

// Headers that contain sensitive authentication data
const SENSITIVE_HEADERS = [
  'authorization',
  'cookie',
  'x-api-token',
  'token',
  'x-auth-token',
  'api-key',
  'x-api-key',
];

// Body fields that contain sensitive data
const SENSITIVE_BODY_FIELDS = [
  'password',
  'token',
  'secret',
  'api_key',
  'apiKey',
  'privateKey',
  'private_key',
];

/**
 * Redact sensitive headers from log output
 */
export function redactHeaders(headers: Record<string, unknown>): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_HEADERS.includes(lowerKey)) {
      redacted[key] = '[REDACTED]';
    } else {
      redacted[key] = value;
    }
  }
  
  return redacted;
}

/**
 * Redact sensitive fields from request/response body
 */
export function redactBody(body: unknown): unknown {
  if (!body || typeof body !== 'object') {
    return body;
  }

  if (Array.isArray(body)) {
    return body.map(item => redactBody(item));
  }

  const redacted: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(body)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_BODY_FIELDS.some(field => lowerKey.includes(field))) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactBody(value);
    } else {
      redacted[key] = value;
    }
  }
  
  return redacted;
}

/**
 * Fastify hook for automatic PII redaction in logs
 */
export function piiRedactionHook(
  request: FastifyRequest,
  _reply: FastifyReply,
  done: () => void
): void {
  // Create child logger with redacted headers
  const redactedHeaders = redactHeaders(request.headers as Record<string, unknown>);
  
  const childLogger = request.log.child({
    headers: redactedHeaders,
  });
  
  // Replace request logger
  (request as any).log = childLogger;

  done();
}
