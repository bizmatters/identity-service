import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { generators } from 'openid-client';
import type { Redis } from 'ioredis';
import type { OIDCClient } from '../../modules/oidc/oidc-client.js';

const LoginQuerySchema = Type.Object({
  redirect_uri: Type.Optional(Type.String()),
});

interface OIDCState {
  state: string;
  nonce: string;
  code_verifier: string;
  redirect_uri: string;
}

export interface LoginRouteConfig {
  allowedRedirectUris: string[];
  defaultRedirectUri: string;
}

/**
 * OIDC Login endpoint
 * Requirements: 1.1, 1.2, 1.3
 */
export function loginRoutes(
  fastify: FastifyInstance,
  oidcClient: OIDCClient,
  cache: Redis,
  config: LoginRouteConfig
): void {
  fastify.get('/auth/login', {
    schema: {
      querystring: LoginQuerySchema,
    },
  }, async (request: FastifyRequest<{ Querystring: typeof LoginQuerySchema.static }>, reply: FastifyReply): Promise<void> => {
    try {
      const { redirect_uri } = request.query;

      // Use provided redirect_uri or default
      const targetRedirectUri = redirect_uri || config.defaultRedirectUri;

      // Validate redirect_uri against allowlist (P0: Redirect URI Validation)
      if (!config.allowedRedirectUris.includes(targetRedirectUri)) {
        return reply.status(400).send({
          error: 'Invalid redirect URI',
          code: 'INVALID_REDIRECT_URI',
          message: 'The provided redirect_uri is not in the allowed list',
        });
      }

      // Generate OIDC parameters
      const state = generators.state();
      const nonce = generators.nonce();
      const codeVerifier = generators.codeVerifier();

      // Store OIDC state in Hot_Cache with 10-minute TTL
      const oidcState: OIDCState = {
        state,
        nonce,
        code_verifier: codeVerifier,
        redirect_uri: targetRedirectUri,
      };

      const stateKey = `oidc:state:${state}`;
      await cache.setex(stateKey, 600, JSON.stringify(oidcState)); // 10 minutes

      // Generate authorization URL with PKCE
      const authUrl = await oidcClient.getAuthorizationUrl(state, nonce, codeVerifier);

      // Redirect to Platform_IdP authorize endpoint
      return reply.redirect(authUrl);
    } catch (error) {
      fastify.log.error(error, 'Login endpoint error');

      return reply.status(500).send({
        error: 'Authentication provider error',
        code: 'OIDC_INIT_FAILED',
        message: 'Failed to initiate authentication',
      });
    }
  });
}

/**
 * Validate redirect URI against allowlist
 */
export function validateRedirectUri(redirectUri: string, allowedUris: string[]): boolean {
  return allowedUris.includes(redirectUri);
}

/**
 * Parse allowed redirect URIs from environment variable
 */
export function parseAllowedRedirectUris(allowedUrisString: string): string[] {
  return allowedUrisString
    .split(',')
    .map(uri => uri.trim())
    .filter(uri => uri.length > 0);
}