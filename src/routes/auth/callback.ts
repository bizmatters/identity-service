import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import '@fastify/cookie';
import { Type } from '@sinclair/typebox';
import type { Redis } from 'ioredis';
import type { OIDCClient } from '../../modules/oidc/oidc-client.js';
import type { SessionManager } from '../../modules/auth/session-manager.js';
import type { UserRepository } from '../../modules/user/user-repository.js';
import type { OrgRepository } from '../../modules/org/org-repository.js';

const CallbackQuerySchema = Type.Object({
  code: Type.String(),
  state: Type.String(),
  error: Type.Optional(Type.String()),
  error_description: Type.Optional(Type.String()),
});

interface OIDCState {
  state: string;
  nonce: string;
  code_verifier: string;
  redirect_uri: string;
}

export interface CallbackRouteConfig {
  sessionCookieName: string;
  cookieDomain: string;
  cookieSecure: boolean;
  dashboardUrl: string;
}

/**
 * OIDC Callback endpoint
 * Requirements: 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 3.5, 3.6
 */
export function callbackRoutes(
  fastify: FastifyInstance,
  oidcClient: OIDCClient,
  sessionManager: SessionManager,
  userRepository: UserRepository,
  orgRepository: OrgRepository,
  cache: Redis,
  config: CallbackRouteConfig
): void {
  fastify.get('/auth/callback', {
    schema: {
      querystring: CallbackQuerySchema,
    },
  }, async (request: FastifyRequest<{ Querystring: typeof CallbackQuerySchema.static }>, reply: FastifyReply): Promise<void> => {
    try {
      const { code, state, error, error_description } = request.query;

      // Check for OIDC errors
      if (error) {
        fastify.log.error({ error, error_description }, 'OIDC callback error');
        return reply.status(400).send({
          error: 'Authentication failed',
          code: 'OIDC_ERROR',
          message: error_description || error,
        });
      }

      // Validate state from Hot_Cache
      const stateKey = `oidc:state:${state}`;
      const stateData = await cache.get(stateKey);

      if (!stateData) {
        fastify.log.error({ state }, 'Invalid or expired OIDC state');
        return reply.status(400).send({
          error: 'Invalid or expired authentication state',
          code: 'INVALID_STATE',
          message: 'Authentication state is invalid or has expired',
        });
      }

      const oidcState = JSON.parse(stateData) as OIDCState;

      // Clean up state from cache
      await cache.del(stateKey);

      // Exchange code for tokens via back-channel
      const tokenSet = await oidcClient.exchangeCode(code, oidcState.code_verifier);

      if (!tokenSet.id_token) {
        throw new Error('No ID token received from OIDC provider');
      }

      // Validate ID token signature
      const idTokenClaims = await oidcClient.validateIdToken(tokenSet.id_token);

      // Validate nonce
      if (idTokenClaims.nonce !== oidcState.nonce) {
        fastify.log.error({
          expected: oidcState.nonce,
          received: idTokenClaims.nonce
        }, 'Nonce mismatch');
        return reply.status(400).send({
          error: 'Authentication validation failed',
          code: 'NONCE_MISMATCH',
          message: 'Authentication nonce validation failed',
        });
      }

      // Extract external_id (sub claim)
      const externalId = idTokenClaims.sub;
      const email = idTokenClaims.email;

      // JIT provision user if not exists (atomic INSERT)
      let user = await userRepository.findByExternalId(externalId);
      let defaultOrgId: string;

      if (!user) {
        // Create default organization first
        const orgName = `${email.split('@')[0]}'s Organization`;
        const orgSlug = `${email.split('@')[0]}-org-${Date.now()}`;

        // Create user and organization in transaction
        const result = await userRepository.createUserWithDefaultOrg(externalId, email, orgName, orgSlug);
        user = result.user;
        defaultOrgId = result.organization.id;

        fastify.log.info({
          userId: user.id,
          externalId,
          email,
          orgId: defaultOrgId
        }, 'JIT provisioned new user');
      } else {
        // Update existing user's profile (email sync)
        await userRepository.updateUserProfile(user.id, { email });
        defaultOrgId = user.default_org_id!;

        fastify.log.info({
          userId: user.id,
          externalId,
          email
        }, 'Updated existing user profile');
      }

      // Get user's role in default organization
      const membership = await orgRepository.getUserRole(user.id, defaultOrgId);
      if (!membership) {
        throw new Error('User has no membership in default organization');
      }

      // Create session (this generates a new session ID - P0: Session Fixation prevention)
      const sessionId = await sessionManager.createSession(user.id, defaultOrgId, membership.role);

      // Set secure cookie: __Host-platform_session (P0: Secure Cookie)
      void reply.cookie(config.sessionCookieName, sessionId, {
        httpOnly: true,
        secure: config.cookieSecure,
        sameSite: 'lax',
        path: '/',
        domain: config.cookieDomain,
        maxAge: 7 * 24 * 60 * 60, // 7 days
      });

      // Log successful authentication
      fastify.log.info({
        userId: user.id,
        orgId: defaultOrgId,
        role: membership.role,
        sessionId: sessionId.substring(0, 8) + '...', // Log partial session ID
        ip: request.ip,
        userAgent: request.headers['user-agent'],
      }, 'User authenticated successfully');

      // Redirect to dashboard (or original redirect_uri)
      const redirectUrl = oidcState.redirect_uri || config.dashboardUrl;
      return reply.redirect(redirectUrl);

    } catch (error) {
      fastify.log.error(error, 'Callback endpoint error');

      return reply.status(500).send({
        error: 'Authentication processing failed',
        code: 'CALLBACK_PROCESSING_FAILED',
        message: 'Failed to process authentication callback',
      });
    }
  });
}