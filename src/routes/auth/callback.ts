import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Type } from '@sinclair/typebox';
import { NeonAuthService } from '../../services/neon-auth.service.js';
import { SessionManager } from '../../modules/auth/session-manager.js';
import { JWTManager } from '../../modules/auth/jwt-manager.js';
import { JWTCache } from '../../modules/auth/jwt-cache.js';

const CallbackQuerySchema = Type.Object({
  code: Type.Optional(Type.String()),
  state: Type.Optional(Type.String()),
  error: Type.Optional(Type.String()),
  error_description: Type.Optional(Type.String()),
  sessionVerifier: Type.Optional(Type.String()),
  redirect_uri: Type.Optional(Type.String()),
});

type CallbackQuery = {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
  sessionVerifier?: string;
  redirect_uri?: string;
};

interface CallbackConfig {
  allowedRedirectUris: string[];
  defaultRedirectUri: string;
  cookieDomain: string;
  cookieSecure: boolean;
}

export function callbackRoutes(
  fastify: FastifyInstance,
  neonAuthService: NeonAuthService,
  sessionManager: SessionManager,
  jwtManager: JWTManager,
  jwtCache: JWTCache,
  config: CallbackConfig
): void {
  /**
   * Handle Neon Auth OAuth callback and create platform session
   * Requirements: 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 3.5, 3.6, 8.1
   */
  fastify.get<{ Querystring: CallbackQuery }>(
    '/auth/callback',
    {
      schema: {
        querystring: CallbackQuerySchema,
      },
    },
    async (request: FastifyRequest<{ Querystring: CallbackQuery }>, reply: FastifyReply) => {
      const { code, state, error, error_description, sessionVerifier, redirect_uri } = request.query;

      try {
        // Check for OAuth errors
        if (error) {
          fastify.log.error({ error, error_description }, 'OAuth callback error');
          return reply.status(400).send({
            error: 'oauth_error',
            message: error_description || error,
          });
        }

        // Validate redirect_uri if provided
        if (redirect_uri && !config.allowedRedirectUris.includes(redirect_uri)) {
          return reply.status(400).send({
            error: 'invalid_redirect_uri',
            message: 'Redirect URI not in allowlist',
          });
        }

        // Handle Neon Auth callback
        const platformContext = await neonAuthService.handleCallback({
          ...(code && { code }),
          ...(state && { state }),
          ...(error && { error }),
          ...(error_description && { error_description }),
          ...(sessionVerifier && { sessionVerifier }),
        });

        // Create Platform session (P0: Session Fixation - always generate new session)
        const sessionId = await sessionManager.createSession(
          platformContext.userId,
          platformContext.orgId,
          platformContext.role
        );

        // Mint Platform JWT with user claims
        const platformJWT = jwtManager.mintPlatformJWT(
          platformContext.userId,
          platformContext.orgId,
          platformContext.role,
          platformContext.version
        );

        // Cache Platform JWT until near-expiry (P2: JWT Cache)
        const jwtPayload = jwtManager.verifyPlatformJWT(platformJWT);
        await jwtCache.set(sessionId, platformContext.orgId, platformJWT, jwtPayload.exp);

        // Set secure cookie with __Host- prefix (P0: Secure Cookie)
        const cookieOptions = {
          path: '/',
          secure: config.cookieSecure,
          httpOnly: true,
          sameSite: 'lax' as const,
          maxAge: 24 * 60 * 60, // 24 hours
        };

        // __Host- prefix requires no domain
        reply.setCookie('__Host-platform_session', sessionId, cookieOptions);

        // Log successful authentication for audit
        fastify.log.info({
          userId: platformContext.userId,
          orgId: platformContext.orgId,
          role: platformContext.role,
          sessionId,
          ip: request.ip,
        }, 'User authenticated successfully');

        // Redirect to dashboard or specified redirect_uri
        const finalRedirectUri = redirect_uri || config.defaultRedirectUri;
        return reply.redirect(302, finalRedirectUri);

      } catch (error) {
        fastify.log.error({ error, query: request.query }, 'Callback handling failed');

        // Return user-friendly error page
        const errorPageHTML = generateErrorPageHTML(
          error instanceof Error ? error.message : 'Authentication failed'
        );
        
        return reply.status(500).type('text/html').send(errorPageHTML);
      }
    }
  );
}

/**
 * Generate error page HTML for authentication failures
 */
function generateErrorPageHTML(errorMessage: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Error</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .error-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 48px;
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .error-icon {
            width: 64px;
            height: 64px;
            background: #ff6b6b;
            border-radius: 50%;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
        }
        
        h1 {
            color: #1a1a1a;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 16px;
        }
        
        .error-message {
            color: #666;
            font-size: 16px;
            margin-bottom: 32px;
            line-height: 1.5;
        }
        
        .retry-button {
            width: 100%;
            background: #667eea;
            border: none;
            border-radius: 8px;
            padding: 16px 24px;
            font-size: 16px;
            font-weight: 500;
            color: white;
            text-decoration: none;
            display: inline-block;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .retry-button:hover {
            background: #5a6fd8;
            transform: translateY(-1px);
        }
        
        .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e1e5e9;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">!</div>
        <h1>Authentication Failed</h1>
        <p class="error-message">${errorMessage}</p>
        
        <a href="/auth/login" class="retry-button">
            Try Again
        </a>
        
        <div class="footer">
            If this problem persists, please contact support.
        </div>
    </div>
</body>
</html>
  `.trim();
}