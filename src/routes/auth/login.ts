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
 * OIDC Login endpoint with Retool-style UI
 * Requirements: 1.1, 1.2, 1.3
 */
export function loginRoutes(
  fastify: FastifyInstance,
  oidcClient: OIDCClient,
  cache: Redis,
  config: LoginRouteConfig
): void {
  // Serve HTML login page with "Continue with Google" button
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

      // Generate Retool-style HTML login page
      const loginPageHtml = generateLoginPageHtml(targetRedirectUri);

      return reply
        .type('text/html')
        .send(loginPageHtml);
    } catch (error) {
      fastify.log.error(error, 'Login page error');

      return reply.status(500).send({
        error: 'Login page error',
        code: 'LOGIN_PAGE_ERROR',
        message: 'Failed to load login page',
      });
    }
  });

  // OIDC initiation endpoint for Google
  fastify.get('/auth/login/google', {
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

      // Generate authorization URL with PKCE and connection parameter for seamless Google redirect
      const authUrl = await oidcClient.getAuthorizationUrl(state, nonce, codeVerifier, 'google-oauth2');

      // Redirect to Platform_IdP authorize endpoint
      return reply.redirect(authUrl);
    } catch (error) {
      fastify.log.error(error, 'Google login initiation error');

      return reply.status(500).send({
        error: 'Authentication provider error',
        code: 'OIDC_INIT_FAILED',
        message: 'Failed to initiate Google authentication',
      });
    }
  });
}

/**
 * Generate Retool-style HTML login page
 */
function generateLoginPageHtml(redirectUri: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to Platform</title>
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
        
        .login-container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 48px 40px;
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        
        .logo {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            font-weight: bold;
        }
        
        h1 {
            color: #1a1a1a;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .subtitle {
            color: #666;
            font-size: 16px;
            margin-bottom: 32px;
            line-height: 1.5;
        }
        
        .google-button {
            width: 100%;
            background: #4285f4;
            color: white;
            border: none;
            border-radius: 8px;
            padding: 16px 24px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            text-decoration: none;
        }
        
        .google-button:hover {
            background: #3367d6;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(66, 133, 244, 0.3);
        }
        
        .google-button:active {
            transform: translateY(0);
        }
        
        .google-icon {
            width: 20px;
            height: 20px;
            background: white;
            border-radius: 3px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #eee;
            color: #888;
            font-size: 14px;
        }
        
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">P</div>
        <h1>Welcome back</h1>
        <p class="subtitle">Sign in to your platform account to continue</p>
        
        <a href="/auth/login/google?redirect_uri=${encodeURIComponent(redirectUri)}" class="google-button">
            <div class="google-icon">
                <svg width="18" height="18" viewBox="0 0 18 18">
                    <path fill="#4285F4" d="M16.51 8H8.98v3h4.3c-.18 1-.74 1.48-1.6 2.04v2.01h2.6a7.8 7.8 0 0 0 2.38-5.88c0-.57-.05-.66-.15-1.18z"/>
                    <path fill="#34A853" d="M8.98 17c2.16 0 3.97-.72 5.3-1.94l-2.6-2.04a4.8 4.8 0 0 1-2.7.75 4.8 4.8 0 0 1-4.52-3.36H1.83v2.07A8 8 0 0 0 8.98 17z"/>
                    <path fill="#FBBC05" d="M4.46 10.41a4.8 4.8 0 0 1-.25-1.41c0-.49.09-.97.25-1.41V5.52H1.83a8 8 0 0 0 0 7.17l2.63-2.28z"/>
                    <path fill="#EA4335" d="M8.98 3.58c1.32 0 2.5.45 3.44 1.35l2.54-2.54A8 8 0 0 0 8.98 1a8 8 0 0 0-7.15 4.42l2.63 2.28c.63-1.9 2.4-3.12 4.52-3.12z"/>
                </svg>
            </div>
            Continue with Google
        </a>
        
        <div class="footer">
            By signing in, you agree to our 
            <a href="/terms">Terms of Service</a> and 
            <a href="/privacy">Privacy Policy</a>
        </div>
    </div>
</body>
</html>`;
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