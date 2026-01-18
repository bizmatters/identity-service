import { FastifyInstance } from 'fastify';
import jwt from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

export interface MockOIDCConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  port: number;
}

export class MockOIDCProvider {
  private keyPair: { publicKey: string; privateKey: string };
  private server: FastifyInstance | null = null;

  constructor(private config: MockOIDCConfig) {
    // Generate test key pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.keyPair = { publicKey, privateKey };
  }

  async start(fastify: FastifyInstance): Promise<void> {
    this.server = fastify;

    // OIDC Discovery endpoint
    fastify.get('/.well-known/openid-configuration', async (request, reply) => {
      return {
        issuer: this.config.issuer,
        authorization_endpoint: `${this.config.issuer}/authorize`,
        token_endpoint: `${this.config.issuer}/token`,
        jwks_uri: `${this.config.issuer}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'email', 'profile'],
        claims_supported: ['sub', 'email', 'given_name', 'family_name'],
      };
    });

    // JWKS endpoint
    fastify.get('/.well-known/jwks.json', async (request, reply) => {
      const jwk = this.publicKeyToJWK(this.keyPair.publicKey);
      return {
        keys: [jwk],
      };
    });

    // Authorization endpoint (redirects back with code)
    fastify.get('/authorize', async (request, reply) => {
      const query = request.query as any;
      const { redirect_uri, state, client_id } = query;

      if (client_id !== this.config.clientId) {
        return reply.status(400).send({ error: 'invalid_client' });
      }

      // Generate mock authorization code
      const code = 'mock-auth-code-' + Date.now();
      
      // Redirect back with code and state
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', code);
      redirectUrl.searchParams.set('state', state);

      return reply.redirect(redirectUrl.toString());
    });

    // Token endpoint
    fastify.post('/token', async (request, reply) => {
      const body = request.body as any;
      const { client_id, client_secret, code, code_verifier } = body;

      if (client_id !== this.config.clientId || client_secret !== this.config.clientSecret) {
        return reply.status(401).send({ error: 'invalid_client' });
      }

      if (!code || !code.startsWith('mock-auth-code-')) {
        return reply.status(400).send({ error: 'invalid_grant' });
      }

      // Generate mock ID token
      const idToken = this.generateIdToken({
        sub: '550e8400-e29b-41d4-a716-446655440000',
        email: 'test@example.com',
        given_name: 'Test',
        family_name: 'User',
        nonce: 'test-nonce-12345',
      });

      return {
        access_token: 'mock-access-token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600,
      };
    });

    await fastify.listen({ port: this.config.port, host: '127.0.0.1' });
  }

  async stop(): Promise<void> {
    if (this.server) {
      await this.server.close();
      this.server = null;
    }
  }

  private generateIdToken(claims: any): string {
    const payload = {
      ...claims,
      iss: this.config.issuer,
      aud: this.config.clientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    return jwt.sign(payload, this.keyPair.privateKey, {
      algorithm: 'RS256',
      keyid: 'test-key-id-1',
    });
  }

  private publicKeyToJWK(publicKeyPem: string): any {
    // This is a simplified JWK conversion for testing
    // In real implementation, use proper crypto libraries
    return {
      kid: 'test-key-id-1',
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      n: 'test-modulus-placeholder',
      e: 'AQAB',
    };
  }

  getIssuer(): string {
    return this.config.issuer;
  }

  getKeyPair(): { publicKey: string; privateKey: string } {
    return this.keyPair;
  }
}