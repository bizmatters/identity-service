import { Issuer, Client, generators, TokenSet, BaseClient } from 'openid-client';
import { createHash } from 'crypto';
import type { Redis } from 'ioredis';

export interface OIDCConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface AuthorizationUrlParams {
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface IDTokenClaims {
  sub: string;
  email: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  nonce?: string | undefined;
}

interface CachedJWKS {
  keys: Record<string, unknown>[];
  expiresAt: number;
}

export class OIDCClient {
  private client: Client | null = null;
  private issuer: Issuer<BaseClient> | null = null;
  private jwksCache: Map<string, CachedJWKS> = new Map();
  private readonly JWKS_CACHE_TTL = 3600 * 1000; // 1 hour in milliseconds

  constructor(
    private config: OIDCConfig,
    private cache: Redis
  ) { }

  /**
   * Initialize the OIDC client by discovering the issuer
   */
  private async initialize(): Promise<void> {
    if (this.client) return;

    try {
      this.issuer = await Issuer.discover(this.config.issuer);
      this.client = new this.issuer.Client({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uris: [this.config.redirectUri],
        response_types: ['code'],
      });
    } catch (error) {
      throw new Error(`Failed to initialize OIDC client: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate authorization URL with PKCE parameters
   * Requirements: 1.1, 1.2
   */
  async getAuthorizationUrl(state: string, nonce: string, codeVerifier: string, connection?: string): Promise<string> {
    await this.initialize();

    if (!this.client) {
      throw new Error('OIDC client not initialized');
    }

    const codeChallenge = generators.codeChallenge(codeVerifier);

    const authParams: Record<string, string> = {
      scope: 'openid email profile',
      response_type: 'code',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    };

    // Add connection parameter for seamless provider redirect (Auth0 style)
    if (connection) {
      authParams['connection'] = connection;
    }

    const authUrl = this.client.authorizationUrl(authParams);

    return authUrl;
  }

  /**
   * Exchange authorization code for tokens using PKCE
   * Requirements: 1.4, 1.5
   */
  async exchangeCode(code: string, codeVerifier: string): Promise<TokenSet> {
    await this.initialize();

    if (!this.client) {
      throw new Error('OIDC client not initialized');
    }

    try {
      const tokenSet = await this.client.callback(
        this.config.redirectUri,
        { code },
        { code_verifier: codeVerifier }
      );

      return tokenSet;
    } catch (error) {
      throw new Error(`Token exchange failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate ID token signature using cached JWKS
   * Requirements: 1.5, 7.1, 7.8
   */
  async validateIdToken(idToken: string): Promise<IDTokenClaims> {
    await this.initialize();

    if (!this.client || !this.issuer) {
      throw new Error('OIDC client not initialized');
    }

    try {
      // Get JWKS (cached with 1-hour TTL)
      await this.getJWKS();

      // Validate the ID token using bracket notation for index signature
      // Note: openid-client v5 might have different API, using cast to allow access
      const client = this.client as unknown as { validateIdToken: (token: string) => Record<string, unknown> };
      const claims = client.validateIdToken(idToken);

      return {
        sub: claims['sub'] as string,
        email: claims['email'] as string,
        iat: claims['iat'] as number,
        exp: claims['exp'] as number,
        aud: claims['aud'] as string,
        iss: claims['iss'] as string,
        nonce: claims['nonce'] as string | undefined,
      };
    } catch (error) {
      throw new Error(`ID token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get JWKS with 1-hour TTL caching (P1)
   * Requirements: 7.8
   */
  async getJWKS(): Promise<Record<string, unknown>[]> {
    await this.initialize();

    if (!this.issuer) {
      throw new Error('OIDC issuer not initialized');
    }

    const issuerHash = createHash('sha256').update(this.config.issuer).digest('hex').substring(0, 16);
    const cacheKey = `jwks:${issuerHash}`;

    // Check in-memory cache first
    const cached = this.jwksCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.keys;
    }

    // Check Redis cache
    try {
      const cachedJwks = await this.cache.get(cacheKey);
      if (cachedJwks) {
        const parsed = JSON.parse(cachedJwks) as CachedJWKS;
        if (Date.now() < parsed.expiresAt) {
          // Update in-memory cache
          this.jwksCache.set(cacheKey, parsed);
          return parsed.keys;
        }
      }
    } catch (error) {
      // Continue to fetch fresh JWKS if cache read fails
    }

    // Fetch fresh JWKS
    try {
      const issuer = this.issuer as unknown as { keystore: () => Promise<{ all: () => { toJWK: () => Record<string, unknown> }[] }> };
      const keystore = await issuer.keystore();
      const keys = keystore.all().map((key) => key.toJWK());

      const expiresAt = Date.now() + this.JWKS_CACHE_TTL;
      const cacheData: CachedJWKS = { keys, expiresAt };

      // Cache in memory
      this.jwksCache.set(cacheKey, cacheData);

      // Cache in Redis
      try {
        await this.cache.setex(cacheKey, Math.floor(this.JWKS_CACHE_TTL / 1000), JSON.stringify(cacheData));
      } catch (error) {
        // Continue even if Redis cache write fails
      }

      return keys;
    } catch (error) {
      throw new Error(`Failed to fetch JWKS: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Clear JWKS cache (useful for testing or forced refresh)
   */
  async clearJWKSCache(): Promise<void> {
    const issuerHash = createHash('sha256').update(this.config.issuer).digest('hex').substring(0, 16);
    const cacheKey = `jwks:${issuerHash}`;

    // Clear in-memory cache
    this.jwksCache.delete(cacheKey);

    // Clear Redis cache
    try {
      await this.cache.del(cacheKey);
    } catch (error) {
      // Continue even if Redis cache clear fails
    }
  }
}