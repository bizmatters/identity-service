import { createHmac, randomBytes } from 'crypto';
import { TokenRepository } from '../token/token-repository.js';
import { TokenCache } from './token-cache.js';

export interface ApiTokenResult {
  tokenId: string;
  token: string; // Plaintext token returned once
  description: string;
  expiresAt: Date | null;
}

export interface TokenValidationResult {
  userId: string;
  orgId: string;
  role: string;
  tokenId: string;
}

export class TokenManager {
  private tokenRepository: TokenRepository;
  private tokenCache: TokenCache;
  private tokenPepper: string;

  constructor(
    tokenRepository: TokenRepository,
    tokenCache: TokenCache,
    tokenPepper: string
  ) {
    this.tokenRepository = tokenRepository;
    this.tokenCache = tokenCache;
    this.tokenPepper = tokenPepper;
  }

  /**
   * Create API token with sk_live_ prefix
   * @param userId - User ID
   * @param orgId - Organization ID
   * @param description - Token description
   * @param expiresAt - Optional expiration date
   * @returns Token data with plaintext token
   */
  async createApiToken(
    userId: string,
    orgId: string,
    description: string,
    expiresAt?: Date
  ): Promise<ApiTokenResult> {
    // Generate random token with sk_live_ prefix
    const randomPart = randomBytes(32).toString('hex'); // 64 characters
    const token = `sk_live_${randomPart}`;
    
    // Hash token with HMAC-SHA256 using pepper for brute-force protection
    const tokenHash = this.hashToken(token);
    
    // Store hashed token in database
    const tokenData = await this.tokenRepository.createToken(
      userId,
      orgId,
      tokenHash,
      description,
      expiresAt
    );

    return {
      tokenId: tokenData.id,
      token, // Return plaintext token once
      description: tokenData.description,
      expiresAt: tokenData.expires_at,
    };
  }

  /**
   * Validate API token with HMAC-SHA256 hash lookup
   * @param token - Plaintext API token
   * @returns Token validation result or throws 401
   */
  async validateApiToken(token: string): Promise<TokenValidationResult> {
    // Validate token format
    if (!token.startsWith('sk_live_') || token.length !== 72) { // sk_live_ (8) + 64 hex chars
      throw new Error('Invalid token format');
    }

    // Hash token for lookup
    const tokenHash = this.hashToken(token);
    const tokenHashPrefix = tokenHash.substring(0, 8); // First 8 chars for cache key

    // Check cache first (P2 optimization)
    const cached = await this.tokenCache.get(tokenHashPrefix);
    if (cached) {
      return {
        userId: cached.userId,
        orgId: cached.orgId,
        role: cached.role,
        tokenId: '', // Not stored in cache
      };
    }

    // Lookup in database
    const tokenData = await this.tokenRepository.findByTokenHash(tokenHash);
    if (!tokenData) {
      throw new Error('Invalid or expired token');
    }

    // For now, assume 'member' role - will be enhanced when user roles are implemented
    const role = 'member';

    // Cache for future requests (P2 optimization)
    await this.tokenCache.set(tokenHashPrefix, tokenData.user_id, tokenData.org_id, role);

    return {
      userId: tokenData.user_id,
      orgId: tokenData.org_id,
      role,
      tokenId: tokenData.id,
    };
  }

  /**
   * Revoke API token
   * @param tokenId - Token ID to revoke
   */
  async revokeApiToken(tokenId: string): Promise<void> {
    await this.tokenRepository.deleteToken(tokenId);
    // Note: Cache invalidation would require storing tokenHash->tokenHashPrefix mapping
    // For now, cache will expire naturally in 60s
  }

  /**
   * Hash token using HMAC-SHA256 with pepper for brute-force protection
   * @param token - Plaintext token
   * @returns HMAC-SHA256 hash
   */
  private hashToken(token: string): string {
    return createHmac('sha256', this.tokenPepper)
      .update(token)
      .digest('hex');
  }
}