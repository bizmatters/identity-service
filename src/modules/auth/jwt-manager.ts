import jwt from 'jsonwebtoken';
import { createPublicKey } from 'crypto';

export interface JWTConfig {
  privateKey: string;
  publicKey: string;
  keyId: string;
  expiration: string; // e.g., "10m"
  previousPrivateKey?: string;
  previousPublicKey?: string;
  previousKeyId?: string;
}

export interface PlatformJWTPayload {
  sub: string; // user_id
  org: string; // org_id
  role: string; // owner, admin, developer, viewer
  ver: number; // membership version (P2: instant revocation)
  iat: number; // issued at
  exp: number; // expiration
}

export interface JWKS {
  keys: JWK[];
}

export interface JWK {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  n: string;
  e: string;
}

/**
 * JWT Manager for Platform_JWT tokens with key rotation support
 * Requirements: 2.9, 2.10, 6.3
 */
export class JWTManager {
  constructor(private config: JWTConfig) { }

  /**
   * Mint Platform_JWT with kid header and ver claim
   * Requirements: 2.9, 6.3
   */
  mintPlatformJWT(userId: string, orgId: string, role: string, membershipVersion: number): string {
    const now = Math.floor(Date.now() / 1000);

    const payload: PlatformJWTPayload = {
      sub: userId,
      org: orgId,
      role,
      ver: membershipVersion, // P2: Membership version for instant revocation
      iat: now,
      exp: now + this.parseExpiration(this.config.expiration),
    };

    const options: jwt.SignOptions = {
      algorithm: 'RS256',
      keyid: this.config.keyId, // P1: Key ID for rotation support
    };

    try {
      return jwt.sign(payload, this.config.privateKey, options);
    } catch (error) {
      throw new Error(`Failed to mint JWT: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Verify Platform_JWT supporting key rotation
   * Requirements: 2.10, 6.3
   */
  verifyPlatformJWT(token: string): PlatformJWTPayload {
    try {
      // First try with current key
      try {
        const payload = jwt.verify(token, this.config.publicKey, {
          algorithms: ['RS256'],
        }) as PlatformJWTPayload;

        return payload;
      } catch (currentKeyError) {
        // If current key fails and we have a previous key, try it
        if (this.config.previousPublicKey) {
          try {
            const payload = jwt.verify(token, this.config.previousPublicKey, {
              algorithms: ['RS256'],
            }) as PlatformJWTPayload;

            return payload;
          } catch (previousKeyError) {
            // Both keys failed, throw the original error
            throw currentKeyError;
          }
        } else {
          // No previous key available, throw the original error
          throw currentKeyError;
        }
      }
    } catch (error) {
      throw new Error(`JWT verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get JWKS containing current and previous public keys
   * Requirements: 2.10, 7.8
   */
  getJWKS(): JWKS {
    const keys: JWK[] = [];

    // Add current key
    try {
      const currentJWK = this.publicKeyToJWK(this.config.publicKey, this.config.keyId);
      keys.push(currentJWK);
    } catch (error) {
      throw new Error(`Failed to convert current public key to JWK: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    // Add previous key if available (for key rotation support)
    if (this.config.previousPublicKey && this.config.previousKeyId) {
      try {
        const previousJWK = this.publicKeyToJWK(this.config.previousPublicKey, this.config.previousKeyId);
        keys.push(previousJWK);
      } catch (error) {
        // Log warning but don't fail - previous key is optional
        console.warn('Failed to convert previous public key to JWK:', error);
      }
    }

    return { keys };
  }

  /**
   * Check if JWT is near expiry (within buffer time)
   * Useful for JWT cache to determine when to refresh
   */
  isNearExpiry(token: string, bufferSeconds: number = 60): boolean {
    try {
      const decoded = jwt.decode(token) as PlatformJWTPayload | null;
      if (!decoded || !decoded.exp) {
        return true; // Treat invalid tokens as expired
      }

      const now = Math.floor(Date.now() / 1000);
      return decoded.exp - now <= bufferSeconds;
    } catch (error) {
      return true; // Treat decode errors as expired
    }
  }

  /**
   * Get JWT expiration time
   */
  getExpiration(token: string): number | null {
    try {
      const decoded = jwt.decode(token) as PlatformJWTPayload | null;
      return decoded?.exp || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Convert PEM public key to JWK format
   */
  private publicKeyToJWK(publicKeyPem: string, keyId: string): JWK {
    try {
      const publicKey = createPublicKey(publicKeyPem);
      const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; n?: string; e?: string };

      if (!jwk.n || !jwk.e) {
        throw new Error('Public key missing n or e parameter');
      }

      return {
        kid: keyId,
        kty: jwk.kty,
        alg: 'RS256',
        use: 'sig',
        n: jwk.n,
        e: jwk.e,
      };
    } catch (error) {
      throw new Error(`Failed to convert public key to JWK: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Parse expiration string to seconds
   */
  private parseExpiration(expiration: string): number {
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match || !match[1]) {
      throw new Error(`Invalid expiration format: ${expiration}`);
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 60 * 60 * 24;
      default:
        throw new Error(`Invalid expiration unit: ${unit}`);
    }
  }
}