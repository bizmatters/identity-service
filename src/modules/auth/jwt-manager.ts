import jwt from 'jsonwebtoken';
import { createHash } from 'crypto';

export interface JWTConfig {
  privateKey: string;
  publicKey: string;
  keyId: string;
  expiration: string; // e.g., "10m"
  
  // Optional previous keys for rotation (P1: Key Rotation Support)
  previousPrivateKey?: string;
  previousPublicKey?: string;
  previousKeyId?: string;
}

export interface PlatformJWTPayload {
  sub: string;             // user_id (UUID) OR "service:<service_id>"
  org: string;             // org_id (UUID)
  role: string;            // owner, admin, developer, viewer, OR "system"
  ver: number;             // Membership version (P2: instant revocation)
  aud: string;             // Audience - "platform-services"
  iat: number;             // Issued at (Unix timestamp)
  exp: number;             // Expiration (Unix timestamp, 5-15 minutes from iat)
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

export class JWTManager {
  private activeKeyId: string;
  private previousKeyId: string | undefined;

  constructor(private config: JWTConfig) {
    this.activeKeyId = config.keyId;
    this.previousKeyId = config.previousKeyId;
  }

  /**
   * Mint Platform JWT with kid header and ver claim
   * Requirements: 2.9, 2.10, 6.3, P1: Key Rotation, P2: Membership Versioning
   */
  mintPlatformJWT(userId: string, orgId: string, role: string, membershipVersion: number): string {
    const now = Math.floor(Date.now() / 1000);
    const expiration = this.parseExpiration(this.config.expiration);
    
    const payload: PlatformJWTPayload = {
      sub: userId,
      org: orgId,
      role,
      ver: membershipVersion,
      aud: 'platform-services',
      iat: now,
      exp: now + expiration,
    };

    const options: jwt.SignOptions = {
      algorithm: 'RS256',
      keyid: this.activeKeyId, // P1: Key ID for rotation support
    };

    return jwt.sign(payload, this.config.privateKey, options);
  }

  /**
   * Mint service account JWT for internal services
   * Requirements: 9.1, 9.2, 9.3
   */
  mintServiceJWT(serviceId: string, orgId: string, permissions: string[], expirationHours = 12): string {
    const now = Math.floor(Date.now() / 1000);
    const expiration = expirationHours * 3600; // Convert hours to seconds
    
    const payload: PlatformJWTPayload = {
      sub: `service:${serviceId}`,
      org: orgId,
      role: 'system',
      ver: 1, // Services don't have membership versions
      aud: 'platform-services',
      iat: now,
      exp: now + expiration,
    };

    // Add permissions as custom claim
    const extendedPayload = {
      ...payload,
      permissions,
    };

    const options: jwt.SignOptions = {
      algorithm: 'RS256',
      keyid: this.activeKeyId,
    };

    return jwt.sign(extendedPayload, this.config.privateKey, options);
  }

  /**
   * Verify Platform JWT supporting key rotation
   * Requirements: 2.10, P1: Key Rotation Support
   */
  verifyPlatformJWT(token: string): PlatformJWTPayload {
    try {
      // First try with current key
      const decoded = jwt.verify(token, this.config.publicKey, {
        algorithms: ['RS256'],
      }) as PlatformJWTPayload;

      return decoded;
    } catch (error) {
      // If current key fails and we have a previous key, try that
      if (this.config.previousPublicKey && error instanceof jwt.JsonWebTokenError) {
        try {
          const decoded = jwt.verify(token, this.config.previousPublicKey, {
            algorithms: ['RS256'],
          }) as PlatformJWTPayload;

          return decoded;
        } catch (previousError) {
          // Both keys failed
          throw new Error(`JWT verification failed: ${error.message}`);
        }
      }

      throw new Error(`JWT verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get JWKS for public key distribution (P1: Key Rotation Support)
   * Requirements: 7.8, 8.2
   */
  getJWKS(): JWKS {
    const keys: JWK[] = [];

    // Add current key
    const currentJWK = this.publicKeyToJWK(this.config.publicKey, this.activeKeyId);
    keys.push(currentJWK);

    // Add previous key if available (for rotation support)
    if (this.config.previousPublicKey && this.previousKeyId) {
      const previousJWK = this.publicKeyToJWK(this.config.previousPublicKey, this.previousKeyId);
      keys.push(previousJWK);
    }

    return { keys };
  }

  /**
   * Convert RSA public key to JWK format
   */
  private publicKeyToJWK(publicKey: string, keyId: string): JWK {
    // This is a simplified implementation
    // In production, you'd use a proper crypto library to extract n and e from the RSA key
    const keyHash = createHash('sha256').update(publicKey).digest('hex').substring(0, 16);
    
    return {
      kid: keyId,
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      n: keyHash, // Simplified - should be actual RSA modulus
      e: 'AQAB',  // Standard RSA exponent
    };
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
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: throw new Error(`Invalid expiration unit: ${unit}`);
    }
  }

  /**
   * Validate JWT expiration is within acceptable range (5-15 minutes)
   * Requirements: 6.3
   */
  validateExpirationRange(payload: PlatformJWTPayload): boolean {
    const duration = payload.exp - payload.iat;
    const minExpiration = 5 * 60;  // 5 minutes
    const maxExpiration = 15 * 60; // 15 minutes
    
    return duration >= minExpiration && duration <= maxExpiration;
  }

  /**
   * Check if JWT is near expiry (within buffer time)
   * Used by JWT cache to determine when to refresh
   */
  isNearExpiry(payload: PlatformJWTPayload, bufferSeconds = 60): boolean {
    const now = Math.floor(Date.now() / 1000);
    return (payload.exp - now) <= bufferSeconds;
  }

  /**
   * Extract kid from JWT header without verification
   * Useful for key rotation scenarios
   */
  extractKeyId(token: string): string | null {
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        return null;
      }
      return decoded.header.kid || null;
    } catch {
      return null;
    }
  }

  /**
   * Health check - verify we can sign and verify a test JWT
   */
  healthCheck(): boolean {
    try {
      const testPayload = {
        sub: 'test-user',
        org: 'test-org',
        role: 'developer',
        ver: 1,
        aud: 'platform-services',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300, // 5 minutes
      };

      const token = jwt.sign(testPayload, this.config.privateKey, {
        algorithm: 'RS256',
        keyid: this.activeKeyId,
      });

      const verified = this.verifyPlatformJWT(token);
      return verified.sub === 'test-user';
    } catch {
      return false;
    }
  }
}