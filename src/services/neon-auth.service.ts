/**
 * Neon Auth Service
 * 
 * This service provides a high-level interface for Neon Auth operations.
 * It abstracts the low-level REST API calls and provides a clean interface
 * for the application to interact with Neon Auth.
 */

import { 
  INeonAuthService,
  NeonAuthConfig,
  AuthResult,
  SessionData,
  OAuthCallbackParams,
  PlatformSessionContext,
  PlatformUserData,
  NeonAuthProvider,
  NEON_AUTH_PROVIDERS,
  NEON_AUTH_ERRORS,
  AuthError
} from '../types/neon-auth.js';
import { NeonAuthClient } from '../modules/auth/neon-auth-client.js';
import { UserRepository } from '../modules/user/user-repository.js';
import { OrgRepository } from '../modules/org/org-repository.js';

export class NeonAuthService implements INeonAuthService {
  private client: NeonAuthClient;

  constructor(
    private config: NeonAuthConfig,
    private userRepository: UserRepository,
    private orgRepository: OrgRepository
  ) {
    this.client = new NeonAuthClient(config);
  }

  /**
   * Initiate OAuth flow with specified provider
   * Requirements: 1.1, 1.2, 1.4
   */
  async initiateOAuth(provider: string, redirectUri?: string): Promise<AuthResult> {
    try {
      // Validate provider
      if (!this.isValidProvider(provider)) {
        throw this.createAuthError(
          NEON_AUTH_ERRORS.OAUTH_ERROR,
          `Unsupported OAuth provider: ${provider}`
        );
      }

      // Validate redirect URI if provided
      if (redirectUri && !this.isValidRedirectUri(redirectUri)) {
        throw this.createAuthError(
          NEON_AUTH_ERRORS.INVALID_STATE,
          'Invalid redirect URI'
        );
      }

      // Build callback URL
      const callbackURL = this.buildCallbackURL(redirectUri);

      // Initiate OAuth flow via Neon Auth
      const result = await this.client.signInWithSocial(provider, callbackURL);

      return result;
    } catch (error) {
      if (error instanceof Error && error.message.includes('AuthError')) {
        throw error;
      }
      throw this.createAuthError(
        NEON_AUTH_ERRORS.OAUTH_ERROR,
        `Failed to initiate OAuth: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Handle OAuth callback and create platform session
   * Requirements: 1.4, 1.5, 1.6, 1.7, 1.8, 1.9
   */
  async handleCallback(params: OAuthCallbackParams): Promise<PlatformSessionContext> {
    try {
      // Check for OAuth errors
      if (params.error) {
        throw this.createAuthError(
          NEON_AUTH_ERRORS.OAUTH_ERROR,
          params.error_description || params.error
        );
      }

      // Validate session verifier
      if (!params.sessionVerifier) {
        throw this.createAuthError(
          NEON_AUTH_ERRORS.INVALID_VERIFIER,
          'Missing session verifier'
        );
      }

      // Validate session with Neon Auth
      const sessionData = await this.client.validateSessionVerifier(params.sessionVerifier);
      if (!sessionData) {
        throw this.createAuthError(
          NEON_AUTH_ERRORS.INVALID_VERIFIER,
          'Invalid session verifier'
        );
      }

      // Extract user data
      const userData = this.extractUserData(sessionData);

      // JIT provision user and organization
      const platformContext = await this.provisionUser(userData);

      return platformContext;
    } catch (error) {
      if (error instanceof Error && error.message.includes('AuthError')) {
        throw error;
      }
      throw this.createAuthError(
        NEON_AUTH_ERRORS.OAUTH_ERROR,
        `Callback handling failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Validate session with Neon Auth
   * Requirements: 1.5, 7.1
   */
  async validateSession(sessionVerifier: string): Promise<SessionData | null> {
    try {
      return await this.client.validateSessionVerifier(sessionVerifier);
    } catch (error) {
      // Return null for validation errors instead of throwing
      return null;
    }
  }

  /**
   * Terminate session with Neon Auth
   * Requirements: 1.9
   */
  async terminateSession(): Promise<void> {
    try {
      await this.client.signOut();
    } catch (error) {
      throw this.createAuthError(
        NEON_AUTH_ERRORS.NETWORK_ERROR,
        `Failed to terminate session: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Health check for Neon Auth service
   */
  async healthCheck(): Promise<boolean> {
    return this.client.healthCheck();
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private isValidProvider(provider: string): provider is NeonAuthProvider {
    return Object.values(NEON_AUTH_PROVIDERS).includes(provider as NeonAuthProvider);
  }

  private isValidRedirectUri(redirectUri: string): boolean {
    const allowedUris = process.env['ALLOWED_REDIRECT_URIS']?.split(',') || [];
    return allowedUris.includes(redirectUri);
  }

  private buildCallbackURL(redirectUri?: string): string {
    const baseCallback = this.config.redirectUri;
    if (redirectUri) {
      return `${baseCallback}?redirect_uri=${encodeURIComponent(redirectUri)}`;
    }
    return baseCallback;
  }

  private extractUserData(sessionData: SessionData): PlatformUserData {
    return {
      externalId: sessionData.user.id,
      email: sessionData.user.email,
      ...(sessionData.user.name && { name: sessionData.user.name }),
      emailVerified: sessionData.user.emailVerified,
    };
  }

  private async provisionUser(userData: PlatformUserData): Promise<PlatformSessionContext> {
    // Check if user exists
    let user = await this.userRepository.findByExternalId(userData.externalId);
    let orgId: string;

    if (!user) {
      // Create user with default organization
      const orgName = `${userData.name || userData.email.split('@')[0]}'s Organization`;
      const orgSlug = `org-${userData.externalId.substring(0, 8)}`;

      const result = await this.userRepository.createUserWithDefaultOrg(
        userData.externalId,
        userData.email,
        orgName,
        orgSlug
      );

      user = result.user;
      orgId = result.organization.id;
    } else {
      // Update existing user profile
      await this.userRepository.updateUserProfile(user.id, {
        email: userData.email,
      });
      orgId = user.default_org_id!;
    }

    // Get user's role in organization
    const membership = await this.orgRepository.getUserRole(user.id, orgId);
    if (!membership) {
      throw this.createAuthError(
        NEON_AUTH_ERRORS.INVALID_RESPONSE,
        'User has no membership in organization'
      );
    }

    return {
      userId: user.id,
      orgId,
      role: membership.role,
      version: membership.version,
    };
  }

  private createAuthError(code: string, message: string, details?: Record<string, unknown>): AuthError {
    const error = new Error(message) as Error & AuthError;
    error.code = code;
    error.message = message;
    if (details) {
      error.details = details;
    }
    return error;
  }
}

// ============================================================================
// Factory Function
// ============================================================================

export function createNeonAuthService(
  config: NeonAuthConfig,
  userRepository: UserRepository,
  orgRepository: OrgRepository
): NeonAuthService {
  return new NeonAuthService(config, userRepository, orgRepository);
}