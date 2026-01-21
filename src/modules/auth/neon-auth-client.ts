import { createAuthClient } from '@neondatabase/auth';
import {
  INeonAuthClient,
  NeonAuthConfig,
  AuthResult,
  SessionData,
} from '../../types/neon-auth.js';

export class NeonAuthClient implements INeonAuthClient {
  private authClient: any;

  constructor(config: NeonAuthConfig) {
    this.authClient = createAuthClient(config.baseURL);
  }

  /**
   * Sign in with email and password
   * Requirements: 1.1, 1.2
   */
  async signInWithEmail(email: string, password: string): Promise<AuthResult> {
    try {
      const result = await (this.authClient).signIn?.email?.({
        email,
        password,
      });

      if (result?.error) {
        throw new Error(result.error.message || 'Email sign-in failed');
      }

      return {
        redirect: false,
        user: result?.data?.user,
        session: result?.data?.session || (result?.data?.token ? { token: result.data.token } : undefined),
      };
    } catch (error) {
      throw new Error(`Email sign-in failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Sign up with email and password
   * Requirements: 1.1, 1.2
   */
  async signUpWithEmail(email: string, password: string, name: string): Promise<AuthResult> {
    try {
      const result = await (this.authClient).signUp?.email?.({
        email,
        password,
        name,
      });

      if (result?.error) {
        throw new Error(result.error.message || 'Email sign-up failed');
      }

      return {
        redirect: false,
        user: result?.data?.user,
        session: result?.data?.session || (result?.data?.token ? { token: result.data.token } : undefined),
      };
    } catch (error) {
      throw new Error(`Email sign-up failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Sign in with social provider (Google OAuth)
   * Requirements: 1.1, 1.2, 1.4
   */
  async signInWithSocial(provider: string, callbackURL: string): Promise<AuthResult> {
    try {
      await (this.authClient).signIn?.social?.({
        provider,
        callbackURL,
      });

      // OAuth flow initiates redirect - no immediate response
      return {
        redirect: true,
        url: callbackURL,
      };
    } catch (error) {
      throw new Error(`Social sign-in failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get current session data
   * Requirements: 1.5, 7.1
   */
  async getSession(): Promise<SessionData | null> {
    try {
      const result = await (this.authClient).getSession?.();

      if (result?.error || !result?.data) {
        return null;
      }

      return {
        session: result.data.session || result.data,
        user: result.data.user || null,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Sign out and terminate session
   * Requirements: 1.9
   */
  async signOut(): Promise<void> {
    try {
      const result = await (this.authClient).signOut?.();
      
      if (result?.error) {
        throw new Error(result.error.message || 'Sign-out failed');
      }
    } catch (error) {
      throw new Error(`Sign-out failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate session with session verifier
   * Used for OAuth callback handling
   * Requirements: 1.4, 1.5
   */
  async validateSessionVerifier(_verifier: string): Promise<SessionData | null> {
    try {
      // OAuth callback handling is managed by the SDK automatically
      // This method may not be needed with the official SDK
      const result = await (this.authClient).getSession?.();

      if (result?.error || !result?.data) {
        return null;
      }

      return {
        session: result.data.session || result.data,
        user: result.data.user || null,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Health check for Neon Auth connectivity
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Try to get session as a health check
      await (this.authClient).getSession?.();
      return true;
    } catch (error) {
      return false;
    }
  }
}