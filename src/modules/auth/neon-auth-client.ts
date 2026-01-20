import {
  INeonAuthClient,
  NeonAuthConfig,
  AuthResult,
  SessionData,
  NeonAuthResponse,
} from '../../types/neon-auth.js';

export class NeonAuthClient implements INeonAuthClient {
  constructor(
    private config: NeonAuthConfig
  ) {}

  /**
   * Sign in with email and password
   * Requirements: 1.1, 1.2
   */
  async signInWithEmail(email: string, password: string): Promise<AuthResult> {
    try {
      const response = await fetch(`${this.config.baseURL}/sign-in/email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.secret}`,
        },
        body: JSON.stringify({
          email,
          password,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json() as NeonAuthResponse;

      if (!result.user || !result.session) {
        throw new Error('Invalid response from Neon Auth');
      }

      return {
        redirect: false,
        user: result.user,
        session: result.session,
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
      const response = await fetch(`${this.config.baseURL}/sign-up/email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.secret}`,
        },
        body: JSON.stringify({
          email,
          password,
          name,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json() as NeonAuthResponse;

      if (!result.user || !result.session) {
        throw new Error('Invalid response from Neon Auth');
      }

      return {
        redirect: false,
        user: result.user,
        session: result.session,
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
      const response = await fetch(`${this.config.baseURL}/sign-in/social`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.secret}`,
        },
        body: JSON.stringify({
          provider,
          callbackURL,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json() as NeonAuthResponse;

      // If redirect is needed for OAuth flow
      if (result.redirect && result.url) {
        return {
          redirect: true,
          url: result.url,
        };
      }

      // If session is created directly
      if (result.user && result.session) {
        return {
          redirect: false,
          user: result.user,
          session: result.session,
        };
      }

      throw new Error('Invalid response from Neon Auth');
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
      const response = await fetch(`${this.config.baseURL}/get-session`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.secret}`,
        },
      });

      if (!response.ok) {
        return null;
      }

      const result = await response.json() as NeonAuthResponse;
      
      if (!result || !result.session || !result.user) {
        return null;
      }

      return {
        session: result.session,
        user: result.user,
      };
    } catch (error) {
      // Return null for invalid sessions instead of throwing
      return null;
    }
  }

  /**
   * Sign out and terminate session
   * Requirements: 1.9
   */
  async signOut(): Promise<void> {
    try {
      const response = await fetch(`${this.config.baseURL}/sign-out`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.secret}`,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
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
  async validateSessionVerifier(verifier: string): Promise<SessionData | null> {
    try {
      const response = await fetch(`${this.config.baseURL}/get-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.secret}`,
        },
        body: JSON.stringify({
          sessionVerifier: verifier,
        }),
      });

      if (!response.ok) {
        return null;
      }

      const result = await response.json() as NeonAuthResponse;

      if (!result || !result.session || !result.user) {
        return null;
      }

      return {
        session: result.session,
        user: result.user,
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
      const response = await fetch(`${this.config.baseURL}/health`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.secret}`,
        },
      });
      
      return response.ok;
    } catch (error) {
      return false;
    }
  }
}