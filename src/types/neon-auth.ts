/**
 * Neon Auth Types and Interfaces
 * 
 * This file contains all type definitions for Neon Auth integration.
 * Centralizing these types makes it easier to maintain and update
 * the Neon Auth integration in the future.
 */

// ============================================================================
// Configuration Interfaces
// ============================================================================

export interface NeonAuthConfig {
  baseURL: string;
  redirectUri: string;
}

export interface NeonAuthEndpoints {
  signInEmail: string;
  signUpEmail: string;
  signInSocial: string;
  getSession: string;
  signOut: string;
  health: string;
}

// ============================================================================
// Request/Response Interfaces
// ============================================================================

export interface SignInEmailRequest {
  email: string;
  password: string;
}

export interface SignUpEmailRequest {
  email: string;
  password: string;
  name: string;
}

export interface SignInSocialRequest {
  provider: string;
  callbackURL: string;
}

export interface GetSessionRequest {
  sessionVerifier?: string;
}

// ============================================================================
// Neon Auth API Response Types
// ============================================================================

export interface NeonAuthResponse {
  user?: BetterAuthUser;
  session?: BetterAuthSession;
  redirect?: boolean;
  url?: string;
  error?: string;
  message?: string;
}

export interface BetterAuthUser {
  id: string;
  email: string;
  name?: string;
  image?: string;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface BetterAuthSession {
  id: string;
  userId: string;
  expiresAt: Date;
  token: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface SessionData {
  session: BetterAuthSession;
  user: BetterAuthUser;
}

// ============================================================================
// Platform Auth Result Types
// ============================================================================

export interface AuthResult {
  redirect: boolean;
  url?: string;
  token?: string;
  user?: BetterAuthUser;
  session?: BetterAuthSession;
}

export interface AuthError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

// ============================================================================
// OAuth Flow Types
// ============================================================================

export interface OAuthState {
  state: string;
  nonce: string;
  redirect_uri?: string;
  provider: string;
}

export interface OAuthCallbackParams {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
  sessionVerifier?: string;
}

// ============================================================================
// Platform Integration Types
// ============================================================================

export interface PlatformUserData {
  externalId: string;
  email: string;
  name?: string;
  emailVerified: boolean;
}

export interface PlatformSessionContext {
  userId: string;
  orgId: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: number;
}

// ============================================================================
// Service Interface Definitions
// ============================================================================

export interface INeonAuthClient {
  signInWithEmail(email: string, password: string): Promise<AuthResult>;
  signUpWithEmail(email: string, password: string, name: string): Promise<AuthResult>;
  signInWithSocial(provider: string, callbackURL: string): Promise<AuthResult>;
  getSession(): Promise<SessionData | null>;
  signOut(): Promise<void>;
  validateSessionVerifier(verifier: string): Promise<SessionData | null>;
  healthCheck(): Promise<boolean>;
}

export interface INeonAuthService {
  initiateOAuth(provider: string, redirectUri?: string): Promise<AuthResult>;
  handleCallback(params: OAuthCallbackParams): Promise<PlatformSessionContext>;
  validateSession(sessionVerifier: string): Promise<SessionData | null>;
  terminateSession(): Promise<void>;
}

// ============================================================================
// Configuration Constants
// ============================================================================

export const NEON_AUTH_PROVIDERS = {
  GOOGLE: 'google'
} as const;

export type NeonAuthProvider = typeof NEON_AUTH_PROVIDERS[keyof typeof NEON_AUTH_PROVIDERS];

export const NEON_AUTH_ERRORS = {
  INVALID_CREDENTIALS: 'invalid_credentials',
  INVALID_STATE: 'invalid_state',
  INVALID_VERIFIER: 'invalid_verifier',
  NETWORK_ERROR: 'network_error',
  INVALID_RESPONSE: 'invalid_response',
  OAUTH_ERROR: 'oauth_error',
} as const;

export type NeonAuthErrorCode = typeof NEON_AUTH_ERRORS[keyof typeof NEON_AUTH_ERRORS];

// ============================================================================
// Utility Types
// ============================================================================

export type NeonAuthMethod = 'email' | 'social';

export interface NeonAuthMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  lastHealthCheck: Date | null;
}

// ============================================================================
// Environment Configuration
// ============================================================================

export interface NeonAuthEnvironmentConfig {
  NEON_AUTH_URL: string;
  NEON_AUTH_REDIRECT_URI: string;
  ALLOWED_REDIRECT_URIS: string[];
  NEON_AUTH_TIMEOUT: number;
  NEON_AUTH_RETRY_ATTEMPTS: number;
}