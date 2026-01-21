/**
 * Neon Auth Configuration Manager
 * 
 * This module manages all Neon Auth configuration settings.
 * It provides a centralized place to manage environment variables,
 * default values, and configuration validation.
 */

import {
  NeonAuthConfig,
  NeonAuthEnvironmentConfig,
  NeonAuthEndpoints,
  NEON_AUTH_PROVIDERS,
} from '../types/neon-auth.js';
import { CONFIG } from './index.js';

// ============================================================================
// Default Configuration Values
// ============================================================================

const DEFAULT_NEON_AUTH_CONFIG = {
  timeout: 10000, // 10 seconds
  retryAttempts: 3,
  defaultProvider: NEON_AUTH_PROVIDERS.GOOGLE,
} as const;

const DEFAULT_ENDPOINTS: NeonAuthEndpoints = {
  signInEmail: '/sign-in/email',
  signUpEmail: '/sign-up/email',
  signInSocial: '/sign-in/social',
  getSession: '/get-session',
  signOut: '/sign-out',
  health: '/health',
} as const;

// ============================================================================
// Configuration Builder
// ============================================================================

export class NeonAuthConfigManager {
  private static instance: NeonAuthConfigManager;
  private config: NeonAuthConfig;
  private environmentConfig: NeonAuthEnvironmentConfig;

  private constructor() {
    this.environmentConfig = this.loadEnvironmentConfig();
    this.config = this.buildConfig();
    this.validateConfig();
  }

  public static getInstance(): NeonAuthConfigManager {
    if (!NeonAuthConfigManager.instance) {
      NeonAuthConfigManager.instance = new NeonAuthConfigManager();
    }
    return NeonAuthConfigManager.instance;
  }

  /**
   * Get the main Neon Auth configuration
   */
  public getConfig(): NeonAuthConfig {
    return { ...this.config };
  }

  /**
   * Get environment-specific configuration
   */
  public getEnvironmentConfig(): NeonAuthEnvironmentConfig {
    return { ...this.environmentConfig };
  }

  /**
   * Get API endpoints configuration
   */
  public getEndpoints(): NeonAuthEndpoints {
    return { ...DEFAULT_ENDPOINTS };
  }

  /**
   * Get full endpoint URL for a specific endpoint
   */
  public getEndpointUrl(endpoint: keyof NeonAuthEndpoints): string {
    const endpoints = this.getEndpoints();
    return `${this.config.baseURL}${endpoints[endpoint]}`;
  }

  /**
   * Check if a redirect URI is allowed
   */
  public isAllowedRedirectUri(uri: string): boolean {
    return this.environmentConfig.ALLOWED_REDIRECT_URIS.includes(uri);
  }

  /**
   * Get allowed redirect URIs
   */
  public getAllowedRedirectUris(): string[] {
    return [...this.environmentConfig.ALLOWED_REDIRECT_URIS];
  }

  /**
   * Reload configuration from environment
   */
  public reloadConfig(): void {
    this.environmentConfig = this.loadEnvironmentConfig();
    this.config = this.buildConfig();
    this.validateConfig();
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private loadEnvironmentConfig(): NeonAuthEnvironmentConfig {
    const allowedUris = process.env['ALLOWED_REDIRECT_URIS']?.split(',') || [];
    
    return {
      NEON_AUTH_URL: process.env['NEON_AUTH_URL'] || 'https://ep-late-cherry-afaerbwj.neonauth.c-2.us-west-2.aws.neon.tech/neondb/auth',
      NEON_AUTH_REDIRECT_URI: CONFIG.NEON_AUTH_REDIRECT_URI as string,
      ALLOWED_REDIRECT_URIS: allowedUris,
      NEON_AUTH_TIMEOUT: parseInt(process.env['NEON_AUTH_TIMEOUT'] || String(DEFAULT_NEON_AUTH_CONFIG.timeout), 10),
      NEON_AUTH_RETRY_ATTEMPTS: parseInt(process.env['NEON_AUTH_RETRY_ATTEMPTS'] || String(DEFAULT_NEON_AUTH_CONFIG.retryAttempts), 10),
    };
  }

  private buildConfig(): NeonAuthConfig {
    return {
      baseURL: this.environmentConfig.NEON_AUTH_URL,
      redirectUri: this.environmentConfig.NEON_AUTH_REDIRECT_URI,
    };
  }

  private validateConfig(): void {
    const errors: string[] = [];

    // Validate required fields
    if (!this.config.baseURL) {
      errors.push('NEON_AUTH_URL is required');
    }

    if (!this.config.redirectUri) {
      errors.push('NEON_AUTH_REDIRECT_URI is required');
    }

    // Validate URL format
    try {
      new URL(this.config.baseURL);
    } catch {
      errors.push('NEON_AUTH_URL must be a valid URL');
    }

    try {
      new URL(this.config.redirectUri);
    } catch {
      errors.push('NEON_AUTH_REDIRECT_URI must be a valid URL');
    }

    // Validate timeout and retry values
    if (this.environmentConfig.NEON_AUTH_TIMEOUT < 1000) {
      errors.push('NEON_AUTH_TIMEOUT must be at least 1000ms');
    }

    if (this.environmentConfig.NEON_AUTH_RETRY_ATTEMPTS < 0) {
      errors.push('NEON_AUTH_RETRY_ATTEMPTS must be non-negative');
    }

    if (errors.length > 0) {
      throw new Error(`Neon Auth configuration validation failed:\n${errors.join('\n')}`);
    }
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Get the current Neon Auth configuration
 */
export function getNeonAuthConfig(): NeonAuthConfig {
  return NeonAuthConfigManager.getInstance().getConfig();
}

/**
 * Get environment configuration
 */
export function getNeonAuthEnvironmentConfig(): NeonAuthEnvironmentConfig {
  return NeonAuthConfigManager.getInstance().getEnvironmentConfig();
}

/**
 * Get API endpoints
 */
export function getNeonAuthEndpoints(): NeonAuthEndpoints {
  return NeonAuthConfigManager.getInstance().getEndpoints();
}

/**
 * Check if redirect URI is allowed
 */
export function isAllowedRedirectUri(uri: string): boolean {
  return NeonAuthConfigManager.getInstance().isAllowedRedirectUri(uri);
}

/**
 * Get endpoint URL
 */
export function getNeonAuthEndpointUrl(endpoint: keyof NeonAuthEndpoints): string {
  return NeonAuthConfigManager.getInstance().getEndpointUrl(endpoint);
}