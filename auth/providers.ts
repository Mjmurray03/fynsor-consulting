/**
 * OAuth 2.0 + PKCE Authentication Providers
 * Institutional-grade security implementation for Fynsor Consulting
 */

import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import { z } from 'zod';

// Configuration schema
const OAuthConfigSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  redirectUri: z.string().url(),
  scope: z.string().array().default(['openid', 'profile', 'email']),
});

// PKCE Implementation
export class PKCEService {
  private static readonly CODE_VERIFIER_LENGTH = 128;
  private static readonly CODE_CHALLENGE_METHOD = 'S256';

  static generateCodeVerifier(): string {
    return crypto
      .randomBytes(Math.ceil(this.CODE_VERIFIER_LENGTH * 3 / 4))
      .toString('base64url')
      .slice(0, this.CODE_VERIFIER_LENGTH);
  }

  static generateCodeChallenge(verifier: string): string {
    return crypto
      .createHash('sha256')
      .update(verifier)
      .digest('base64url');
  }

  static generateState(): string {
    return crypto.randomBytes(32).toString('base64url');
  }
}

// Base OAuth Provider
abstract class BaseOAuthProvider {
  protected config: z.infer<typeof OAuthConfigSchema>;
  protected supabase: ReturnType<typeof createClient>;

  constructor(config: z.infer<typeof OAuthConfigSchema>) {
    this.config = OAuthConfigSchema.parse(config);
    this.supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_ANON_KEY!
    );
  }

  abstract getAuthorizationUrl(codeChallenge: string, state: string): string;
  abstract exchangeCodeForToken(code: string, codeVerifier: string): Promise<any>;
  abstract getUserInfo(accessToken: string): Promise<any>;

  protected buildAuthUrl(baseUrl: string, params: Record<string, string>): string {
    const searchParams = new URLSearchParams(params);
    return `${baseUrl}?${searchParams.toString()}`;
  }
}

// Google OAuth Provider
export class GoogleOAuthProvider extends BaseOAuthProvider {
  private static readonly AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
  private static readonly TOKEN_URL = 'https://oauth2.googleapis.com/token';
  private static readonly USER_INFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';

  getAuthorizationUrl(codeChallenge: string, state: string): string {
    return this.buildAuthUrl(GoogleOAuthProvider.AUTHORIZATION_URL, {
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scope.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      access_type: 'offline',
      prompt: 'consent',
    });
  }

  async exchangeCodeForToken(code: string, codeVerifier: string): Promise<any> {
    const response = await fetch(GoogleOAuthProvider.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        code_verifier: codeVerifier,
        grant_type: 'authorization_code',
        redirect_uri: this.config.redirectUri,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    return response.json();
  }

  async getUserInfo(accessToken: string): Promise<any> {
    const response = await fetch(GoogleOAuthProvider.USER_INFO_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    return response.json();
  }
}

// Microsoft OAuth Provider
export class MicrosoftOAuthProvider extends BaseOAuthProvider {
  private static readonly AUTHORIZATION_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
  private static readonly TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
  private static readonly USER_INFO_URL = 'https://graph.microsoft.com/v1.0/me';

  getAuthorizationUrl(codeChallenge: string, state: string): string {
    return this.buildAuthUrl(MicrosoftOAuthProvider.AUTHORIZATION_URL, {
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: this.config.scope.join(' '),
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      response_mode: 'query',
    });
  }

  async exchangeCodeForToken(code: string, codeVerifier: string): Promise<any> {
    const response = await fetch(MicrosoftOAuthProvider.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        code_verifier: codeVerifier,
        grant_type: 'authorization_code',
        redirect_uri: this.config.redirectUri,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    return response.json();
  }

  async getUserInfo(accessToken: string): Promise<any> {
    const response = await fetch(MicrosoftOAuthProvider.USER_INFO_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    return response.json();
  }
}

// OAuth Manager
export class OAuthManager {
  private providers: Map<string, BaseOAuthProvider> = new Map();

  constructor() {
    this.initializeProviders();
  }

  private initializeProviders(): void {
    // Google OAuth
    if (process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET) {
      this.providers.set('google', new GoogleOAuthProvider({
        clientId: process.env.GOOGLE_OAUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        redirectUri: process.env.GOOGLE_OAUTH_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
        scope: ['openid', 'profile', 'email'],
      }));
    }

    // Microsoft OAuth
    if (process.env.MICROSOFT_OAUTH_CLIENT_ID && process.env.MICROSOFT_OAUTH_CLIENT_SECRET) {
      this.providers.set('microsoft', new MicrosoftOAuthProvider({
        clientId: process.env.MICROSOFT_OAUTH_CLIENT_ID,
        clientSecret: process.env.MICROSOFT_OAUTH_CLIENT_SECRET,
        redirectUri: process.env.MICROSOFT_OAUTH_CALLBACK_URL || 'http://localhost:3000/auth/microsoft/callback',
        scope: ['openid', 'profile', 'email'],
      }));
    }
  }

  getProvider(provider: string): BaseOAuthProvider | undefined {
    return this.providers.get(provider);
  }

  getAvailableProviders(): string[] {
    return Array.from(this.providers.keys());
  }

  async initiateAuthFlow(provider: string): Promise<{
    authUrl: string;
    codeVerifier: string;
    state: string;
  }> {
    const oauthProvider = this.getProvider(provider);
    if (!oauthProvider) {
      throw new Error(`Provider ${provider} not configured`);
    }

    const codeVerifier = PKCEService.generateCodeVerifier();
    const codeChallenge = PKCEService.generateCodeChallenge(codeVerifier);
    const state = PKCEService.generateState();

    const authUrl = oauthProvider.getAuthorizationUrl(codeChallenge, state);

    return {
      authUrl,
      codeVerifier,
      state,
    };
  }

  async completeAuthFlow(
    provider: string,
    code: string,
    codeVerifier: string
  ): Promise<any> {
    const oauthProvider = this.getProvider(provider);
    if (!oauthProvider) {
      throw new Error(`Provider ${provider} not configured`);
    }

    const tokenResponse = await oauthProvider.exchangeCodeForToken(code, codeVerifier);
    const userInfo = await oauthProvider.getUserInfo(tokenResponse.access_token);

    return {
      tokens: tokenResponse,
      user: userInfo,
    };
  }
}

// Session Storage for PKCE parameters
export class PKCESessionStorage {
  private static readonly STORAGE_PREFIX = 'pkce_';
  private static readonly EXPIRY_TIME = 10 * 60 * 1000; // 10 minutes

  static store(sessionId: string, data: { codeVerifier: string; state: string }): void {
    const key = `${this.STORAGE_PREFIX}${sessionId}`;
    const item = {
      ...data,
      expiresAt: Date.now() + this.EXPIRY_TIME,
    };

    // In production, store in Redis or similar
    // For now, using in-memory storage
    global.pkceStorage = global.pkceStorage || new Map();
    global.pkceStorage.set(key, item);
  }

  static retrieve(sessionId: string): { codeVerifier: string; state: string } | null {
    const key = `${this.STORAGE_PREFIX}${sessionId}`;

    global.pkceStorage = global.pkceStorage || new Map();
    const item = global.pkceStorage.get(key);

    if (!item || Date.now() > item.expiresAt) {
      if (item) {
        global.pkceStorage.delete(key);
      }
      return null;
    }

    return {
      codeVerifier: item.codeVerifier,
      state: item.state,
    };
  }

  static cleanup(): void {
    global.pkceStorage = global.pkceStorage || new Map();
    const now = Date.now();

    for (const [key, value] of global.pkceStorage.entries()) {
      if (now > value.expiresAt) {
        global.pkceStorage.delete(key);
      }
    }
  }
}

// Export singleton instance
export const oauthManager = new OAuthManager();