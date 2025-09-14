import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { encryptionManager } from './encryption.config';

export interface AuthConfig {
  mfa: {
    enabled: boolean;
    issuer: string;
    algorithms: string[];
    window: number;
    stepSize: number;
  };
  oauth: {
    providers: OAuthProvider[];
    pkce: {
      enabled: boolean;
      codeChallenge: string;
      codeChallengeMethod: string;
    };
    redirectUris: string[];
    scopes: string[];
  };
  session: {
    name: string;
    secret: string;
    maxAge: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
  };
  rateLimit: {
    windowMs: number;
    maxAttempts: number;
    blockDuration: number;
    skipSuccessfulRequests: boolean;
  };
  ipWhitelist: {
    enabled: boolean;
    allowedIPs: string[];
    highValueInvestorIPs: string[];
  };
}

export interface OAuthProvider {
  name: string;
  clientId: string;
  clientSecret: string;
  authorizationURL: string;
  tokenURL: string;
  userInfoURL: string;
  scope: string[];
  callbackURL: string;
}

export interface UserSession {
  userId: string;
  email: string;
  role: string;
  mfaVerified: boolean;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivity: Date;
}

export interface MFASetup {
  secret: string;
  qrCode: string;
  backupCodes: string[];
  isVerified: boolean;
}

export const AUTH_CONFIG: AuthConfig = {
  mfa: {
    enabled: process.env.MFA_ENABLED !== 'false',
    issuer: 'Fynsor',
    algorithms: ['SHA1', 'SHA256', 'SHA512'],
    window: 1, // Allow 1 step tolerance
    stepSize: 30 // 30 second steps
  },
  oauth: {
    providers: [
      {
        name: 'google',
        clientId: process.env.GOOGLE_OAUTH_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET || '',
        authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenURL: 'https://www.googleapis.com/oauth2/v4/token',
        userInfoURL: 'https://www.googleapis.com/oauth2/v2/userinfo',
        scope: ['profile', 'email'],
        callbackURL: process.env.GOOGLE_OAUTH_CALLBACK_URL || ''
      },
      {
        name: 'microsoft',
        clientId: process.env.MICROSOFT_OAUTH_CLIENT_ID || '',
        clientSecret: process.env.MICROSOFT_OAUTH_CLIENT_SECRET || '',
        authorizationURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenURL: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userInfoURL: 'https://graph.microsoft.com/v1.0/me',
        scope: ['profile', 'email'],
        callbackURL: process.env.MICROSOFT_OAUTH_CALLBACK_URL || ''
      }
    ],
    pkce: {
      enabled: true,
      codeChallenge: 'S256',
      codeChallengeMethod: 'S256'
    },
    redirectUris: [
      process.env.OAUTH_REDIRECT_URI || 'https://app.fynsor.com/auth/callback'
    ],
    scopes: ['openid', 'profile', 'email']
  },
  session: {
    name: 'fynsor_session',
    secret: process.env.SESSION_SECRET || encryptionManager.generateSecureToken(64),
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 5,
    blockDuration: 30 * 60 * 1000, // 30 minutes
    skipSuccessfulRequests: true
  },
  ipWhitelist: {
    enabled: process.env.IP_WHITELIST_ENABLED === 'true',
    allowedIPs: (process.env.ALLOWED_IPS || '').split(',').filter(Boolean),
    highValueInvestorIPs: (process.env.HIGH_VALUE_INVESTOR_IPS || '').split(',').filter(Boolean)
  }
};

export class AuthenticationManager {
  private static instance: AuthenticationManager;
  private rateLimitStore: Map<string, { count: number; resetTime: number; blockedUntil?: number }> = new Map();
  private activeSessions: Map<string, UserSession> = new Map();
  private failedAttempts: Map<string, number> = new Map();

  private constructor() {
    this.startCleanupInterval();
  }

  public static getInstance(): AuthenticationManager {
    if (!AuthenticationManager.instance) {
      AuthenticationManager.instance = new AuthenticationManager();
    }
    return AuthenticationManager.instance;
  }

  public async authenticateUser(email: string, password: string, ipAddress: string, userAgent: string): Promise<{
    success: boolean;
    sessionToken?: string;
    mfaRequired?: boolean;
    error?: string;
  }> {
    try {
      // Check IP whitelist for high-value investors
      if (AUTH_CONFIG.ipWhitelist.enabled && !this.isIPAllowed(ipAddress, email)) {
        return { success: false, error: 'IP address not authorized' };
      }

      // Check rate limiting
      if (!this.checkRateLimit(ipAddress)) {
        return { success: false, error: 'Too many attempts. Please try again later.' };
      }

      // Validate credentials (implement your user validation logic)
      const user = await this.validateUserCredentials(email, password);
      if (!user) {
        this.recordFailedAttempt(ipAddress);
        return { success: false, error: 'Invalid credentials' };
      }

      // Check if MFA is required
      if (AUTH_CONFIG.mfa.enabled && user.mfaEnabled) {
        return { success: false, mfaRequired: true };
      }

      // Create session
      const sessionToken = await this.createSession(user, ipAddress, userAgent);
      this.clearFailedAttempts(ipAddress);

      return { success: true, sessionToken };
    } catch (error) {
      console.error('[AUTH] Authentication error:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  public async verifyMFA(sessionId: string, totpCode: string): Promise<{ success: boolean; sessionToken?: string }> {
    try {
      const session = this.activeSessions.get(sessionId);
      if (!session) {
        return { success: false };
      }

      // Verify TOTP code (implement TOTP verification)
      const isValidTOTP = await this.verifyTOTPCode(session.userId, totpCode);
      if (!isValidTOTP) {
        return { success: false };
      }

      // Update session to mark MFA as verified
      session.mfaVerified = true;
      this.activeSessions.set(sessionId, session);

      return { success: true, sessionToken: sessionId };
    } catch (error) {
      console.error('[AUTH] MFA verification error:', error);
      return { success: false };
    }
  }

  public async setupMFA(userId: string): Promise<MFASetup> {
    try {
      const secret = this.generateTOTPSecret();
      const qrCode = await this.generateQRCode(userId, secret);
      const backupCodes = this.generateBackupCodes();

      // Store MFA setup in encrypted format
      const mfaData = {
        secret,
        backupCodes,
        isVerified: false,
        createdAt: new Date().toISOString()
      };

      const encryptedMFAData = encryptionManager.encrypt(JSON.stringify(mfaData), `mfa_${userId}`);
      // Store encryptedMFAData in your database

      return {
        secret,
        qrCode,
        backupCodes,
        isVerified: false
      };
    } catch (error) {
      console.error('[AUTH] MFA setup error:', error);
      throw new Error('Failed to setup MFA');
    }
  }

  public generatePKCEChallenge(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = encryptionManager.generateSecureToken(64);
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    return { codeVerifier, codeChallenge };
  }

  public async createOAuthAuthorizationURL(provider: string, state: string, codeChallenge?: string): Promise<string> {
    const oauthProvider = AUTH_CONFIG.oauth.providers.find(p => p.name === provider);
    if (!oauthProvider) {
      throw new Error(`OAuth provider ${provider} not configured`);
    }

    const params = new URLSearchParams({
      client_id: oauthProvider.clientId,
      redirect_uri: oauthProvider.callbackURL,
      response_type: 'code',
      scope: oauthProvider.scope.join(' '),
      state
    });

    if (AUTH_CONFIG.oauth.pkce.enabled && codeChallenge) {
      params.append('code_challenge', codeChallenge);
      params.append('code_challenge_method', AUTH_CONFIG.oauth.pkce.codeChallengeMethod);
    }

    return `${oauthProvider.authorizationURL}?${params.toString()}`;
  }

  public async validateSession(sessionToken: string): Promise<UserSession | null> {
    try {
      const session = this.activeSessions.get(sessionToken);
      if (!session) {
        return null;
      }

      // Check if session is expired
      if (session.expiresAt < new Date()) {
        this.activeSessions.delete(sessionToken);
        return null;
      }

      // Update last activity
      session.lastActivity = new Date();
      this.activeSessions.set(sessionToken, session);

      return session;
    } catch (error) {
      console.error('[AUTH] Session validation error:', error);
      return null;
    }
  }

  public async logoutUser(sessionToken: string): Promise<void> {
    this.activeSessions.delete(sessionToken);
  }

  private checkRateLimit(identifier: string): boolean {
    const now = Date.now();
    const record = this.rateLimitStore.get(identifier);

    if (!record) {
      this.rateLimitStore.set(identifier, {
        count: 1,
        resetTime: now + AUTH_CONFIG.rateLimit.windowMs
      });
      return true;
    }

    // Check if blocked
    if (record.blockedUntil && now < record.blockedUntil) {
      return false;
    }

    // Reset if window expired
    if (now > record.resetTime) {
      this.rateLimitStore.set(identifier, {
        count: 1,
        resetTime: now + AUTH_CONFIG.rateLimit.windowMs
      });
      return true;
    }

    // Increment count
    record.count++;

    // Block if exceeded
    if (record.count > AUTH_CONFIG.rateLimit.maxAttempts) {
      record.blockedUntil = now + AUTH_CONFIG.rateLimit.blockDuration;
      return false;
    }

    return true;
  }

  private isIPAllowed(ipAddress: string, email?: string): boolean {
    if (!AUTH_CONFIG.ipWhitelist.enabled) {
      return true;
    }

    // Check general allowed IPs
    if (AUTH_CONFIG.ipWhitelist.allowedIPs.includes(ipAddress)) {
      return true;
    }

    // Check high-value investor IPs (you'd need to implement user role checking)
    if (AUTH_CONFIG.ipWhitelist.highValueInvestorIPs.includes(ipAddress)) {
      return true;
    }

    return false;
  }

  private async validateUserCredentials(email: string, password: string): Promise<any> {
    // Implement your user validation logic here
    // This should check against your user database
    // Return user object if valid, null if invalid
    throw new Error('User validation not implemented - integrate with your user database');
  }

  private async createSession(user: any, ipAddress: string, userAgent: string): Promise<string> {
    const sessionToken = encryptionManager.generateSecureToken(64);
    const session: UserSession = {
      userId: user.id,
      email: user.email,
      role: user.role,
      mfaVerified: !AUTH_CONFIG.mfa.enabled || !user.mfaEnabled,
      ipAddress,
      userAgent,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + AUTH_CONFIG.session.maxAge),
      lastActivity: new Date()
    };

    this.activeSessions.set(sessionToken, session);
    return sessionToken;
  }

  private async verifyTOTPCode(userId: string, code: string): Promise<boolean> {
    // Implement TOTP verification logic
    // This should verify against the user's TOTP secret
    throw new Error('TOTP verification not implemented');
  }

  private generateTOTPSecret(): string {
    return encryptionManager.generateSecureToken(20);
  }

  private async generateQRCode(userId: string, secret: string): Promise<string> {
    // Generate TOTP QR code
    const otpAuthURL = `otpauth://totp/${AUTH_CONFIG.mfa.issuer}:${userId}?secret=${secret}&issuer=${AUTH_CONFIG.mfa.issuer}`;
    // Use a QR code library to generate the QR code image
    return otpAuthURL; // Return base64 encoded QR code image
  }

  private generateBackupCodes(): string[] {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push(encryptionManager.generateSecureToken(8));
    }
    return codes;
  }

  private recordFailedAttempt(identifier: string): void {
    const current = this.failedAttempts.get(identifier) || 0;
    this.failedAttempts.set(identifier, current + 1);
  }

  private clearFailedAttempts(identifier: string): void {
    this.failedAttempts.delete(identifier);
  }

  private startCleanupInterval(): void {
    // Clean up expired sessions and rate limit records every hour
    setInterval(() => {
      this.cleanupExpiredSessions();
      this.cleanupRateLimitRecords();
    }, 60 * 60 * 1000);
  }

  private cleanupExpiredSessions(): void {
    const now = new Date();
    for (const [sessionToken, session] of this.activeSessions.entries()) {
      if (session.expiresAt < now) {
        this.activeSessions.delete(sessionToken);
      }
    }
  }

  private cleanupRateLimitRecords(): void {
    const now = Date.now();
    for (const [identifier, record] of this.rateLimitStore.entries()) {
      if (now > record.resetTime && (!record.blockedUntil || now > record.blockedUntil)) {
        this.rateLimitStore.delete(identifier);
      }
    }
  }
}

export const authManager = AuthenticationManager.getInstance();