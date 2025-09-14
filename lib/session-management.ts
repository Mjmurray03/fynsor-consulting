/**
 * Secure Session Management
 * Enterprise-grade session handling with 30-minute timeout for Fynsor Consulting
 */

import { z } from 'zod';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { encryptionService } from './encryption';

// Session configuration
const SESSION_CONFIG = {
  timeout: 30 * 60 * 1000, // 30 minutes
  renewalThreshold: 5 * 60 * 1000, // Renew if less than 5 minutes remaining
  maxSessions: 3, // Maximum concurrent sessions per user
  tokenLength: 32,
  cookieName: 'fynsor_session',
  secureCookies: process.env.NODE_ENV === 'production',
  sameSite: 'strict' as const,
  httpOnly: true,
} as const;

// Session schemas
const SessionDataSchema = z.object({
  sessionId: z.string(),
  userId: z.string(),
  email: z.string().email(),
  name: z.string(),
  roles: z.array(z.string()),
  permissions: z.array(z.string()),
  mfaVerified: z.boolean(),
  createdAt: z.date(),
  lastActivity: z.date(),
  expiresAt: z.date(),
  ipAddress: z.string().ip(),
  userAgent: z.string(),
  deviceFingerprint: z.string(),
  isActive: z.boolean(),
  metadata: z.record(z.any()).optional(),
});

const SessionTokenSchema = z.object({
  token: z.string(),
  sessionId: z.string(),
  userId: z.string(),
  expiresAt: z.date(),
  ipAddress: z.string().ip(),
  signature: z.string(),
});

export type SessionData = z.infer<typeof SessionDataSchema>;
export type SessionToken = z.infer<typeof SessionTokenSchema>;

// Device fingerprint generator
export class DeviceFingerprint {
  static generate(userAgent: string, ipAddress: string, acceptLanguage: string = ''): string {
    const fingerprint = crypto.createHash('sha256')
      .update(userAgent)
      .update(ipAddress)
      .update(acceptLanguage)
      .digest('hex');

    return fingerprint.substring(0, 16); // Use first 16 characters
  }

  static verify(stored: string, userAgent: string, ipAddress: string, acceptLanguage: string = ''): boolean {
    const generated = this.generate(userAgent, ipAddress, acceptLanguage);
    return stored === generated;
  }
}

// Session token generator
export class SessionTokenGenerator {
  private static readonly SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

  static generate(sessionId: string, userId: string, ipAddress: string): SessionToken {
    const token = crypto.randomBytes(SESSION_CONFIG.tokenLength).toString('hex');
    const expiresAt = new Date(Date.now() + SESSION_CONFIG.timeout);

    // Create signature to prevent tampering
    const signature = this.createSignature(token, sessionId, userId, ipAddress, expiresAt);

    return {
      token,
      sessionId,
      userId,
      expiresAt,
      ipAddress,
      signature,
    };
  }

  static verify(sessionToken: SessionToken): boolean {
    const expectedSignature = this.createSignature(
      sessionToken.token,
      sessionToken.sessionId,
      sessionToken.userId,
      sessionToken.ipAddress,
      sessionToken.expiresAt
    );

    return this.constantTimeEquals(expectedSignature, sessionToken.signature);
  }

  private static createSignature(
    token: string,
    sessionId: string,
    userId: string,
    ipAddress: string,
    expiresAt: Date
  ): string {
    const data = `${token}:${sessionId}:${userId}:${ipAddress}:${expiresAt.getTime()}`;
    return crypto.createHmac('sha256', this.SECRET).update(data).digest('hex');
  }

  private static constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}

// Session manager
export class SessionManager {
  private supabase: ReturnType<typeof createClient>;
  private activeSessions = new Map<string, SessionData>();

  constructor() {
    this.supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_KEY!
    );

    this.startCleanupTimer();
  }

  // Create new session
  async createSession(
    userId: string,
    userEmail: string,
    userName: string,
    roles: string[],
    permissions: string[],
    ipAddress: string,
    userAgent: string,
    acceptLanguage: string = '',
    mfaVerified: boolean = false
  ): Promise<{ sessionData: SessionData; sessionToken: SessionToken }> {
    // Check for maximum concurrent sessions
    await this.enforceSessionLimit(userId);

    const sessionId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_CONFIG.timeout);
    const deviceFingerprint = DeviceFingerprint.generate(userAgent, ipAddress, acceptLanguage);

    // Create session data
    const sessionData: SessionData = {
      sessionId,
      userId,
      email: userEmail,
      name: userName,
      roles,
      permissions,
      mfaVerified,
      createdAt: now,
      lastActivity: now,
      expiresAt,
      ipAddress,
      userAgent,
      deviceFingerprint,
      isActive: true,
      metadata: {
        acceptLanguage,
        loginMethod: 'oauth',
      },
    };

    // Generate session token
    const sessionToken = SessionTokenGenerator.generate(sessionId, userId, ipAddress);

    // Encrypt session data for storage
    const encryptedSessionData = encryptionService.encrypt(
      JSON.stringify(sessionData),
      'session_data'
    );

    // Store in database
    await this.supabase
      .from('sessions')
      .insert({
        session_id: sessionId,
        user_id: userId,
        encrypted_data: JSON.stringify(encryptedSessionData),
        token_hash: crypto.createHash('sha256').update(sessionToken.token).digest('hex'),
        expires_at: expiresAt.toISOString(),
        ip_address: ipAddress,
        user_agent: userAgent,
        device_fingerprint: deviceFingerprint,
        created_at: now.toISOString(),
        last_activity: now.toISOString(),
        is_active: true,
      });

    // Store in memory cache
    this.activeSessions.set(sessionId, sessionData);

    // Log session creation
    await this.logSessionEvent(sessionId, 'session_created', {
      userId,
      ipAddress,
      userAgent,
    });

    return { sessionData, sessionToken };
  }

  // Retrieve session
  async getSession(sessionToken: SessionToken): Promise<SessionData | null> {
    try {
      // Verify token signature
      if (!SessionTokenGenerator.verify(sessionToken)) {
        await this.logSessionEvent(sessionToken.sessionId, 'invalid_token', {
          userId: sessionToken.userId,
          ipAddress: sessionToken.ipAddress,
        });
        return null;
      }

      // Check token expiration
      if (new Date() > sessionToken.expiresAt) {
        await this.invalidateSession(sessionToken.sessionId, 'token_expired');
        return null;
      }

      // Check memory cache first
      let sessionData = this.activeSessions.get(sessionToken.sessionId);

      if (!sessionData) {
        // Load from database
        const { data, error } = await this.supabase
          .from('sessions')
          .select('*')
          .eq('session_id', sessionToken.sessionId)
          .eq('is_active', true)
          .single();

        if (error || !data) {
          return null;
        }

        // Decrypt session data
        const encryptedData = JSON.parse(data.encrypted_data);
        const decryptedData = encryptionService.decrypt(encryptedData, 'session_data');
        sessionData = JSON.parse(decryptedData);

        // Add to cache
        this.activeSessions.set(sessionToken.sessionId, sessionData);
      }

      // Check session expiration
      if (new Date() > sessionData.expiresAt) {
        await this.invalidateSession(sessionToken.sessionId, 'session_expired');
        return null;
      }

      // Verify device fingerprint (optional security check)
      if (process.env.STRICT_DEVICE_FINGERPRINT === 'true') {
        if (!DeviceFingerprint.verify(
          sessionData.deviceFingerprint,
          sessionData.userAgent,
          sessionData.ipAddress
        )) {
          await this.invalidateSession(sessionToken.sessionId, 'device_mismatch');
          return null;
        }
      }

      // Update last activity
      await this.updateLastActivity(sessionToken.sessionId);

      return sessionData;
    } catch (error) {
      console.error('Session retrieval error:', error);
      return null;
    }
  }

  // Update last activity
  async updateLastActivity(sessionId: string): Promise<void> {
    const now = new Date();

    // Update in cache
    const sessionData = this.activeSessions.get(sessionId);
    if (sessionData) {
      sessionData.lastActivity = now;

      // Check if session needs renewal
      const timeUntilExpiry = sessionData.expiresAt.getTime() - now.getTime();
      if (timeUntilExpiry <= SESSION_CONFIG.renewalThreshold) {
        sessionData.expiresAt = new Date(now.getTime() + SESSION_CONFIG.timeout);
      }
    }

    // Update in database
    await this.supabase
      .from('sessions')
      .update({
        last_activity: now.toISOString(),
        expires_at: sessionData?.expiresAt.toISOString(),
      })
      .eq('session_id', sessionId);
  }

  // Renew session
  async renewSession(sessionId: string): Promise<SessionToken | null> {
    const sessionData = this.activeSessions.get(sessionId);
    if (!sessionData || !sessionData.isActive) {
      return null;
    }

    const now = new Date();
    const newExpiresAt = new Date(now.getTime() + SESSION_CONFIG.timeout);

    // Update session data
    sessionData.expiresAt = newExpiresAt;
    sessionData.lastActivity = now;

    // Generate new token
    const newToken = SessionTokenGenerator.generate(
      sessionId,
      sessionData.userId,
      sessionData.ipAddress
    );

    // Update in database
    const encryptedSessionData = encryptionService.encrypt(
      JSON.stringify(sessionData),
      'session_data'
    );

    await this.supabase
      .from('sessions')
      .update({
        encrypted_data: JSON.stringify(encryptedSessionData),
        token_hash: crypto.createHash('sha256').update(newToken.token).digest('hex'),
        expires_at: newExpiresAt.toISOString(),
        last_activity: now.toISOString(),
      })
      .eq('session_id', sessionId);

    // Log session renewal
    await this.logSessionEvent(sessionId, 'session_renewed', {
      userId: sessionData.userId,
    });

    return newToken;
  }

  // Invalidate session
  async invalidateSession(sessionId: string, reason: string = 'user_logout'): Promise<void> {
    // Remove from cache
    const sessionData = this.activeSessions.get(sessionId);
    this.activeSessions.delete(sessionId);

    // Mark as inactive in database
    await this.supabase
      .from('sessions')
      .update({
        is_active: false,
        invalidated_at: new Date().toISOString(),
        invalidation_reason: reason,
      })
      .eq('session_id', sessionId);

    // Log session invalidation
    await this.logSessionEvent(sessionId, 'session_invalidated', {
      userId: sessionData?.userId,
      reason,
    });
  }

  // Invalidate all user sessions
  async invalidateAllUserSessions(userId: string, exceptSessionId?: string): Promise<void> {
    // Remove from cache
    for (const [sessionId, sessionData] of this.activeSessions.entries()) {
      if (sessionData.userId === userId && sessionId !== exceptSessionId) {
        this.activeSessions.delete(sessionId);
      }
    }

    // Mark as inactive in database
    const query = this.supabase
      .from('sessions')
      .update({
        is_active: false,
        invalidated_at: new Date().toISOString(),
        invalidation_reason: 'user_logout_all',
      })
      .eq('user_id', userId)
      .eq('is_active', true);

    if (exceptSessionId) {
      query.neq('session_id', exceptSessionId);
    }

    await query;

    // Log bulk invalidation
    await this.logSessionEvent('bulk', 'sessions_invalidated', {
      userId,
      exceptSessionId,
      reason: 'user_logout_all',
    });
  }

  // Enforce session limit per user
  private async enforceSessionLimit(userId: string): Promise<void> {
    const { data: sessions } = await this.supabase
      .from('sessions')
      .select('session_id, created_at')
      .eq('user_id', userId)
      .eq('is_active', true)
      .order('created_at', { ascending: false });

    if (sessions && sessions.length >= SESSION_CONFIG.maxSessions) {
      // Remove oldest sessions
      const sessionsToRemove = sessions.slice(SESSION_CONFIG.maxSessions - 1);

      for (const session of sessionsToRemove) {
        await this.invalidateSession(session.session_id, 'session_limit_exceeded');
      }
    }
  }

  // Get user sessions
  async getUserSessions(userId: string): Promise<Array<{
    sessionId: string;
    createdAt: Date;
    lastActivity: Date;
    ipAddress: string;
    userAgent: string;
    isActive: boolean;
    isCurrent?: boolean;
  }>> {
    const { data: sessions } = await this.supabase
      .from('sessions')
      .select('session_id, created_at, last_activity, ip_address, user_agent, is_active')
      .eq('user_id', userId)
      .order('last_activity', { ascending: false });

    return (sessions || []).map(session => ({
      sessionId: session.session_id,
      createdAt: new Date(session.created_at),
      lastActivity: new Date(session.last_activity),
      ipAddress: session.ip_address,
      userAgent: session.user_agent,
      isActive: session.is_active,
    }));
  }

  // Cleanup expired sessions
  async cleanupExpiredSessions(): Promise<void> {
    const now = new Date();

    // Remove from cache
    for (const [sessionId, sessionData] of this.activeSessions.entries()) {
      if (now > sessionData.expiresAt) {
        this.activeSessions.delete(sessionId);
      }
    }

    // Mark expired sessions as inactive in database
    await this.supabase
      .from('sessions')
      .update({
        is_active: false,
        invalidated_at: now.toISOString(),
        invalidation_reason: 'expired',
      })
      .lt('expires_at', now.toISOString())
      .eq('is_active', true);

    // Delete very old sessions (older than 30 days)
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    await this.supabase
      .from('sessions')
      .delete()
      .lt('created_at', thirtyDaysAgo.toISOString());
  }

  // Log session events
  private async logSessionEvent(
    sessionId: string,
    eventType: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    try {
      await this.supabase
        .from('session_events')
        .insert({
          id: crypto.randomUUID(),
          session_id: sessionId,
          event_type: eventType,
          timestamp: new Date().toISOString(),
          metadata: metadata || {},
        });
    } catch (error) {
      console.error('Failed to log session event:', error);
    }
  }

  // Start cleanup timer
  private startCleanupTimer(): void {
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 5 * 60 * 1000); // Cleanup every 5 minutes
  }

  // Generate secure cookie options
  static getCookieOptions(): {
    name: string;
    options: {
      httpOnly: boolean;
      secure: boolean;
      sameSite: 'strict' | 'lax' | 'none';
      maxAge: number;
      path: string;
    };
  } {
    return {
      name: SESSION_CONFIG.cookieName,
      options: {
        httpOnly: SESSION_CONFIG.httpOnly,
        secure: SESSION_CONFIG.secureCookies,
        sameSite: SESSION_CONFIG.sameSite,
        maxAge: SESSION_CONFIG.timeout / 1000, // Convert to seconds
        path: '/',
      },
    };
  }
}

// Session middleware for Next.js
export class SessionMiddleware {
  private sessionManager: SessionManager;

  constructor() {
    this.sessionManager = new SessionManager();
  }

  // Extract session token from request
  extractSessionToken(request: Request): SessionToken | null {
    try {
      // Try to get from Authorization header
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const tokenString = authHeader.substring(7);
        return JSON.parse(atob(tokenString)) as SessionToken;
      }

      // Try to get from cookie
      const cookieHeader = request.headers.get('cookie');
      if (cookieHeader) {
        const cookies = Object.fromEntries(
          cookieHeader.split('; ').map(c => c.split('='))
        );

        const sessionCookie = cookies[SESSION_CONFIG.cookieName];
        if (sessionCookie) {
          return JSON.parse(decodeURIComponent(sessionCookie)) as SessionToken;
        }
      }

      return null;
    } catch (error) {
      console.error('Error extracting session token:', error);
      return null;
    }
  }

  // Validate session from request
  async validateSession(request: Request): Promise<SessionData | null> {
    const sessionToken = this.extractSessionToken(request);
    if (!sessionToken) {
      return null;
    }

    return await this.sessionManager.getSession(sessionToken);
  }
}

// Export singleton instances
export const sessionManager = new SessionManager();
export const sessionMiddleware = new SessionMiddleware();

// Export configuration and utilities
export {
  SESSION_CONFIG,
  SessionDataSchema,
  SessionTokenSchema,
  DeviceFingerprint,
  SessionTokenGenerator,
};