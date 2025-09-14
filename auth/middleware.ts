/**
 * Authentication Middleware
 * Comprehensive authentication and authorization middleware for Fynsor Consulting
 */

import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRY = '30m'; // 30 minutes
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days

// User schema
const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string(),
  provider: z.string(),
  mfaEnabled: z.boolean().default(false),
  mfaVerified: z.boolean().default(false),
  roles: z.array(z.string()).default(['user']),
  lastActivity: z.date(),
  ipAddress: z.string().ip().optional(),
  userAgent: z.string().optional(),
});

export type User = z.infer<typeof UserSchema>;

// Session schema
const SessionSchema = z.object({
  sessionId: z.string(),
  userId: z.string(),
  accessToken: z.string(),
  refreshToken: z.string(),
  expiresAt: z.date(),
  ipAddress: z.string().ip(),
  userAgent: z.string(),
  mfaVerified: z.boolean().default(false),
  createdAt: z.date(),
  lastActivity: z.date(),
});

export type Session = z.infer<typeof SessionSchema>;

// JWT Payload schema
const JWTPayloadSchema = z.object({
  sub: z.string(), // user ID
  email: z.string().email(),
  name: z.string(),
  provider: z.string(),
  roles: z.array(z.string()),
  sessionId: z.string(),
  mfaVerified: z.boolean(),
  iat: z.number(),
  exp: z.number(),
});

export type JWTPayload = z.infer<typeof JWTPayloadSchema>;

// Authentication Service
export class AuthService {
  private supabase: ReturnType<typeof createClient>;

  constructor() {
    this.supabase = createClient(
      process.env.SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_KEY!
    );
  }

  // Generate session tokens
  async generateTokens(user: User, sessionId: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const payload: Omit<JWTPayload, 'iat' | 'exp'> = {
      sub: user.id,
      email: user.email,
      name: user.name,
      provider: user.provider,
      roles: user.roles,
      sessionId,
      mfaVerified: user.mfaVerified,
    };

    const accessToken = jwt.sign(payload, JWT_SECRET, {
      expiresIn: JWT_EXPIRY,
      issuer: 'fynsor.com',
      audience: 'fynsor.com',
    });

    const refreshToken = jwt.sign(
      { sub: user.id, sessionId, type: 'refresh' },
      JWT_SECRET,
      {
        expiresIn: REFRESH_TOKEN_EXPIRY,
        issuer: 'fynsor.com',
        audience: 'fynsor.com',
      }
    );

    return { accessToken, refreshToken };
  }

  // Verify and decode JWT
  verifyToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, JWT_SECRET, {
        issuer: 'fynsor.com',
        audience: 'fynsor.com',
      }) as any;

      return JWTPayloadSchema.parse(decoded);
    } catch (error) {
      console.error('Token verification failed:', error);
      return null;
    }
  }

  // Create session
  async createSession(
    user: User,
    ipAddress: string,
    userAgent: string
  ): Promise<Session> {
    const sessionId = crypto.randomUUID();
    const { accessToken, refreshToken } = await this.generateTokens(user, sessionId);

    const session: Session = {
      sessionId,
      userId: user.id,
      accessToken,
      refreshToken,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes
      ipAddress,
      userAgent,
      mfaVerified: user.mfaVerified,
      createdAt: new Date(),
      lastActivity: new Date(),
    };

    // Store session in database
    await this.supabase
      .from('sessions')
      .insert({
        session_id: session.sessionId,
        user_id: session.userId,
        access_token: this.encryptToken(session.accessToken),
        refresh_token: this.encryptToken(session.refreshToken),
        expires_at: session.expiresAt.toISOString(),
        ip_address: session.ipAddress,
        user_agent: session.userAgent,
        mfa_verified: session.mfaVerified,
        created_at: session.createdAt.toISOString(),
        last_activity: session.lastActivity.toISOString(),
      });

    return session;
  }

  // Get session
  async getSession(sessionId: string): Promise<Session | null> {
    const { data, error } = await this.supabase
      .from('sessions')
      .select('*')
      .eq('session_id', sessionId)
      .single();

    if (error || !data) {
      return null;
    }

    return {
      sessionId: data.session_id,
      userId: data.user_id,
      accessToken: this.decryptToken(data.access_token),
      refreshToken: this.decryptToken(data.refresh_token),
      expiresAt: new Date(data.expires_at),
      ipAddress: data.ip_address,
      userAgent: data.user_agent,
      mfaVerified: data.mfa_verified,
      createdAt: new Date(data.created_at),
      lastActivity: new Date(data.last_activity),
    };
  }

  // Update session activity
  async updateSessionActivity(sessionId: string): Promise<void> {
    await this.supabase
      .from('sessions')
      .update({
        last_activity: new Date().toISOString(),
      })
      .eq('session_id', sessionId);
  }

  // Invalidate session
  async invalidateSession(sessionId: string): Promise<void> {
    await this.supabase
      .from('sessions')
      .delete()
      .eq('session_id', sessionId);
  }

  // Refresh access token
  async refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
  } | null> {
    try {
      const decoded = jwt.verify(refreshToken, JWT_SECRET) as any;

      if (decoded.type !== 'refresh') {
        throw new Error('Invalid refresh token');
      }

      const session = await this.getSession(decoded.sessionId);
      if (!session || session.refreshToken !== refreshToken) {
        throw new Error('Invalid session');
      }

      // Get user data
      const { data: userData } = await this.supabase
        .from('users')
        .select('*')
        .eq('id', decoded.sub)
        .single();

      if (!userData) {
        throw new Error('User not found');
      }

      const user: User = {
        id: userData.id,
        email: userData.email,
        name: userData.name,
        provider: userData.provider,
        mfaEnabled: userData.mfa_enabled,
        mfaVerified: userData.mfa_verified,
        roles: userData.roles || ['user'],
        lastActivity: new Date(userData.last_activity),
        ipAddress: userData.ip_address,
        userAgent: userData.user_agent,
      };

      return await this.generateTokens(user, decoded.sessionId);
    } catch (error) {
      console.error('Token refresh failed:', error);
      return null;
    }
  }

  // Clean up expired sessions
  async cleanupExpiredSessions(): Promise<void> {
    await this.supabase
      .from('sessions')
      .delete()
      .lt('expires_at', new Date().toISOString());
  }

  private encryptToken(token: string): string {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipher(algorithm, key);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return `${iv.toString('hex')}:${encrypted}`;
  }

  private decryptToken(encryptedToken: string): string {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const [ivHex, encrypted] = encryptedToken.split(':');
    const iv = Buffer.from(ivHex, 'hex');

    const decipher = crypto.createDecipher(algorithm, key);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

// Authentication Middleware
export class AuthMiddleware {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  // Middleware for protected routes
  async authenticate(request: NextRequest): Promise<{
    user: User | null;
    session: Session | null;
    error: string | null;
  }> {
    try {
      // Get token from Authorization header or cookie
      const authHeader = request.headers.get('authorization');
      const cookieToken = request.cookies.get('access_token')?.value;

      const token = authHeader?.replace('Bearer ', '') || cookieToken;

      if (!token) {
        return { user: null, session: null, error: 'No token provided' };
      }

      // Verify token
      const payload = this.authService.verifyToken(token);
      if (!payload) {
        return { user: null, session: null, error: 'Invalid token' };
      }

      // Get session
      const session = await this.authService.getSession(payload.sessionId);
      if (!session) {
        return { user: null, session: null, error: 'Session not found' };
      }

      // Check session expiry
      if (session.expiresAt < new Date()) {
        await this.authService.invalidateSession(session.sessionId);
        return { user: null, session: null, error: 'Session expired' };
      }

      // IP validation for sensitive operations
      const clientIp = this.getClientIp(request);
      if (session.ipAddress !== clientIp) {
        console.warn(`IP mismatch for session ${session.sessionId}: ${session.ipAddress} vs ${clientIp}`);
        // For now, log but don't block - in production, consider blocking or requiring re-auth
      }

      // Update session activity
      await this.authService.updateSessionActivity(session.sessionId);

      const user: User = {
        id: payload.sub,
        email: payload.email,
        name: payload.name,
        provider: payload.provider,
        mfaEnabled: true, // Assume MFA is required for all users
        mfaVerified: payload.mfaVerified,
        roles: payload.roles,
        lastActivity: new Date(),
        ipAddress: clientIp,
        userAgent: request.headers.get('user-agent') || 'unknown',
      };

      return { user, session, error: null };
    } catch (error) {
      console.error('Authentication error:', error);
      return { user: null, session: null, error: 'Authentication failed' };
    }
  }

  // Role-based authorization
  authorize(user: User, requiredRoles: string[]): boolean {
    if (!user.roles || user.roles.length === 0) {
      return false;
    }

    return requiredRoles.some(role => user.roles.includes(role));
  }

  // MFA requirement check
  requireMFA(user: User): boolean {
    return user.mfaEnabled && !user.mfaVerified;
  }

  // Get client IP address
  private getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    const realIp = request.headers.get('x-real-ip');
    const clientIp = request.headers.get('x-client-ip');

    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }

    return realIp || clientIp || 'unknown';
  }
}

// Middleware factory for Next.js
export function createAuthMiddleware(options: {
  requiredRoles?: string[];
  requireMFA?: boolean;
  publicPaths?: string[];
} = {}) {
  const authMiddleware = new AuthMiddleware();

  return async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Skip authentication for public paths
    if (options.publicPaths?.some(path => pathname.startsWith(path))) {
      return NextResponse.next();
    }

    const { user, session, error } = await authMiddleware.authenticate(request);

    // Authentication failed
    if (error || !user || !session) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'Unauthorized', message: error || 'Authentication required' },
          { status: 401 }
        );
      }

      return NextResponse.redirect(new URL('/auth/login', request.url));
    }

    // Check MFA requirement
    if ((options.requireMFA ?? true) && authMiddleware.requireMFA(user)) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'MFA Required', message: 'Multi-factor authentication required' },
          { status: 403 }
        );
      }

      return NextResponse.redirect(new URL('/auth/mfa', request.url));
    }

    // Check role authorization
    if (options.requiredRoles && !authMiddleware.authorize(user, options.requiredRoles)) {
      if (pathname.startsWith('/api/')) {
        return NextResponse.json(
          { error: 'Forbidden', message: 'Insufficient permissions' },
          { status: 403 }
        );
      }

      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }

    // Add user info to request headers for downstream use
    const response = NextResponse.next();
    response.headers.set('x-user-id', user.id);
    response.headers.set('x-user-email', user.email);
    response.headers.set('x-user-roles', user.roles.join(','));
    response.headers.set('x-session-id', session.sessionId);

    return response;
  };
}

// Export singleton
export const authService = new AuthService();
export const authMiddleware = new AuthMiddleware();