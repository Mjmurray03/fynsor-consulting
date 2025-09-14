/**
 * Authentication Guards
 * Route protection and authorization guards for Fynsor Consulting
 */

import { NextRequest, NextResponse } from 'next/server';
import { authMiddleware, User, Session } from './middleware';
import { z } from 'zod';

// Guard result interface
interface GuardResult {
  success: boolean;
  user?: User;
  session?: Session;
  error?: string;
  redirectUrl?: string;
}

// Base Guard class
abstract class BaseGuard {
  protected authMiddleware = authMiddleware;

  abstract check(request: NextRequest): Promise<GuardResult>;

  protected createResponse(result: GuardResult, request: NextRequest): NextResponse {
    if (!result.success) {
      if (request.nextUrl.pathname.startsWith('/api/')) {
        return NextResponse.json(
          {
            error: 'Access Denied',
            message: result.error || 'Access denied',
            code: this.getErrorCode(result.error)
          },
          { status: this.getStatusCode(result.error) }
        );
      }

      const redirectUrl = result.redirectUrl || '/auth/login';
      return NextResponse.redirect(new URL(redirectUrl, request.url));
    }

    const response = NextResponse.next();
    if (result.user && result.session) {
      this.attachUserHeaders(response, result.user, result.session);
    }

    return response;
  }

  protected getStatusCode(error?: string): number {
    switch (error) {
      case 'Unauthorized':
      case 'No token provided':
      case 'Invalid token':
      case 'Session expired':
        return 401;
      case 'MFA Required':
      case 'Insufficient permissions':
      case 'Admin access required':
      case 'High-value investor access required':
        return 403;
      case 'IP not allowed':
        return 403;
      default:
        return 401;
    }
  }

  protected getErrorCode(error?: string): string {
    switch (error) {
      case 'MFA Required':
        return 'MFA_REQUIRED';
      case 'Insufficient permissions':
        return 'INSUFFICIENT_PERMISSIONS';
      case 'IP not allowed':
        return 'IP_BLOCKED';
      case 'Session expired':
        return 'SESSION_EXPIRED';
      default:
        return 'UNAUTHORIZED';
    }
  }

  protected attachUserHeaders(response: NextResponse, user: User, session: Session): void {
    response.headers.set('x-user-id', user.id);
    response.headers.set('x-user-email', user.email);
    response.headers.set('x-user-roles', user.roles.join(','));
    response.headers.set('x-session-id', session.sessionId);
    response.headers.set('x-mfa-verified', user.mfaVerified.toString());
  }
}

// Authentication Guard - Basic authentication check
export class AuthGuard extends BaseGuard {
  async check(request: NextRequest): Promise<GuardResult> {
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    return { success: true, user, session };
  }
}

// MFA Guard - Multi-factor authentication check
export class MFAGuard extends BaseGuard {
  async check(request: NextRequest): Promise<GuardResult> {
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    if (this.authMiddleware.requireMFA(user)) {
      return {
        success: false,
        error: 'MFA Required',
        redirectUrl: '/auth/mfa'
      };
    }

    return { success: true, user, session };
  }
}

// Role Guard - Role-based authorization
export class RoleGuard extends BaseGuard {
  constructor(private requiredRoles: string[]) {
    super();
  }

  async check(request: NextRequest): Promise<GuardResult> {
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    if (this.authMiddleware.requireMFA(user)) {
      return {
        success: false,
        error: 'MFA Required',
        redirectUrl: '/auth/mfa'
      };
    }

    if (!this.authMiddleware.authorize(user, this.requiredRoles)) {
      return {
        success: false,
        error: 'Insufficient permissions',
        redirectUrl: '/unauthorized'
      };
    }

    return { success: true, user, session };
  }
}

// Admin Guard - Administrative access
export class AdminGuard extends RoleGuard {
  constructor() {
    super(['admin', 'super_admin']);
  }

  async check(request: NextRequest): Promise<GuardResult> {
    const result = await super.check(request);

    if (!result.success && result.error === 'Insufficient permissions') {
      result.error = 'Admin access required';
    }

    return result;
  }
}

// IP Whitelist Guard - IP-based access control
export class IPWhitelistGuard extends BaseGuard {
  private allowedIPs: Set<string>;
  private highValueInvestorIPs: Set<string>;

  constructor() {
    super();
    this.allowedIPs = new Set(
      (process.env.ALLOWED_IPS || '').split(',').filter(ip => ip.trim())
    );
    this.highValueInvestorIPs = new Set(
      (process.env.HIGH_VALUE_INVESTOR_IPS || '').split(',').filter(ip => ip.trim())
    );
  }

  async check(request: NextRequest): Promise<GuardResult> {
    // First check authentication
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    // Check IP whitelist
    const clientIp = this.getClientIp(request);
    const isAllowed = this.allowedIPs.has(clientIp) ||
                     this.highValueInvestorIPs.has(clientIp) ||
                     process.env.IP_WHITELIST_ENABLED !== 'true';

    if (!isAllowed) {
      // Log security event
      console.warn(`IP access denied: ${clientIp} for user ${user.email}`);

      return {
        success: false,
        error: 'IP not allowed',
        redirectUrl: '/access-denied'
      };
    }

    return { success: true, user, session };
  }

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

// High-Value Investor Guard - Special access for high-value investors
export class HighValueInvestorGuard extends BaseGuard {
  private highValueInvestorIPs: Set<string>;

  constructor() {
    super();
    this.highValueInvestorIPs = new Set(
      (process.env.HIGH_VALUE_INVESTOR_IPS || '').split(',').filter(ip => ip.trim())
    );
  }

  async check(request: NextRequest): Promise<GuardResult> {
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    if (this.authMiddleware.requireMFA(user)) {
      return {
        success: false,
        error: 'MFA Required',
        redirectUrl: '/auth/mfa'
      };
    }

    // Check if user has high-value investor role OR is accessing from whitelisted IP
    const clientIp = this.getClientIp(request);
    const hasInvestorRole = user.roles.includes('high_value_investor');
    const isWhitelistedIP = this.highValueInvestorIPs.has(clientIp);

    if (!hasInvestorRole && !isWhitelistedIP) {
      return {
        success: false,
        error: 'High-value investor access required',
        redirectUrl: '/investor-access-required'
      };
    }

    return { success: true, user, session };
  }

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

// API Rate Limit Guard
export class RateLimitGuard extends BaseGuard {
  private rateLimitStore: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(maxRequests: number = 100, windowMs: number = 15 * 60 * 1000) {
    super();
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  async check(request: NextRequest): Promise<GuardResult> {
    const { user, session, error } = await this.authMiddleware.authenticate(request);

    if (error || !user || !session) {
      return {
        success: false,
        error: error || 'Authentication required',
        redirectUrl: '/auth/login'
      };
    }

    // Check rate limit
    const key = `${user.id}:${this.getClientIp(request)}`;
    const now = Date.now();
    const userLimit = this.rateLimitStore.get(key);

    if (userLimit) {
      if (now < userLimit.resetTime) {
        if (userLimit.count >= this.maxRequests) {
          return {
            success: false,
            error: 'Rate limit exceeded'
          };
        }
        userLimit.count++;
      } else {
        // Reset window
        userLimit.count = 1;
        userLimit.resetTime = now + this.windowMs;
      }
    } else {
      this.rateLimitStore.set(key, {
        count: 1,
        resetTime: now + this.windowMs
      });
    }

    return { success: true, user, session };
  }

  private getClientIp(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    const realIp = request.headers.get('x-real-ip');

    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }

    return realIp || 'unknown';
  }
}

// Combined Guard - Multiple guards in sequence
export class CombinedGuard extends BaseGuard {
  constructor(private guards: BaseGuard[]) {
    super();
  }

  async check(request: NextRequest): Promise<GuardResult> {
    for (const guard of this.guards) {
      const result = await guard.check(request);
      if (!result.success) {
        return result;
      }
    }

    // If all guards pass, return the result from the last guard (which should have user/session)
    return await this.guards[this.guards.length - 1].check(request);
  }
}

// Guard Factory - Create guards with fluent interface
export class GuardFactory {
  private guards: BaseGuard[] = [];

  static create(): GuardFactory {
    return new GuardFactory();
  }

  auth(): GuardFactory {
    this.guards.push(new AuthGuard());
    return this;
  }

  mfa(): GuardFactory {
    this.guards.push(new MFAGuard());
    return this;
  }

  roles(roles: string[]): GuardFactory {
    this.guards.push(new RoleGuard(roles));
    return this;
  }

  admin(): GuardFactory {
    this.guards.push(new AdminGuard());
    return this;
  }

  ipWhitelist(): GuardFactory {
    this.guards.push(new IPWhitelistGuard());
    return this;
  }

  highValueInvestor(): GuardFactory {
    this.guards.push(new HighValueInvestorGuard());
    return this;
  }

  rateLimit(maxRequests?: number, windowMs?: number): GuardFactory {
    this.guards.push(new RateLimitGuard(maxRequests, windowMs));
    return this;
  }

  build(): CombinedGuard {
    if (this.guards.length === 0) {
      throw new Error('At least one guard must be specified');
    }
    return new CombinedGuard(this.guards);
  }
}

// Middleware factory for Next.js
export function createGuardMiddleware(guard: BaseGuard) {
  return async function middleware(request: NextRequest) {
    const result = await guard.check(request);
    return guard.createResponse(result, request);
  };
}

// Export guard instances
export const authGuard = new AuthGuard();
export const mfaGuard = new MFAGuard();
export const adminGuard = new AdminGuard();
export const ipWhitelistGuard = new IPWhitelistGuard();
export const highValueInvestorGuard = new HighValueInvestorGuard();