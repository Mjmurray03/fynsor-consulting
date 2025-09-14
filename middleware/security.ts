/**
 * Security Middleware
 * Comprehensive security headers and protection for Fynsor Consulting
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import crypto from 'crypto';

// Security configuration schema
const SecurityConfigSchema = z.object({
  csp: z.object({
    enabled: z.boolean().default(true),
    reportOnly: z.boolean().default(false),
    reportUri: z.string().default('/api/security/csp-report'),
    directives: z.record(z.string()).optional(),
  }).default({}),
  hsts: z.object({
    enabled: z.boolean().default(true),
    maxAge: z.number().default(31536000), // 1 year
    includeSubDomains: z.boolean().default(true),
    preload: z.boolean().default(true),
  }).default({}),
  frameOptions: z.enum(['DENY', 'SAMEORIGIN']).default('DENY'),
  contentTypeOptions: z.boolean().default(true),
  referrerPolicy: z.enum([
    'no-referrer',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url'
  ]).default('strict-origin-when-cross-origin'),
  permissionsPolicy: z.object({
    enabled: z.boolean().default(true),
    policies: z.record(z.array(z.string())).optional(),
  }).default({}),
});

export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

// Rate limiting store
interface RateLimitEntry {
  count: number;
  resetTime: number;
  blocked: boolean;
}

class RateLimitStore {
  private store: Map<string, RateLimitEntry> = new Map();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Cleanup expired entries every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
  }

  get(key: string): RateLimitEntry | undefined {
    return this.store.get(key);
  }

  set(key: string, entry: RateLimitEntry): void {
    this.store.set(key, entry);
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.resetTime) {
        this.store.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
  }
}

// Security middleware class
export class SecurityMiddleware {
  private config: SecurityConfig;
  private rateLimitStore: RateLimitStore;
  private nonces: Map<string, string> = new Map();

  constructor(config: Partial<SecurityConfig> = {}) {
    this.config = SecurityConfigSchema.parse(config);
    this.rateLimitStore = new RateLimitStore();
  }

  // Main middleware function
  async handle(request: NextRequest): Promise<NextResponse> {
    const response = NextResponse.next();

    // Apply security headers
    this.applySecurityHeaders(request, response);

    // Apply rate limiting
    const rateLimitResult = this.applyRateLimit(request);
    if (!rateLimitResult.allowed) {
      return this.createRateLimitResponse(rateLimitResult);
    }

    // Apply CORS if needed
    this.applyCORS(request, response);

    return response;
  }

  // Apply comprehensive security headers
  private applySecurityHeaders(request: NextRequest, response: NextResponse): void {
    // Content Security Policy
    if (this.config.csp.enabled) {
      const cspHeader = this.buildCSP(request);
      const headerName = this.config.csp.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
      response.headers.set(headerName, cspHeader);
    }

    // HTTP Strict Transport Security
    if (this.config.hsts.enabled) {
      const hstsValue = this.buildHSTS();
      response.headers.set('Strict-Transport-Security', hstsValue);
    }

    // X-Frame-Options
    response.headers.set('X-Frame-Options', this.config.frameOptions);

    // X-Content-Type-Options
    if (this.config.contentTypeOptions) {
      response.headers.set('X-Content-Type-Options', 'nosniff');
    }

    // Referrer Policy
    response.headers.set('Referrer-Policy', this.config.referrerPolicy);

    // X-XSS-Protection (legacy, but still useful)
    response.headers.set('X-XSS-Protection', '1; mode=block');

    // Permissions Policy
    if (this.config.permissionsPolicy.enabled) {
      const permissionsPolicy = this.buildPermissionsPolicy();
      response.headers.set('Permissions-Policy', permissionsPolicy);
    }

    // Additional security headers
    response.headers.set('X-Permitted-Cross-Domain-Policies', 'none');
    response.headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
    response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    response.headers.set('Cross-Origin-Resource-Policy', 'same-origin');

    // Remove server identification
    response.headers.delete('Server');
    response.headers.delete('X-Powered-By');

    // Security headers for API responses
    if (request.nextUrl.pathname.startsWith('/api/')) {
      response.headers.set('Cache-Control', 'no-store, max-age=0');
      response.headers.set('Pragma', 'no-cache');
    }
  }

  // Build Content Security Policy
  private buildCSP(request: NextRequest): string {
    const nonce = this.generateNonce();
    const requestId = request.headers.get('x-request-id') || crypto.randomUUID();
    this.nonces.set(requestId, nonce);

    const defaultDirectives = {
      'default-src': "'self'",
      'script-src': `'self' 'nonce-${nonce}' 'strict-dynamic'`,
      'style-src': `'self' 'nonce-${nonce}' 'unsafe-inline'`,
      'img-src': "'self' data: https:",
      'font-src': "'self' https:",
      'connect-src': "'self' https://api.supabase.co wss://api.supabase.co https://*.supabase.co",
      'media-src': "'self'",
      'object-src': "'none'",
      'child-src': "'none'",
      'worker-src': "'self'",
      'frame-ancestors': "'none'",
      'form-action': "'self'",
      'base-uri': "'self'",
      'manifest-src': "'self'",
      'upgrade-insecure-requests': '',
      'block-all-mixed-content': '',
    };

    // Merge with custom directives
    const directives = { ...defaultDirectives, ...this.config.csp.directives };

    // Add report URI
    if (this.config.csp.reportUri) {
      directives['report-uri'] = this.config.csp.reportUri;
      directives['report-to'] = 'csp-endpoint';
    }

    return Object.entries(directives)
      .map(([directive, value]) => `${directive} ${value}`)
      .join('; ');
  }

  // Build HSTS header
  private buildHSTS(): string {
    let hsts = `max-age=${this.config.hsts.maxAge}`;

    if (this.config.hsts.includeSubDomains) {
      hsts += '; includeSubDomains';
    }

    if (this.config.hsts.preload) {
      hsts += '; preload';
    }

    return hsts;
  }

  // Build Permissions Policy
  private buildPermissionsPolicy(): string {
    const defaultPolicies = {
      'accelerometer': ['()'],
      'ambient-light-sensor': ['()'],
      'autoplay': ['self'],
      'battery': ['()'],
      'camera': ['()'],
      'cross-origin-isolated': ['()'],
      'display-capture': ['()'],
      'document-domain': ['()'],
      'encrypted-media': ['()'],
      'execution-while-not-rendered': ['()'],
      'execution-while-out-of-viewport': ['()'],
      'fullscreen': ['self'],
      'geolocation': ['()'],
      'gyroscope': ['()'],
      'magnetometer': ['()'],
      'microphone': ['()'],
      'midi': ['()'],
      'navigation-override': ['()'],
      'payment': ['self'],
      'picture-in-picture': ['()'],
      'publickey-credentials-get': ['self'],
      'screen-wake-lock': ['()'],
      'sync-xhr': ['()'],
      'usb': ['()'],
      'web-share': ['self'],
      'xr-spatial-tracking': ['()'],
    };

    const policies = { ...defaultPolicies, ...this.config.permissionsPolicy.policies };

    return Object.entries(policies)
      .map(([feature, allowlist]) => `${feature}=(${allowlist.join(' ')})`)
      .join(', ');
  }

  // Apply rate limiting
  private applyRateLimit(request: NextRequest): { allowed: boolean; limit?: number; remaining?: number; resetTime?: number } {
    const clientIp = this.getClientIp(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';
    const key = `${clientIp}:${userAgent}`;

    // Different limits for different endpoints
    const isSubmission = request.nextUrl.pathname.includes('/submit') ||
                        request.nextUrl.pathname.includes('/contact') ||
                        request.nextUrl.pathname.includes('/consultation');

    const isAPI = request.nextUrl.pathname.startsWith('/api/');
    const isAuth = request.nextUrl.pathname.startsWith('/auth/');

    let limit: number;
    let windowMs: number;

    if (isSubmission) {
      limit = 5; // 5 submissions per hour
      windowMs = 60 * 60 * 1000; // 1 hour
    } else if (isAuth) {
      limit = 20; // 20 auth attempts per 15 minutes
      windowMs = 15 * 60 * 1000; // 15 minutes
    } else if (isAPI) {
      limit = 100; // 100 API calls per 15 minutes
      windowMs = 15 * 60 * 1000; // 15 minutes
    } else {
      limit = 1000; // 1000 page views per hour
      windowMs = 60 * 60 * 1000; // 1 hour
    }

    const now = Date.now();
    const resetTime = now + windowMs;

    const entry = this.rateLimitStore.get(key);

    if (!entry || now > entry.resetTime) {
      // New window or expired entry
      this.rateLimitStore.set(key, {
        count: 1,
        resetTime,
        blocked: false,
      });

      return {
        allowed: true,
        limit,
        remaining: limit - 1,
        resetTime,
      };
    }

    if (entry.blocked) {
      return {
        allowed: false,
        limit,
        remaining: 0,
        resetTime: entry.resetTime,
      };
    }

    if (entry.count >= limit) {
      // Rate limit exceeded
      entry.blocked = true;
      this.rateLimitStore.set(key, entry);

      // Log security event
      console.warn(`Rate limit exceeded for ${clientIp} on ${request.nextUrl.pathname}`);

      return {
        allowed: false,
        limit,
        remaining: 0,
        resetTime: entry.resetTime,
      };
    }

    // Increment counter
    entry.count++;
    this.rateLimitStore.set(key, entry);

    return {
      allowed: true,
      limit,
      remaining: limit - entry.count,
      resetTime: entry.resetTime,
    };
  }

  // Create rate limit response
  private createRateLimitResponse(rateLimitResult: { limit?: number; remaining?: number; resetTime?: number }): NextResponse {
    const response = NextResponse.json(
      {
        error: 'Rate Limit Exceeded',
        message: 'Too many requests. Please try again later.',
        retryAfter: Math.ceil(((rateLimitResult.resetTime || Date.now()) - Date.now()) / 1000),
      },
      { status: 429 }
    );

    response.headers.set('X-RateLimit-Limit', String(rateLimitResult.limit || 0));
    response.headers.set('X-RateLimit-Remaining', String(rateLimitResult.remaining || 0));
    response.headers.set('X-RateLimit-Reset', String(Math.ceil((rateLimitResult.resetTime || Date.now()) / 1000)));
    response.headers.set('Retry-After', String(Math.ceil(((rateLimitResult.resetTime || Date.now()) - Date.now()) / 1000)));

    return response;
  }

  // Apply CORS headers
  private applyCORS(request: NextRequest, response: NextResponse): void {
    const origin = request.headers.get('origin');
    const allowedOrigins = (process.env.CORS_ORIGIN || 'https://fynsor.com').split(',');

    if (origin && allowedOrigins.includes(origin)) {
      response.headers.set('Access-Control-Allow-Origin', origin);
    } else if (process.env.NODE_ENV === 'development') {
      response.headers.set('Access-Control-Allow-Origin', 'http://localhost:3000');
    }

    if (request.method === 'OPTIONS') {
      response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours
    }

    if (process.env.CORS_CREDENTIALS === 'true') {
      response.headers.set('Access-Control-Allow-Credentials', 'true');
    }
  }

  // Generate nonce for CSP
  private generateNonce(): string {
    return crypto.randomBytes(16).toString('base64');
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

  // Get stored nonce for request
  getNonce(requestId: string): string | undefined {
    return this.nonces.get(requestId);
  }

  // Cleanup nonces
  cleanupNonces(): void {
    this.nonces.clear();
  }

  // Destroy middleware and cleanup resources
  destroy(): void {
    this.rateLimitStore.destroy();
    this.nonces.clear();
  }
}

// Bot protection middleware
export class BotProtection {
  private suspiciousPatterns: RegExp[] = [
    /bot|crawler|spider|scraper/i,
    /curl|wget|python|requests/i,
    /postman|insomnia|httpie/i,
  ];

  private honeypotFields = ['website', 'company_name_hidden', 'email_verify'];

  // Check if request is from a bot
  isSuspiciousRequest(request: NextRequest): boolean {
    const userAgent = request.headers.get('user-agent') || '';

    // Check for suspicious user agents
    if (this.suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
      return true;
    }

    // Check for missing common headers
    if (!request.headers.get('accept') || !request.headers.get('accept-language')) {
      return true;
    }

    // Check for suspicious header combinations
    const referer = request.headers.get('referer');
    if (request.method === 'POST' && !referer) {
      return true;
    }

    return false;
  }

  // Validate honeypot fields
  validateHoneypot(formData: Record<string, any>): boolean {
    // Honeypot fields should be empty
    return this.honeypotFields.every(field => !formData[field] || formData[field].trim() === '');
  }

  // Generate challenge for suspicious requests
  generateChallenge(): { challenge: string; answer: string } {
    const a = Math.floor(Math.random() * 10) + 1;
    const b = Math.floor(Math.random() * 10) + 1;

    return {
      challenge: `What is ${a} + ${b}?`,
      answer: String(a + b),
    };
  }
}

// IP validation middleware
export class IPValidation {
  private blockedIPs: Set<string> = new Set();
  private allowedIPs: Set<string> = new Set();
  private bruteForceAttempts: Map<string, { count: number; lastAttempt: number }> = new Map();

  constructor() {
    this.loadIPLists();
  }

  private loadIPLists(): void {
    // Load from environment variables
    const blocked = (process.env.BLOCKED_IPS || '').split(',').filter(ip => ip.trim());
    const allowed = (process.env.ALLOWED_IPS || '').split(',').filter(ip => ip.trim());

    blocked.forEach(ip => this.blockedIPs.add(ip.trim()));
    allowed.forEach(ip => this.allowedIPs.add(ip.trim()));
  }

  // Check if IP is allowed
  isIPAllowed(ip: string): boolean {
    // If IP is explicitly blocked
    if (this.blockedIPs.has(ip)) {
      return false;
    }

    // If allowlist is configured and IP is not in it
    if (this.allowedIPs.size > 0 && !this.allowedIPs.has(ip)) {
      return false;
    }

    return true;
  }

  // Track brute force attempts
  trackBruteForce(ip: string, isFailure: boolean): boolean {
    const now = Date.now();
    const key = ip;

    if (!isFailure) {
      // Success - reset counter
      this.bruteForceAttempts.delete(key);
      return true;
    }

    const attempt = this.bruteForceAttempts.get(key);
    const maxAttempts = 5;
    const windowMs = 15 * 60 * 1000; // 15 minutes

    if (!attempt) {
      this.bruteForceAttempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }

    // Reset if window has passed
    if (now - attempt.lastAttempt > windowMs) {
      this.bruteForceAttempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }

    // Increment counter
    attempt.count++;
    attempt.lastAttempt = now;

    if (attempt.count >= maxAttempts) {
      // Temporarily block IP
      this.blockedIPs.add(ip);
      console.warn(`IP ${ip} temporarily blocked due to brute force attempts`);

      // Remove from blocked list after 1 hour
      setTimeout(() => {
        this.blockedIPs.delete(ip);
        this.bruteForceAttempts.delete(key);
      }, 60 * 60 * 1000);

      return false;
    }

    return true;
  }
}

// Export middleware instances
export const securityMiddleware = new SecurityMiddleware();
export const botProtection = new BotProtection();
export const ipValidation = new IPValidation();