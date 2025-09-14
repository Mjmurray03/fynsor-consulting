import { NextRequest, NextResponse } from 'next/server'
import { AuditService, RateLimitService } from '@/lib/supabase/client'
import { ApiError, SecurityError, RateLimitError } from '@/lib/error-handling'

// Security middleware configuration
export interface SecurityConfig {
  rateLimit?: {
    requests: number
    windowMs: number
    skipSuccessfulRequests?: boolean
    skipFailedRequests?: boolean
  }
  audit?: {
    enabled: boolean
    logSuccessfulRequests?: boolean
    logFailedRequests?: boolean
    sensitiveEndpoints?: string[]
  }
  security?: {
    validateOrigin?: boolean
    allowedOrigins?: string[]
    requireHttps?: boolean
    blockSuspiciousPatterns?: boolean
  }
  ddos?: {
    enabled: boolean
    maxRequestsPerSecond: number
    blockDurationMs: number
  }
}

// Default security configuration
const DEFAULT_CONFIG: SecurityConfig = {
  rateLimit: {
    requests: 100,
    windowMs: 60 * 60 * 1000, // 1 hour
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  },
  audit: {
    enabled: true,
    logSuccessfulRequests: false,
    logFailedRequests: true,
    sensitiveEndpoints: ['/api/auth', '/api/contact', '/api/admin']
  },
  security: {
    validateOrigin: true,
    allowedOrigins: ['https://fynsor.com', 'https://www.fynsor.com', 'https://admin.fynsor.com'],
    requireHttps: process.env.NODE_ENV === 'production',
    blockSuspiciousPatterns: true
  },
  ddos: {
    enabled: true,
    maxRequestsPerSecond: 10,
    blockDurationMs: 5 * 60 * 1000 // 5 minutes
  }
}

// Request context interface
export interface RequestContext {
  ipAddress: string
  userAgent: string
  requestId: string
  method: string
  pathname: string
  origin?: string
  referer?: string
  startTime: number
  userId?: string
  userEmail?: string
  userRole?: string
}

// Suspicious pattern detection
class SuspiciousPatternDetector {
  private static readonly SUSPICIOUS_PATTERNS = [
    // SQL injection patterns
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
    /([\'\";]|--|\*\/|\*\*)/g,

    // XSS patterns
    /(<script|javascript:|vbscript:|onload=|onerror=|onclick=)/gi,

    // Path traversal
    /(\.\.[\/\\]|\.\.%2f|\.\.%5c)/gi,

    // Command injection
    /(\||;|&|\$\(|\`)/g,

    // File inclusion
    /(file:\/\/|php:\/\/|data:)/gi,

    // Common attack tools
    /(sqlmap|nmap|nikto|burp|acunetix|havij|pangolin)/gi
  ]

  static analyze(request: NextRequest): {
    isSuspicious: boolean
    patterns: string[]
    riskScore: number
  } {
    const url = request.url
    const userAgent = request.headers.get('user-agent') || ''
    const referer = request.headers.get('referer') || ''

    const detectedPatterns: string[] = []
    let riskScore = 0

    // Check URL
    this.SUSPICIOUS_PATTERNS.forEach((pattern, index) => {
      if (pattern.test(url)) {
        detectedPatterns.push(`URL pattern ${index + 1}`)
        riskScore += 20
      }
    })

    // Check User-Agent
    this.SUSPICIOUS_PATTERNS.forEach((pattern, index) => {
      if (pattern.test(userAgent)) {
        detectedPatterns.push(`User-Agent pattern ${index + 1}`)
        riskScore += 15
      }
    })

    // Check for bot patterns
    if (/bot|crawler|spider|scraper/gi.test(userAgent)) {
      detectedPatterns.push('Bot detected')
      riskScore += 10
    }

    // Check for missing or suspicious referer
    if (!referer && request.method === 'POST') {
      detectedPatterns.push('Missing referer on POST request')
      riskScore += 5
    }

    // Check for common vulnerability scanners
    if (/nikto|nessus|openvas|w3af/gi.test(userAgent)) {
      detectedPatterns.push('Vulnerability scanner detected')
      riskScore += 30
    }

    return {
      isSuspicious: riskScore > 25,
      patterns: detectedPatterns,
      riskScore: Math.min(100, riskScore)
    }
  }
}

// DDoS protection
class DDoSProtection {
  private static requests = new Map<string, number[]>()

  static isUnderAttack(
    ipAddress: string,
    maxRequestsPerSecond: number,
    windowMs: number = 1000
  ): boolean {
    const now = Date.now()
    const requests = this.requests.get(ipAddress) || []

    // Remove old requests outside the window
    const recentRequests = requests.filter(timestamp => now - timestamp < windowMs)

    // Add current request
    recentRequests.push(now)

    // Update the map
    this.requests.set(ipAddress, recentRequests)

    // Check if over limit
    return recentRequests.length > maxRequestsPerSecond
  }

  static cleanup(): void {
    // Cleanup old entries periodically
    const now = Date.now()
    const maxAge = 60 * 1000 // 1 minute

    for (const [ip, requests] of this.requests.entries()) {
      const recentRequests = requests.filter(timestamp => now - timestamp < maxAge)
      if (recentRequests.length === 0) {
        this.requests.delete(ip)
      } else {
        this.requests.set(ip, recentRequests)
      }
    }
  }
}

// Main security middleware class
export class SecurityMiddleware {
  private config: SecurityConfig

  constructor(config: Partial<SecurityConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Main middleware function
   */
  async handle(
    request: NextRequest,
    next: () => Promise<NextResponse>
  ): Promise<NextResponse> {
    const startTime = Date.now()
    const context = this.extractRequestContext(request, startTime)

    try {
      // 1. Basic security checks
      await this.performSecurityChecks(request, context)

      // 2. DDoS protection
      if (this.config.ddos?.enabled) {
        await this.checkDDoSProtection(context)
      }

      // 3. Suspicious pattern detection
      if (this.config.security?.blockSuspiciousPatterns) {
        await this.checkSuspiciousPatterns(request, context)
      }

      // 4. Rate limiting
      if (this.config.rateLimit) {
        await this.checkRateLimit(context)
      }

      // 5. Log request start (if configured)
      if (this.shouldLogRequest(context, 'start')) {
        await this.logRequestStart(context)
      }

      // Execute the actual request
      const response = await next()

      // 6. Log successful request
      const processingTime = Date.now() - startTime
      if (this.shouldLogRequest(context, 'success')) {
        await this.logRequestSuccess(context, response, processingTime)
      }

      return response

    } catch (error) {
      // 7. Log failed request
      const processingTime = Date.now() - startTime
      if (this.shouldLogRequest(context, 'error')) {
        await this.logRequestError(context, error, processingTime)
      }

      throw error
    }
  }

  /**
   * Extract request context information
   */
  private extractRequestContext(request: NextRequest, startTime: number): RequestContext {
    const ipAddress =
      request.headers.get('x-forwarded-for')?.split(',')[0] ||
      request.headers.get('x-real-ip') ||
      request.ip ||
      '127.0.0.1'

    const userAgent = request.headers.get('user-agent') || 'unknown'
    const requestId = request.headers.get('x-request-id') || crypto.randomUUID()
    const method = request.method
    const pathname = new URL(request.url).pathname
    const origin = request.headers.get('origin') || undefined
    const referer = request.headers.get('referer') || undefined

    return {
      ipAddress,
      userAgent,
      requestId,
      method,
      pathname,
      origin,
      referer,
      startTime
    }
  }

  /**
   * Perform basic security checks
   */
  private async performSecurityChecks(request: NextRequest, context: RequestContext): Promise<void> {
    const { security } = this.config

    // HTTPS requirement
    if (security?.requireHttps && !request.url.startsWith('https://')) {
      throw new SecurityError('HTTPS is required')
    }

    // Origin validation
    if (security?.validateOrigin && request.method !== 'GET') {
      const origin = context.origin
      const allowedOrigins = security.allowedOrigins || []

      if (origin && !allowedOrigins.includes(origin)) {
        await AuditService.logEvent({
          action: 'security_violation',
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          requestId: context.requestId,
          resourceType: 'security',
          riskScore: 50,
          metadata: {
            violation_type: 'invalid_origin',
            origin,
            allowed_origins: allowedOrigins,
            method: context.method,
            pathname: context.pathname
          }
        })

        throw new SecurityError('Invalid origin')
      }
    }
  }

  /**
   * Check for DDoS attacks
   */
  private async checkDDoSProtection(context: RequestContext): Promise<void> {
    const { ddos } = this.config
    if (!ddos?.enabled) return

    if (DDoSProtection.isUnderAttack(context.ipAddress, ddos.maxRequestsPerSecond)) {
      await AuditService.logEvent({
        action: 'ddos_detected',
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        requestId: context.requestId,
        resourceType: 'security',
        riskScore: 80,
        metadata: {
          max_requests_per_second: ddos.maxRequestsPerSecond,
          method: context.method,
          pathname: context.pathname
        }
      })

      throw new RateLimitError('DDoS protection triggered')
    }

    // Cleanup old entries periodically
    if (Math.random() < 0.01) { // 1% chance
      DDoSProtection.cleanup()
    }
  }

  /**
   * Check for suspicious patterns
   */
  private async checkSuspiciousPatterns(request: NextRequest, context: RequestContext): Promise<void> {
    const analysis = SuspiciousPatternDetector.analyze(request)

    if (analysis.isSuspicious) {
      await AuditService.logEvent({
        action: 'suspicious_activity',
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        requestId: context.requestId,
        resourceType: 'security',
        riskScore: analysis.riskScore,
        metadata: {
          detected_patterns: analysis.patterns,
          risk_score: analysis.riskScore,
          method: context.method,
          pathname: context.pathname,
          url: request.url
        }
      })

      if (analysis.riskScore > 50) {
        throw new SecurityError('Suspicious activity detected')
      }
    }
  }

  /**
   * Check rate limits
   */
  private async checkRateLimit(context: RequestContext): Promise<void> {
    const { rateLimit } = this.config
    if (!rateLimit) return

    const allowed = await RateLimitService.checkRateLimit(
      context.ipAddress,
      context.pathname,
      rateLimit.requests,
      rateLimit.windowMs / (60 * 1000) // Convert to minutes
    )

    if (!allowed) {
      await AuditService.logEvent({
        action: 'rate_limit_exceeded',
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        requestId: context.requestId,
        resourceType: 'security',
        riskScore: 30,
        metadata: {
          endpoint: context.pathname,
          limit: rateLimit.requests,
          window_ms: rateLimit.windowMs,
          method: context.method
        }
      })

      throw new RateLimitError(`Rate limit exceeded for ${context.pathname}`)
    }
  }

  /**
   * Determine if request should be logged
   */
  private shouldLogRequest(
    context: RequestContext,
    type: 'start' | 'success' | 'error'
  ): boolean {
    const { audit } = this.config
    if (!audit?.enabled) return false

    const isSensitiveEndpoint = audit.sensitiveEndpoints?.some(endpoint =>
      context.pathname.startsWith(endpoint)
    )

    switch (type) {
      case 'start':
        return isSensitiveEndpoint
      case 'success':
        return audit.logSuccessfulRequests || isSensitiveEndpoint
      case 'error':
        return audit.logFailedRequests !== false // Default to true
      default:
        return false
    }
  }

  /**
   * Log request start
   */
  private async logRequestStart(context: RequestContext): Promise<void> {
    await AuditService.logEvent({
      action: 'request_started',
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      requestId: context.requestId,
      userId: context.userId,
      userEmail: context.userEmail,
      userRole: context.userRole,
      resourceType: 'request',
      riskScore: 0,
      metadata: {
        method: context.method,
        pathname: context.pathname,
        origin: context.origin,
        referer: context.referer
      }
    })
  }

  /**
   * Log successful request
   */
  private async logRequestSuccess(
    context: RequestContext,
    response: NextResponse,
    processingTime: number
  ): Promise<void> {
    await AuditService.logEvent({
      action: 'request_completed',
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      requestId: context.requestId,
      userId: context.userId,
      userEmail: context.userEmail,
      userRole: context.userRole,
      resourceType: 'request',
      riskScore: 0,
      metadata: {
        method: context.method,
        pathname: context.pathname,
        status_code: response.status,
        processing_time: processingTime
      }
    })
  }

  /**
   * Log failed request
   */
  private async logRequestError(
    context: RequestContext,
    error: unknown,
    processingTime: number
  ): Promise<void> {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    const errorCode = error instanceof ApiError ? error.code : 'UNKNOWN_ERROR'

    await AuditService.logEvent({
      action: 'request_failed',
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      requestId: context.requestId,
      userId: context.userId,
      userEmail: context.userEmail,
      userRole: context.userRole,
      resourceType: 'request',
      riskScore: error instanceof SecurityError ? 60 : 25,
      metadata: {
        method: context.method,
        pathname: context.pathname,
        error_message: errorMessage,
        error_code: errorCode,
        processing_time: processingTime
      }
    })
  }
}

// Factory function to create middleware with configuration
export function createSecurityMiddleware(config?: Partial<SecurityConfig>) {
  const middleware = new SecurityMiddleware(config)

  return async (
    request: NextRequest,
    next: () => Promise<NextResponse>
  ): Promise<NextResponse> => {
    return middleware.handle(request, next)
  }
}

// Preset configurations for different use cases
export const presetConfigs = {
  // High security for admin endpoints
  admin: {
    rateLimit: {
      requests: 20,
      windowMs: 60 * 60 * 1000 // 1 hour
    },
    audit: {
      enabled: true,
      logSuccessfulRequests: true,
      logFailedRequests: true,
      sensitiveEndpoints: ['/api/admin', '/api/auth']
    },
    security: {
      validateOrigin: true,
      allowedOrigins: ['https://admin.fynsor.com'],
      requireHttps: true,
      blockSuspiciousPatterns: true
    },
    ddos: {
      enabled: true,
      maxRequestsPerSecond: 5,
      blockDurationMs: 15 * 60 * 1000 // 15 minutes
    }
  },

  // Medium security for API endpoints
  api: {
    rateLimit: {
      requests: 100,
      windowMs: 60 * 60 * 1000 // 1 hour
    },
    audit: {
      enabled: true,
      logSuccessfulRequests: false,
      logFailedRequests: true
    },
    security: {
      validateOrigin: true,
      requireHttps: true,
      blockSuspiciousPatterns: true
    },
    ddos: {
      enabled: true,
      maxRequestsPerSecond: 10,
      blockDurationMs: 5 * 60 * 1000 // 5 minutes
    }
  },

  // Basic security for public endpoints
  public: {
    rateLimit: {
      requests: 200,
      windowMs: 60 * 60 * 1000 // 1 hour
    },
    audit: {
      enabled: true,
      logSuccessfulRequests: false,
      logFailedRequests: true
    },
    security: {
      validateOrigin: false,
      requireHttps: process.env.NODE_ENV === 'production',
      blockSuspiciousPatterns: true
    },
    ddos: {
      enabled: true,
      maxRequestsPerSecond: 20,
      blockDurationMs: 2 * 60 * 1000 // 2 minutes
    }
  }
}

export default {
  SecurityMiddleware,
  createSecurityMiddleware,
  presetConfigs,
  SuspiciousPatternDetector,
  DDoSProtection
}