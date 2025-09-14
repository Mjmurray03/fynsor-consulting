import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import { AuditService } from '@/lib/supabase/client'
import { ApiError } from '@/lib/error-handling'

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required')
}

// Interface for decoded JWT payload
interface JWTPayload {
  userId: string
  email: string
  role: string
  iat: number
  exp: number
  iss: string
  aud: string
}

// Interface for authenticated request context
export interface AuthenticatedRequest extends NextRequest {
  user: {
    id: string
    email: string
    role: string
  }
  auth: {
    token: string
    issuedAt: number
    expiresAt: number
  }
}

// Security context helper
function getSecurityContext(request: NextRequest) {
  const ipAddress =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    '127.0.0.1'

  const userAgent = request.headers.get('user-agent') || 'unknown'
  const requestId = request.headers.get('x-request-id') || crypto.randomUUID()

  return { ipAddress, userAgent, requestId }
}

// Extract JWT token from request
function extractToken(request: NextRequest): string | null {
  // Try Authorization header first (Bearer token)
  const authHeader = request.headers.get('authorization')
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }

  // Fallback to HTTP-only cookie
  const cookies = request.headers.get('cookie')
  if (cookies) {
    const authCookie = cookies
      .split(';')
      .find(c => c.trim().startsWith('auth-token='))

    if (authCookie) {
      return authCookie.split('=')[1]
    }
  }

  return null
}

// Verify and decode JWT token
function verifyToken(token: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'fynsor-consulting',
      audience: 'fynsor-admin'
    }) as JWTPayload

    // Check if token is expired (additional check)
    if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired')
    }

    return decoded
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new ApiError('Token expired', 401, 'TOKEN_EXPIRED')
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new ApiError('Invalid token', 401, 'INVALID_TOKEN')
    } else {
      throw new ApiError('Token verification failed', 401, 'TOKEN_VERIFICATION_FAILED')
    }
  }
}

// Authentication middleware function
export async function authenticateRequest(
  request: NextRequest,
  requiredRole?: string
): Promise<AuthenticatedRequest> {
  const securityContext = getSecurityContext(request)

  try {
    // Extract token from request
    const token = extractToken(request)

    if (!token) {
      await AuditService.logEvent({
        action: 'authentication_failed',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 25,
        metadata: { reason: 'no_token_provided' }
      })

      throw new ApiError('Authentication required', 401, 'AUTHENTICATION_REQUIRED')
    }

    // Verify and decode token
    const decoded = verifyToken(token)

    // Check role permissions if required
    if (requiredRole && decoded.role !== requiredRole && decoded.role !== 'super_admin') {
      await AuditService.logEvent({
        action: 'authorization_failed',
        userId: decoded.userId,
        userEmail: decoded.email,
        userRole: decoded.role,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 35,
        metadata: {
          required_role: requiredRole,
          user_role: decoded.role
        }
      })

      throw new ApiError('Insufficient permissions', 403, 'INSUFFICIENT_PERMISSIONS')
    }

    // Create authenticated request object
    const authenticatedRequest = request as AuthenticatedRequest
    authenticatedRequest.user = {
      id: decoded.userId,
      email: decoded.email,
      role: decoded.role
    }
    authenticatedRequest.auth = {
      token,
      issuedAt: decoded.iat,
      expiresAt: decoded.exp
    }

    // Log successful authentication (optional, might be verbose)
    if (process.env.LOG_AUTH_SUCCESS === 'true') {
      await AuditService.logEvent({
        action: 'authentication_success',
        userId: decoded.userId,
        userEmail: decoded.email,
        userRole: decoded.role,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 0,
        metadata: {
          required_role: requiredRole,
          token_issued_at: new Date(decoded.iat * 1000).toISOString()
        }
      })
    }

    return authenticatedRequest

  } catch (error) {
    // Re-throw ApiErrors
    if (error instanceof ApiError) {
      throw error
    }

    // Log unexpected authentication errors
    await AuditService.logEvent({
      action: 'authentication_error',
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      requestId: securityContext.requestId,
      resourceType: 'auth',
      riskScore: 50,
      metadata: {
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    })

    throw new ApiError('Authentication failed', 401, 'AUTHENTICATION_FAILED')
  }
}

// Role-based access control helper
export function requireRole(role: string) {
  return async (request: NextRequest): Promise<AuthenticatedRequest> => {
    return authenticateRequest(request, role)
  }
}

// Admin-only access helper
export const requireAdmin = requireRole('admin')

// Super admin-only access helper
export const requireSuperAdmin = requireRole('super_admin')

// Check if user has permission for specific action
export function hasPermission(userRole: string, requiredRole: string): boolean {
  const roleHierarchy = {
    'readonly': 1,
    'admin': 2,
    'super_admin': 3
  }

  const userLevel = roleHierarchy[userRole as keyof typeof roleHierarchy] || 0
  const requiredLevel = roleHierarchy[requiredRole as keyof typeof roleHierarchy] || 999

  return userLevel >= requiredLevel
}

// Middleware wrapper for API routes
export function withAuth(
  handler: (request: AuthenticatedRequest) => Promise<NextResponse>,
  requiredRole?: string
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    try {
      const authenticatedRequest = await authenticateRequest(request, requiredRole)
      return handler(authenticatedRequest)
    } catch (error) {
      if (error instanceof ApiError) {
        return NextResponse.json(
          {
            success: false,
            error: error.message,
            code: error.code
          },
          {
            status: error.statusCode,
            headers: {
              'X-Request-ID': getSecurityContext(request).requestId
            }
          }
        )
      }

      return NextResponse.json(
        {
          success: false,
          error: 'Authentication failed',
          code: 'AUTHENTICATION_FAILED'
        },
        {
          status: 401,
          headers: {
            'X-Request-ID': getSecurityContext(request).requestId
          }
        }
      )
    }
  }
}

// Token refresh helper (for future implementation)
export async function refreshToken(currentToken: string): Promise<string | null> {
  try {
    const decoded = jwt.verify(currentToken, JWT_SECRET, { ignoreExpiration: true }) as JWTPayload

    // Check if token is close to expiry (within 1 hour)
    const now = Math.floor(Date.now() / 1000)
    const timeUntilExpiry = decoded.exp - now

    if (timeUntilExpiry > 3600) { // More than 1 hour left
      return currentToken // No need to refresh
    }

    // Generate new token with same payload but updated timestamps
    const newPayload = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      iat: now
    }

    return jwt.sign(newPayload, JWT_SECRET, {
      expiresIn: '24h',
      issuer: 'fynsor-consulting',
      audience: 'fynsor-admin'
    })

  } catch (error) {
    console.error('Token refresh failed:', error)
    return null
  }
}

export default {
  authenticateRequest,
  requireRole,
  requireAdmin,
  requireSuperAdmin,
  hasPermission,
  withAuth,
  refreshToken
}