import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import { AuditService } from '@/lib/supabase/client'
import { ApiResponse } from '@/lib/supabase/types'
import { handleApiError, ApiError } from '@/lib/error-handling'

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required')
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

// Extract user from JWT token
function extractUserFromToken(request: NextRequest): { userId: string; email: string; role: string } | null {
  try {
    // Try to get token from Authorization header first
    let token = request.headers.get('authorization')?.replace('Bearer ', '')

    // Fallback to cookie
    if (!token) {
      const cookies = request.headers.get('cookie')
      if (cookies) {
        const authCookie = cookies
          .split(';')
          .find(c => c.trim().startsWith('auth-token='))

        if (authCookie) {
          token = authCookie.split('=')[1]
        }
      }
    }

    if (!token) {
      return null
    }

    const decoded = jwt.verify(token, JWT_SECRET) as any
    return {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role
    }
  } catch (error) {
    console.error('Token extraction failed:', error)
    return null
  }
}

// POST endpoint for admin logout
export async function POST(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  let securityContext: ReturnType<typeof getSecurityContext>
  let userInfo: ReturnType<typeof extractUserFromToken> = null

  try {
    // Get security context
    securityContext = getSecurityContext(request)

    // Extract user information from token
    userInfo = extractUserFromToken(request)

    // Log logout event (even if token is invalid, for security tracking)
    await AuditService.logEvent({
      action: 'user_logout',
      userId: userInfo?.userId || undefined,
      userEmail: userInfo?.email || undefined,
      userRole: userInfo?.role || undefined,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      requestId: securityContext.requestId,
      resourceType: 'auth',
      riskScore: 0,
      metadata: {
        logout_method: 'explicit',
        had_valid_token: !!userInfo,
        processing_time: Date.now() - startTime
      }
    })

    const response: ApiResponse = {
      success: true,
      message: 'Logout successful'
    }

    // Clear the authentication cookie
    const cookieOptions = [
      'auth-token=',
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      'Max-Age=0', // Expire immediately
      'Path=/',
      ...(process.env.NODE_ENV === 'production' ? ['Domain=.fynsor.com'] : [])
    ].join('; ')

    return NextResponse.json(response, {
      status: 200,
      headers: {
        'Set-Cookie': cookieOptions,
        'X-Request-ID': securityContext.requestId,
        'X-Processing-Time': `${Date.now() - startTime}ms`,
        'Clear-Site-Data': '"cache", "cookies", "storage"'
      }
    })

  } catch (error) {
    // Log failed logout attempt
    if (securityContext) {
      await AuditService.logEvent({
        action: 'failed_logout',
        userId: userInfo?.userId || undefined,
        userEmail: userInfo?.email || undefined,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 15,
        metadata: {
          error: error instanceof Error ? error.message : 'Unknown error',
          processing_time: Date.now() - startTime
        }
      })
    }

    return handleApiError(error, {
      ipAddress: securityContext?.ipAddress,
      userAgent: securityContext?.userAgent,
      requestId: securityContext?.requestId,
      processingTime: Date.now() - startTime
    })
  }
}

// GET endpoint to check authentication status
export async function GET(request: NextRequest): Promise<NextResponse> {
  const securityContext = getSecurityContext(request)

  try {
    const userInfo = extractUserFromToken(request)

    if (!userInfo) {
      return NextResponse.json(
        {
          success: false,
          authenticated: false,
          message: 'Not authenticated'
        },
        { status: 401 }
      )
    }

    // Log auth check (optional, might be too verbose)
    if (process.env.LOG_AUTH_CHECKS === 'true') {
      await AuditService.logEvent({
        action: 'auth_check',
        userId: userInfo.userId,
        userEmail: userInfo.email,
        userRole: userInfo.role,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 0
      })
    }

    return NextResponse.json({
      success: true,
      authenticated: true,
      user: {
        id: userInfo.userId,
        email: userInfo.email,
        role: userInfo.role
      }
    })

  } catch (error) {
    return handleApiError(error, {
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      requestId: securityContext.requestId
    })
  }
}

// OPTIONS endpoint for CORS
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://admin.fynsor.com',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  })
}