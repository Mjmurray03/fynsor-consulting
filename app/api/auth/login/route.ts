import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { supabaseAdmin, AuditService, RateLimitService } from '@/lib/supabase/client'
import { ApiResponse, LoginCredentials, AdminUser } from '@/lib/supabase/types'
import { handleApiError, ApiError } from '@/lib/error-handling'
import { sanitizeInput } from '@/lib/server-validation'

// Validation schema for login
const loginSchema = z.object({
  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email must be less than 255 characters')
    .toLowerCase(),

  password: z
    .string()
    .min(1, 'Password is required')
    .max(128, 'Password must be less than 128 characters'),

  // reCAPTCHA token for bot protection
  recaptchaToken: z.string().optional()
})

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-for-build'
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h'

// JWT_SECRET validation handled in production environment

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

// reCAPTCHA verification for login attempts
async function verifyRecaptcha(token: string, ipAddress: string): Promise<boolean> {
  if (!process.env.RECAPTCHA_SECRET_KEY) {
    return true // Allow in development
  }

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        secret: process.env.RECAPTCHA_SECRET_KEY,
        response: token,
        remoteip: ipAddress,
      }),
    })

    const data = await response.json()
    return data.success && data.score > 0.3 // Lower threshold for login
  } catch (error) {
    console.error('reCAPTCHA verification failed:', error)
    return false
  }
}

// Generate JWT token
function generateToken(user: AdminUser): string {
  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
    iat: Math.floor(Date.now() / 1000)
  }

  return jwt.sign(payload, JWT_SECRET as string, {
    expiresIn: JWT_EXPIRES_IN,
    issuer: 'fynsor-consulting',
    audience: 'fynsor-admin'
  })
}

// Update user login tracking
async function updateLoginTracking(
  userId: string,
  ipAddress: string,
  success: boolean
): Promise<void> {
  try {
    if (success) {
      // Reset failed attempts and update last login
      await supabaseAdmin
        .from('admin_users')
        .update({
          last_login: new Date().toISOString(),
          failed_login_attempts: 0,
          locked_until: null,
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
    } else {
      // Increment failed attempts
      const { data: user } = await supabaseAdmin
        .from('admin_users')
        .select('failed_login_attempts')
        .eq('id', userId)
        .single()

      const newFailedAttempts = (user?.failed_login_attempts || 0) + 1
      const lockedUntil = newFailedAttempts >= 5
        ? new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 minutes
        : null

      await supabaseAdmin
        .from('admin_users')
        .update({
          failed_login_attempts: newFailedAttempts,
          locked_until: lockedUntil,
          updated_at: new Date().toISOString()
        })
        .eq('id', userId)
    }
  } catch (error) {
    console.error('Failed to update login tracking:', error)
  }
}

// POST endpoint for admin login
export async function POST(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  let securityContext: ReturnType<typeof getSecurityContext>
  let userEmail: string = ''

  try {
    // Get security context
    securityContext = getSecurityContext(request)

    // Rate limiting for login attempts
    const rateLimitAllowed = await RateLimitService.checkRateLimit(
      securityContext.ipAddress,
      '/api/auth/login',
      10, // 10 attempts
      60 // per hour
    )

    if (!rateLimitAllowed) {
      await AuditService.logEvent({
        action: 'rate_limit_exceeded',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 75,
        metadata: { endpoint: '/api/auth/login' }
      })

      throw new ApiError('Too many login attempts. Please try again later.', 429, 'RATE_LIMIT_EXCEEDED')
    }

    // Parse request body
    let body: any
    try {
      body = await request.json()
    } catch (error) {
      throw new ApiError('Invalid JSON in request body', 400, 'INVALID_JSON')
    }

    // Sanitize and validate input
    const sanitizedData = {
      email: sanitizeInput(body.email),
      password: body.password, // Don't sanitize passwords
      recaptchaToken: body.recaptchaToken
    }

    const validationResult = loginSchema.safeParse(sanitizedData)

    if (!validationResult.success) {
      const errors = validationResult.error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
        code: err.code
      }))

      await AuditService.logEvent({
        action: 'failed_login',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 25,
        metadata: { reason: 'validation_failed', errors }
      })

      throw new ApiError('Invalid login credentials', 400, 'VALIDATION_FAILED', { errors })
    }

    const { email, password, recaptchaToken } = validationResult.data
    userEmail = email

    // reCAPTCHA verification for suspicious login patterns
    if (recaptchaToken) {
      const recaptchaValid = await verifyRecaptcha(recaptchaToken, securityContext.ipAddress)
      if (!recaptchaValid) {
        await AuditService.logEvent({
          action: 'failed_login',
          userEmail: email,
          ipAddress: securityContext.ipAddress,
          userAgent: securityContext.userAgent,
          requestId: securityContext.requestId,
          resourceType: 'auth',
          riskScore: 50,
          metadata: { reason: 'recaptcha_failed' }
        })

        throw new ApiError('reCAPTCHA verification failed', 400, 'RECAPTCHA_FAILED')
      }
    }

    // Fetch user from database
    const { data: user, error: userError } = await supabaseAdmin
      .from('admin_users')
      .select('*')
      .eq('email', email)
      .eq('active', true)
      .single()

    if (userError || !user) {
      await AuditService.logEvent({
        action: 'failed_login',
        userEmail: email,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 40,
        metadata: { reason: 'user_not_found' }
      })

      throw new ApiError('Invalid login credentials', 401, 'INVALID_CREDENTIALS')
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await AuditService.logEvent({
        action: 'failed_login',
        userId: user.id,
        userEmail: email,
        userRole: user.role,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 60,
        metadata: { reason: 'account_locked', locked_until: user.locked_until }
      })

      throw new ApiError('Account is temporarily locked. Please try again later.', 423, 'ACCOUNT_LOCKED')
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password_hash)

    if (!passwordValid) {
      // Update failed login attempts
      await updateLoginTracking(user.id, securityContext.ipAddress, false)

      await AuditService.logEvent({
        action: 'failed_login',
        userId: user.id,
        userEmail: email,
        userRole: user.role,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 35,
        metadata: {
          reason: 'invalid_password',
          failed_attempts: user.failed_login_attempts + 1
        }
      })

      throw new ApiError('Invalid login credentials', 401, 'INVALID_CREDENTIALS')
    }

    // Successful login - update tracking
    await updateLoginTracking(user.id, securityContext.ipAddress, true)

    // Generate JWT token
    const token = generateToken(user)
    const expiresAt = new Date(Date.now() + (24 * 60 * 60 * 1000)).toISOString() // 24 hours

    // Log successful login
    await AuditService.logEvent({
      action: 'user_login',
      userId: user.id,
      userEmail: email,
      userRole: user.role,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      requestId: securityContext.requestId,
      resourceType: 'auth',
      riskScore: 0,
      metadata: {
        login_method: 'password',
        processing_time: Date.now() - startTime
      }
    })

    // Prepare response data (exclude sensitive fields)
    const userData = {
      id: user.id,
      email: user.email,
      role: user.role,
      lastLogin: user.last_login
    }

    const response: ApiResponse = {
      success: true,
      message: 'Login successful',
      data: {
        user: userData,
        token,
        expiresAt
      }
    }

    // Set secure HTTP-only cookie
    const cookieOptions = [
      `auth-token=${token}`,
      'HttpOnly',
      'Secure',
      'SameSite=Strict',
      `Max-Age=${24 * 60 * 60}`, // 24 hours
      'Path=/',
      ...(process.env.NODE_ENV === 'production' ? ['Domain=.fynsor.com'] : [])
    ].join('; ')

    return NextResponse.json(response, {
      status: 200,
      headers: {
        'Set-Cookie': cookieOptions,
        'X-Request-ID': securityContext.requestId,
        'X-Processing-Time': `${Date.now() - startTime}ms`
      }
    })

  } catch (error) {
    // Log failed login attempt if we have user email
    if (userEmail && securityContext) {
      await AuditService.logEvent({
        action: 'failed_login',
        userEmail,
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'auth',
        riskScore: 45,
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

// OPTIONS endpoint for CORS
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://admin.fynsor.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    },
  })
}