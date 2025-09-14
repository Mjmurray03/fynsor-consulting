import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { ContactService, AuditService, RateLimitService } from '@/lib/supabase/client'
import { ContactFormData, ApiResponse, PropertyType, InvestmentSize } from '@/lib/supabase/types'
import { validateInput, sanitizeInput } from '@/lib/server-validation'
import { handleApiError, ApiError } from '@/lib/error-handling'

// Validation schema for contact form
const contactSchema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .max(100, 'Name must be less than 100 characters')
    .regex(/^[a-zA-Z\s\-\'\.]+$/, 'Name contains invalid characters'),

  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email must be less than 255 characters')
    .toLowerCase(),

  company: z
    .string()
    .max(200, 'Company name must be less than 200 characters')
    .regex(/^[a-zA-Z0-9\s\-&\.,\']+$/, 'Company name contains invalid characters')
    .optional()
    .nullable(),

  phone: z
    .string()
    .regex(/^[\+]?[1-9][\d]{0,15}$/, 'Invalid phone number format')
    .optional()
    .nullable(),

  message: z
    .string()
    .max(5000, 'Message must be less than 5000 characters')
    .optional()
    .nullable(),

  propertyType: z
    .enum(['office', 'retail', 'industrial', 'multifamily', 'hospitality', 'mixed_use', 'land', 'other'])
    .optional()
    .nullable(),

  investmentSize: z
    .enum(['under_1m', '1m_5m', '5m_10m', '10m_25m', '25m_50m', '50m_100m', 'over_100m'])
    .optional()
    .nullable(),

  // Honeypot field for bot detection
  website: z.string().max(0, 'Bot detected').optional(),

  // reCAPTCHA token
  recaptchaToken: z.string().min(1, 'reCAPTCHA verification required').optional()
})

// Enhanced security validation
function validateSecurityContext(request: NextRequest): {
  ipAddress: string
  userAgent: string
  requestId: string
  riskScore: number
} {
  const ipAddress =
    request.headers.get('x-forwarded-for')?.split(',')[0] ||
    request.headers.get('x-real-ip') ||
    '127.0.0.1'

  const userAgent = request.headers.get('user-agent') || 'unknown'
  const requestId = request.headers.get('x-request-id') || crypto.randomUUID()

  // Calculate risk score based on various factors
  let riskScore = 0

  // Check for suspicious patterns
  if (userAgent.toLowerCase().includes('bot') || userAgent.toLowerCase().includes('crawler')) {
    riskScore += 30
  }

  if (ipAddress === '127.0.0.1' || ipAddress.startsWith('10.') || ipAddress.startsWith('192.168.')) {
    riskScore += 10 // Local/private IP
  }

  // Check request frequency (simplified)
  const referer = request.headers.get('referer')
  if (!referer || !referer.includes('fynsor.com')) {
    riskScore += 20
  }

  return { ipAddress, userAgent, requestId, riskScore }
}

// reCAPTCHA verification
async function verifyRecaptcha(token: string, ipAddress: string): Promise<boolean> {
  if (!process.env.RECAPTCHA_SECRET_KEY) {
    console.warn('reCAPTCHA secret key not configured')
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
    return data.success && data.score > 0.5
  } catch (error) {
    console.error('reCAPTCHA verification failed:', error)
    return false
  }
}

// POST endpoint for contact form submission
export async function POST(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  let securityContext: ReturnType<typeof validateSecurityContext>

  try {
    // Get security context
    securityContext = validateSecurityContext(request)

    // Rate limiting check
    const rateLimitAllowed = await RateLimitService.checkRateLimit(
      securityContext.ipAddress,
      '/api/contact',
      5, // 5 requests
      60 // per hour
    )

    if (!rateLimitAllowed) {
      await AuditService.logEvent({
        action: 'rate_limit_exceeded',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'contact_form',
        riskScore: securityContext.riskScore + 25,
        metadata: { endpoint: '/api/contact' }
      })

      throw new ApiError('Too many requests. Please try again later.', 429, 'RATE_LIMIT_EXCEEDED')
    }

    // Parse and validate request body
    let body: any
    try {
      body = await request.json()
    } catch (error) {
      throw new ApiError('Invalid JSON in request body', 400, 'INVALID_JSON')
    }

    // Honeypot check
    if (body.website && body.website.length > 0) {
      await AuditService.logEvent({
        action: 'contact_creation_failed',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'contact_form',
        riskScore: securityContext.riskScore + 50,
        metadata: { reason: 'honeypot_triggered' }
      })

      throw new ApiError('Bot detected', 400, 'BOT_DETECTED')
    }

    // reCAPTCHA verification
    if (body.recaptchaToken) {
      const recaptchaValid = await verifyRecaptcha(body.recaptchaToken, securityContext.ipAddress)
      if (!recaptchaValid) {
        throw new ApiError('reCAPTCHA verification failed', 400, 'RECAPTCHA_FAILED')
      }
    }

    // Sanitize input data
    const sanitizedData = {
      name: sanitizeInput(body.name),
      email: sanitizeInput(body.email),
      company: body.company ? sanitizeInput(body.company) : undefined,
      phone: body.phone ? sanitizeInput(body.phone) : undefined,
      message: body.message ? sanitizeInput(body.message) : undefined,
      propertyType: body.propertyType,
      investmentSize: body.investmentSize,
    }

    // Validate sanitized data
    const validationResult = contactSchema.safeParse(sanitizedData)

    if (!validationResult.success) {
      const errors = validationResult.error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
        code: err.code
      }))

      await AuditService.logEvent({
        action: 'contact_creation_failed',
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        requestId: securityContext.requestId,
        resourceType: 'contact_form',
        riskScore: securityContext.riskScore + 15,
        metadata: { reason: 'validation_failed', errors }
      })

      throw new ApiError('Validation failed', 400, 'VALIDATION_FAILED', { errors })
    }

    const validatedData = validationResult.data

    // Additional business logic validation
    if (validatedData.investmentSize && !validatedData.propertyType) {
      throw new ApiError('Property type is required when investment size is specified', 400, 'MISSING_PROPERTY_TYPE')
    }

    // Create contact using service
    const contactService = new ContactService()
    const result = await contactService.createContact({
      name: validatedData.name,
      email: validatedData.email,
      company: validatedData.company || undefined,
      phone: validatedData.phone || undefined,
      message: validatedData.message || undefined,
      propertyType: validatedData.propertyType as PropertyType,
      investmentSize: validatedData.investmentSize as InvestmentSize,
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      referrer: request.headers.get('referer') || undefined,
      utmSource: new URL(request.url).searchParams.get('utm_source') || undefined,
      utmMedium: new URL(request.url).searchParams.get('utm_medium') || undefined,
      utmCampaign: new URL(request.url).searchParams.get('utm_campaign') || undefined,
    })

    if (!result.success) {
      throw new ApiError(result.error || 'Failed to create contact', 500, 'CONTACT_CREATION_FAILED')
    }

    // Send admin notification (without PII)
    if (process.env.ADMIN_NOTIFICATION_WEBHOOK) {
      try {
        await fetch(process.env.ADMIN_NOTIFICATION_WEBHOOK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: `New contact form submission`,
            attachments: [{
              color: 'good',
              fields: [
                { title: 'Property Type', value: validatedData.propertyType || 'Not specified', short: true },
                { title: 'Investment Size', value: validatedData.investmentSize || 'Not specified', short: true },
                { title: 'Contact ID', value: result.contactId, short: true },
                { title: 'Timestamp', value: new Date().toISOString(), short: true },
              ]
            }]
          })
        })
      } catch (error) {
        console.error('Failed to send admin notification:', error)
        // Don't fail the request if notification fails
      }
    }

    const processingTime = Date.now() - startTime

    // Log successful submission
    await AuditService.logEvent({
      action: 'contact_created',
      ipAddress: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      requestId: securityContext.requestId,
      resourceType: 'contact',
      resourceId: result.contactId,
      riskScore: securityContext.riskScore,
      metadata: {
        propertyType: validatedData.propertyType,
        investmentSize: validatedData.investmentSize,
        hasCompany: !!validatedData.company,
        hasPhone: !!validatedData.phone,
        hasMessage: !!validatedData.message,
        processingTime
      }
    })

    const response: ApiResponse = {
      success: true,
      message: 'Contact form submitted successfully. We will get back to you soon.',
      data: {
        contactId: result.contactId,
        submittedAt: new Date().toISOString()
      }
    }

    return NextResponse.json(response, {
      status: 201,
      headers: {
        'X-Request-ID': securityContext.requestId,
        'X-Processing-Time': `${processingTime}ms`
      }
    })

  } catch (error) {
    return handleApiError(error, {
      ipAddress: securityContext?.ipAddress,
      userAgent: securityContext?.userAgent,
      requestId: securityContext?.requestId,
      processingTime: Date.now() - startTime
    })
  }
}

// GET endpoint for retrieving contacts (admin only)
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // This would require authentication middleware in a real implementation
    // For now, we'll just return an error
    throw new ApiError('Authentication required', 401, 'AUTHENTICATION_REQUIRED')

    // Example of what the authenticated endpoint would look like:
    /*
    const user = await authenticateRequest(request)
    if (!user || user.role !== 'admin') {
      throw new ApiError('Insufficient permissions', 403, 'INSUFFICIENT_PERMISSIONS')
    }

    const { searchParams } = new URL(request.url)
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100)
    const offset = parseInt(searchParams.get('offset') || '0')

    const contactService = new ContactService()
    const result = await contactService.getContacts(user.id, limit, offset)

    if (!result.success) {
      throw new ApiError(result.error || 'Failed to retrieve contacts', 500, 'RETRIEVAL_FAILED')
    }

    return NextResponse.json({
      success: true,
      data: {
        contacts: result.contacts,
        pagination: {
          limit,
          offset,
          total: result.contacts?.length || 0
        }
      }
    })
    */

  } catch (error) {
    return handleApiError(error)
  }
}

// OPTIONS endpoint for CORS
export async function OPTIONS(request: NextRequest): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.ALLOWED_ORIGINS || 'https://fynsor.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Request-ID',
      'Access-Control-Max-Age': '86400',
    },
  })
}