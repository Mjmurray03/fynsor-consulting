import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { supabaseAdmin } from '@/lib/supabase/client'

// Rate limiting storage (simple in-memory for small site)
const rateLimit = new Map<string, { count: number; resetTime: number }>()

// Validation schema for contact form
const contactSchema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .max(100, 'Name must be less than 100 characters'),

  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email must be less than 255 characters')
    .toLowerCase(),

  company: z
    .string()
    .max(200, 'Company name must be less than 200 characters')
    .optional(),

  phone: z
    .string()
    .optional(),

  message: z
    .string()
    .max(5000, 'Message must be less than 5000 characters')
    .optional(),

  propertyType: z
    .enum(['office', 'retail', 'industrial', 'multifamily', 'hospitality', 'mixed_use', 'land', 'other'])
    .optional(),

  investmentSize: z
    .enum(['under_1m', '1m_5m', '5m_10m', '10m_25m', '25m_50m', '50m_100m', 'over_100m'])
    .optional(),

  // Honeypot field for bot detection
  website: z.string().max(0, 'Bot detected').optional(),
})

// Simple rate limiting (5 requests per hour per IP)
function checkRateLimit(ip: string): boolean {
  const now = Date.now()
  const hourInMs = 60 * 60 * 1000

  const current = rateLimit.get(ip)

  if (!current || now > current.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + hourInMs })
    return true
  }

  if (current.count >= 5) {
    return false
  }

  current.count++
  return true
}

// Get client IP
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for')?.split(',')[0] ||
         request.headers.get('x-real-ip') ||
         '127.0.0.1'
}

// POST endpoint for contact form submission
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const ip = getClientIP(request)

    // Rate limiting check
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      )
    }

    // Parse request body
    const body = await request.json()

    // Honeypot check
    if (body.website && body.website.length > 0) {
      return NextResponse.json(
        { error: 'Bot detected' },
        { status: 400 }
      )
    }

    // Validate input
    const validationResult = contactSchema.safeParse(body)

    if (!validationResult.success) {
      const errors = validationResult.error.issues.map(err => ({
        field: err.path.join('.'),
        message: err.message,
      }))

      return NextResponse.json(
        { error: 'Validation failed', details: errors },
        { status: 400 }
      )
    }

    const data = validationResult.data

    // Store in Supabase
    const { error } = await supabaseAdmin
      .from('contacts')
      .insert({
        name_encrypted: data.name,
        email_encrypted: data.email,
        company_encrypted: data.company || null,
        phone_encrypted: data.phone || null,
        message_encrypted: data.message || null,
        property_type: data.propertyType || null,
        investment_size: data.investmentSize || null,
        ip_address: ip,
        user_agent: request.headers.get('user-agent') || null,
        referrer: request.headers.get('referer') || null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })

    if (error) {
      console.error('Database error:', error)
      return NextResponse.json(
        { error: 'Failed to submit form. Please try again.' },
        { status: 500 }
      )
    }

    return NextResponse.json({
      success: true,
      message: 'Contact form submitted successfully. We will get back to you soon.',
    })

  } catch (error) {
    console.error('Contact form error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

// OPTIONS endpoint for CORS
export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  })
}