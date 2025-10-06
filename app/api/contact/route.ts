import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { supabaseAdmin } from '@/lib/supabase/client'
import { Resend } from 'resend'

// Initialize Resend (only if API key is available)
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null

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

    // Store in Supabase (continue if this fails)
    let databaseSuccess = false
    let databaseError = null
    try {
      console.log('Attempting to store contact in Supabase...')
      console.log('Supabase URL:', process.env.NEXT_PUBLIC_SUPABASE_URL ? 'Set' : 'Missing')
      console.log('Service Role Key:', process.env.SUPABASE_SERVICE_ROLE_KEY ? 'Set' : 'Missing')

      const { data: insertData, error } = await supabaseAdmin
        .from('contacts')
        .insert({
          name: data.name,
          email: data.email,
          company: data.company || null,
          message: data.message || null,
          ip_address: ip || 'unknown',
          user_agent: request.headers.get('user-agent') || null,
          referrer: request.headers.get('referer') || null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .select()

      if (error) {
        console.error('Database insert error:', {
          code: error.code,
          message: error.message,
          details: error.details,
          hint: error.hint
        })
        databaseError = error.message
      } else {
        databaseSuccess = true
        console.log('Successfully stored contact in database:', insertData)
      }
    } catch (dbError: any) {
      console.error('Database connection failed:', {
        error: dbError,
        message: dbError?.message,
        stack: dbError?.stack
      })
      databaseError = dbError?.message || 'Unknown database error'
    }

    // Send email notification to contact@fynsor.io
    let emailSuccess = false
    try {
      if (resend) {
        console.log('Attempting to send email notification...')
        const emailResult = await resend.emails.send({
          from: 'onboarding@resend.dev', // Use Resend's verified domain until fynsor.io is verified
          to: ['michael.murray@fynsor.io'], // Use your verified email address
          subject: `New Contact Form Submission from ${data.name}`,
          html: `
            <h2>New Contact Form Submission</h2>
            <p><strong>Name:</strong> ${data.name}</p>
            <p><strong>Email:</strong> ${data.email}</p>
            <p><strong>Company:</strong> ${data.company || 'Not provided'}</p>
            <p><strong>Message:</strong></p>
            <p>${data.message || 'No message provided'}</p>
            <hr>
            <p><small>Submitted from: ${request.headers.get('referer') || 'Unknown'}</small></p>
            <p><small>IP Address: ${ip}</small></p>
            <p><small>Time: ${new Date().toISOString()}</small></p>
          `,
        })
        console.log('Email sent successfully:', emailResult)
        emailSuccess = true
      } else {
        console.log('Resend not initialized - missing API key')
      }
    } catch (emailError) {
      console.error('Email sending error:', emailError)
      // Don't fail the request if email fails - the form submission was still successful
    }

    return NextResponse.json({
      success: true,
      message: 'Contact form submitted successfully. We will get back to you soon.',
      details: {
        databaseStored: databaseSuccess,
        databaseError: databaseError,
        emailSent: emailSuccess,
        resendConfigured: !!resend
      }
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