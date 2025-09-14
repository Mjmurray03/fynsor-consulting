import { z } from 'zod'
import DOMPurify from 'isomorphic-dompurify'
import validator from 'validator'

// Validation error interface
export interface ValidationError {
  field: string
  message: string
  code: string
  value?: any
}

export interface ValidationResult {
  isValid: boolean
  errors: ValidationError[]
  sanitizedData?: any
}

// Common validation schemas
export const commonSchemas = {
  // Email validation
  email: z.string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .refine(
      (email) => validator.isEmail(email),
      'Invalid email format'
    ),

  // Phone validation (international format)
  phone: z.string()
    .regex(/^[\+]?[1-9][\d]{0,15}$/, 'Invalid phone number format')
    .optional()
    .nullable(),

  // Name validation (letters, spaces, hyphens, apostrophes, periods)
  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long')
    .regex(/^[a-zA-Z\s\-\'\.]+$/, 'Name contains invalid characters'),

  // Company name validation
  company: z.string()
    .max(200, 'Company name too long')
    .regex(/^[a-zA-Z0-9\s\-&\.,\']+$/, 'Company name contains invalid characters')
    .optional()
    .nullable(),

  // Text content validation (for messages, descriptions)
  textContent: z.string()
    .max(5000, 'Text too long')
    .optional()
    .nullable(),

  // UUID validation
  uuid: z.string().uuid('Invalid UUID format'),

  // Positive number validation
  positiveNumber: z.number().positive('Must be a positive number'),

  // Percentage validation (0-100)
  percentage: z.number().min(0, 'Percentage cannot be negative').max(100, 'Percentage cannot exceed 100'),

  // IP address validation
  ipAddress: z.string().ip('Invalid IP address'),

  // URL validation
  url: z.string().url('Invalid URL format').optional().nullable()
}

// Input sanitization functions
export class InputSanitizer {
  /**
   * Sanitize general text input
   */
  static sanitizeText(input: string): string {
    if (!input || typeof input !== 'string') return ''

    // Remove null bytes and control characters
    let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Trim whitespace
    sanitized = sanitized.trim()

    // Normalize unicode
    sanitized = sanitized.normalize('NFC')

    return sanitized
  }

  /**
   * Sanitize HTML content (removes all HTML tags)
   */
  static sanitizeHTML(input: string): string {
    if (!input || typeof input !== 'string') return ''

    // Use DOMPurify to remove all HTML
    return DOMPurify.sanitize(input, { ALLOWED_TAGS: [] })
  }

  /**
   * Sanitize email addresses
   */
  static sanitizeEmail(input: string): string {
    if (!input || typeof input !== 'string') return ''

    let sanitized = this.sanitizeText(input)
    sanitized = sanitized.toLowerCase()

    // Validate with validator.js
    if (!validator.isEmail(sanitized)) {
      return ''
    }

    return sanitized
  }

  /**
   * Sanitize phone numbers
   */
  static sanitizePhone(input: string): string {
    if (!input || typeof input !== 'string') return ''

    // Remove all non-digit characters except + at the beginning
    let sanitized = input.replace(/[^\d+]/g, '')

    // Ensure + is only at the beginning
    if (sanitized.includes('+')) {
      const parts = sanitized.split('+')
      sanitized = '+' + parts.join('')
    }

    return sanitized
  }

  /**
   * Sanitize file paths (prevent directory traversal)
   */
  static sanitizeFilePath(input: string): string {
    if (!input || typeof input !== 'string') return ''

    let sanitized = this.sanitizeText(input)

    // Remove dangerous path components
    sanitized = sanitized.replace(/\.\./g, '')
    sanitized = sanitized.replace(/[\/\\]/g, '_')

    return sanitized
  }

  /**
   * Sanitize SQL input (basic protection - should use parameterized queries)
   */
  static sanitizeSQL(input: string): string {
    if (!input || typeof input !== 'string') return ''

    let sanitized = this.sanitizeText(input)

    // Remove SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
      /[';]/g,
      /--/g,
      /\/\*/g,
      /\*\//g
    ]

    sqlPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '')
    })

    return sanitized
  }

  /**
   * Sanitize JSON input
   */
  static sanitizeJSON(input: any): any {
    if (typeof input === 'string') {
      return this.sanitizeText(input)
    }

    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeJSON(item))
    }

    if (typeof input === 'object' && input !== null) {
      const sanitized: any = {}
      for (const [key, value] of Object.entries(input)) {
        const sanitizedKey = this.sanitizeText(key)
        sanitized[sanitizedKey] = this.sanitizeJSON(value)
      }
      return sanitized
    }

    return input
  }
}

// Main sanitization function
export function sanitizeInput(input: any, type: 'text' | 'email' | 'phone' | 'html' | 'sql' | 'json' = 'text'): any {
  if (input === null || input === undefined) return input

  switch (type) {
    case 'email':
      return InputSanitizer.sanitizeEmail(String(input))
    case 'phone':
      return InputSanitizer.sanitizePhone(String(input))
    case 'html':
      return InputSanitizer.sanitizeHTML(String(input))
    case 'sql':
      return InputSanitizer.sanitizeSQL(String(input))
    case 'json':
      return InputSanitizer.sanitizeJSON(input)
    case 'text':
    default:
      return InputSanitizer.sanitizeText(String(input))
  }
}

// Advanced validation functions
export class AdvancedValidator {
  /**
   * Validate credit card number (basic Luhn algorithm)
   */
  static validateCreditCard(number: string): boolean {
    const sanitized = number.replace(/\D/g, '')

    if (sanitized.length < 13 || sanitized.length > 19) {
      return false
    }

    // Luhn algorithm
    let sum = 0
    let shouldDouble = false

    for (let i = sanitized.length - 1; i >= 0; i--) {
      let digit = parseInt(sanitized.charAt(i), 10)

      if (shouldDouble) {
        digit *= 2
        if (digit > 9) {
          digit -= 9
        }
      }

      sum += digit
      shouldDouble = !shouldDouble
    }

    return sum % 10 === 0
  }

  /**
   * Validate social security number (US format)
   */
  static validateSSN(ssn: string): boolean {
    const sanitized = ssn.replace(/\D/g, '')

    if (sanitized.length !== 9) {
      return false
    }

    // Check for invalid patterns
    const invalidPatterns = [
      '000000000',
      '123456789',
      '111111111',
      '222222222',
      '333333333',
      '444444444',
      '555555555',
      '666666666',
      '777777777',
      '888888888',
      '999999999'
    ]

    return !invalidPatterns.includes(sanitized)
  }

  /**
   * Validate password strength
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean
    score: number
    requirements: {
      length: boolean
      lowercase: boolean
      uppercase: boolean
      number: boolean
      special: boolean
    }
    suggestions: string[]
  } {
    const requirements = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    }

    const score = Object.values(requirements).filter(Boolean).length * 20
    const isValid = score >= 80

    const suggestions: string[] = []
    if (!requirements.length) suggestions.push('Use at least 8 characters')
    if (!requirements.lowercase) suggestions.push('Include lowercase letters')
    if (!requirements.uppercase) suggestions.push('Include uppercase letters')
    if (!requirements.number) suggestions.push('Include numbers')
    if (!requirements.special) suggestions.push('Include special characters')

    return {
      isValid,
      score,
      requirements,
      suggestions
    }
  }

  /**
   * Validate financial amount
   */
  static validateFinancialAmount(amount: number, min = 0, max = Infinity): ValidationResult {
    const errors: ValidationError[] = []

    if (typeof amount !== 'number' || isNaN(amount)) {
      errors.push({
        field: 'amount',
        message: 'Amount must be a valid number',
        code: 'INVALID_NUMBER'
      })
    }

    if (amount < min) {
      errors.push({
        field: 'amount',
        message: `Amount must be at least ${min}`,
        code: 'AMOUNT_TOO_LOW',
        value: amount
      })
    }

    if (amount > max) {
      errors.push({
        field: 'amount',
        message: `Amount cannot exceed ${max}`,
        code: 'AMOUNT_TOO_HIGH',
        value: amount
      })
    }

    // Check for reasonable decimal places (max 2 for currency)
    if (amount % 0.01 !== 0) {
      errors.push({
        field: 'amount',
        message: 'Amount cannot have more than 2 decimal places',
        code: 'INVALID_DECIMAL_PLACES',
        value: amount
      })
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: Math.round(amount * 100) / 100 // Round to 2 decimal places
    }
  }

  /**
   * Validate business identifier (EIN)
   */
  static validateEIN(ein: string): boolean {
    const sanitized = ein.replace(/\D/g, '')

    if (sanitized.length !== 9) {
      return false
    }

    // First two digits should be valid prefix
    const prefix = parseInt(sanitized.substring(0, 2), 10)
    const validPrefixes = [
      10, 12, 20, 21, 22, 23, 24, 25, 26, 27, 30, 32, 34, 35, 36, 37, 38, 39,
      40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
      60, 61, 62, 63, 64, 65, 66, 67, 68, 71, 72, 73, 74, 75, 76, 77, 81, 82, 83,
      84, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 98, 99
    ]

    return validPrefixes.includes(prefix)
  }
}

// Composite validation function for complex objects
export function validateObject<T>(
  data: any,
  schema: z.ZodSchema<T>,
  options: {
    sanitize?: boolean
    strictMode?: boolean
    allowUnknown?: boolean
  } = {}
): ValidationResult {
  const { sanitize = true, strictMode = false, allowUnknown = false } = options

  try {
    // Sanitize data if requested
    let processedData = data
    if (sanitize) {
      processedData = InputSanitizer.sanitizeJSON(data)
    }

    // Remove unknown fields in strict mode
    if (strictMode && !allowUnknown && typeof processedData === 'object') {
      // This would require knowing the schema shape, simplified for now
      processedData = { ...processedData }
    }

    // Validate with Zod
    const result = schema.safeParse(processedData)

    if (result.success) {
      return {
        isValid: true,
        errors: [],
        sanitizedData: result.data
      }
    } else {
      const errors: ValidationError[] = result.error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
        code: err.code,
        value: err.input
      }))

      return {
        isValid: false,
        errors,
        sanitizedData: processedData
      }
    }
  } catch (error) {
    return {
      isValid: false,
      errors: [{
        field: 'root',
        message: error instanceof Error ? error.message : 'Validation failed',
        code: 'VALIDATION_ERROR'
      }]
    }
  }
}

// Rate limiting validation
export function validateRateLimit(
  identifier: string,
  action: string,
  limit: number,
  windowMs: number,
  storage: Map<string, { count: number; windowStart: number }> = new Map()
): { allowed: boolean; remaining: number; resetTime: number } {
  const key = `${identifier}:${action}`
  const now = Date.now()

  const record = storage.get(key)

  if (!record || now - record.windowStart > windowMs) {
    // New window
    storage.set(key, { count: 1, windowStart: now })
    return {
      allowed: true,
      remaining: limit - 1,
      resetTime: now + windowMs
    }
  }

  if (record.count >= limit) {
    // Rate limit exceeded
    return {
      allowed: false,
      remaining: 0,
      resetTime: record.windowStart + windowMs
    }
  }

  // Increment counter
  record.count++
  storage.set(key, record)

  return {
    allowed: true,
    remaining: limit - record.count,
    resetTime: record.windowStart + windowMs
  }
}

// Security headers validation
export function validateSecurityHeaders(headers: Record<string, string | undefined>): {
  isValid: boolean
  missingHeaders: string[]
  recommendations: string[]
} {
  const requiredHeaders = [
    'x-frame-options',
    'x-content-type-options',
    'x-xss-protection',
    'strict-transport-security',
    'content-security-policy'
  ]

  const missingHeaders = requiredHeaders.filter(header =>
    !headers[header] && !headers[header.toLowerCase()]
  )

  const recommendations: string[] = []

  if (missingHeaders.includes('x-frame-options')) {
    recommendations.push('Add X-Frame-Options header to prevent clickjacking')
  }

  if (missingHeaders.includes('content-security-policy')) {
    recommendations.push('Implement Content Security Policy to prevent XSS attacks')
  }

  if (missingHeaders.includes('strict-transport-security')) {
    recommendations.push('Add HSTS header to enforce HTTPS')
  }

  return {
    isValid: missingHeaders.length === 0,
    missingHeaders,
    recommendations
  }
}

export default {
  commonSchemas,
  InputSanitizer,
  sanitizeInput,
  AdvancedValidator,
  validateObject,
  validateRateLimit,
  validateSecurityHeaders
}