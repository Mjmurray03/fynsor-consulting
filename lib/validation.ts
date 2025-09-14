/**
 * Input Validation and Sanitization Library
 * Comprehensive input validation and XSS protection for Fynsor Consulting
 */

import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';
import validator from 'validator';

// Validation configuration
const VALIDATION_CONFIG = {
  maxStringLength: 10000,
  maxArrayLength: 1000,
  maxObjectDepth: 10,
  allowedFileTypes: ['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'],
  maxFileSize: 10 * 1024 * 1024, // 10MB
} as const;

// Common validation patterns
const PATTERNS = {
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  phone: /^\+?[\d\s\-\(\)\.]{10,20}$/,
  name: /^[a-zA-Z\s\-\.\']{1,100}$/,
  businessName: /^[a-zA-Z0-9\s\-\.\'&,]{1,200}$/,
  alphanumeric: /^[a-zA-Z0-9]+$/,
  slug: /^[a-z0-9\-_]+$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  url: /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$/,
} as const;

// Dangerous patterns to detect
const DANGEROUS_PATTERNS = [
  // Script injection
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  // JavaScript URLs
  /javascript:/gi,
  // Data URLs with scripts
  /data:.*script/gi,
  // Event handlers
  /on\w+\s*=/gi,
  // SQL injection patterns
  /(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b).*(\bfrom\b|\binto\b|\bwhere\b)/gi,
  // Command injection
  /(\$\(|\`|&&|\|\||;|<|>)/g,
  // LDAP injection
  /(\*|\(|\)|\\|\||&)/g,
] as const;

// XSS patterns
const XSS_PATTERNS = [
  /<script[^>]*>.*?<\/script>/gi,
  /<iframe[^>]*>.*?<\/iframe>/gi,
  /<object[^>]*>.*?<\/object>/gi,
  /<embed[^>]*>/gi,
  /<link[^>]*>/gi,
  /<meta[^>]*>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /data:text\/html/gi,
  /onload\s*=/gi,
  /onerror\s*=/gi,
  /onclick\s*=/gi,
  /onmouseover\s*=/gi,
] as const;

// Input sanitizer class
export class InputSanitizer {
  // Sanitize string input
  static sanitizeString(input: string, options: {
    allowHtml?: boolean;
    allowedTags?: string[];
    maxLength?: number;
    stripDangerous?: boolean;
  } = {}): string {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    let sanitized = input;

    // Basic trimming
    sanitized = sanitized.trim();

    // Length check
    const maxLength = options.maxLength || VALIDATION_CONFIG.maxStringLength;
    if (sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    // Strip dangerous patterns if requested
    if (options.stripDangerous !== false) {
      DANGEROUS_PATTERNS.forEach(pattern => {
        sanitized = sanitized.replace(pattern, '');
      });
    }

    // HTML sanitization
    if (options.allowHtml) {
      const allowedTags = options.allowedTags || ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li'];
      sanitized = DOMPurify.sanitize(sanitized, {
        ALLOWED_TAGS: allowedTags,
        ALLOWED_ATTR: ['href', 'title', 'target'],
        ALLOW_DATA_ATTR: false,
      });
    } else {
      // Strip all HTML
      sanitized = DOMPurify.sanitize(sanitized, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
      });
    }

    // Additional XSS protection
    XSS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });

    // Encode special characters
    sanitized = validator.escape(sanitized);

    return sanitized;
  }

  // Sanitize email
  static sanitizeEmail(email: string): string {
    if (typeof email !== 'string') {
      throw new Error('Email must be a string');
    }

    let sanitized = email.trim().toLowerCase();

    // Basic email validation
    if (!PATTERNS.email.test(sanitized)) {
      throw new Error('Invalid email format');
    }

    // Additional validation using validator library
    if (!validator.isEmail(sanitized)) {
      throw new Error('Invalid email format');
    }

    return validator.normalizeEmail(sanitized) || sanitized;
  }

  // Sanitize phone number
  static sanitizePhone(phone: string): string {
    if (typeof phone !== 'string') {
      throw new Error('Phone must be a string');
    }

    // Remove all non-digit characters except + at the beginning
    let sanitized = phone.replace(/[^\d+]/g, '');

    // Ensure + is only at the beginning
    if (sanitized.includes('+')) {
      const plusIndex = sanitized.indexOf('+');
      if (plusIndex > 0) {
        sanitized = sanitized.replace(/\+/g, '');
      } else {
        sanitized = '+' + sanitized.replace(/\+/g, '');
      }
    }

    // Basic phone validation
    if (!PATTERNS.phone.test(phone)) {
      throw new Error('Invalid phone format');
    }

    return sanitized;
  }

  // Sanitize URL
  static sanitizeUrl(url: string): string {
    if (typeof url !== 'string') {
      throw new Error('URL must be a string');
    }

    let sanitized = url.trim();

    // Only allow HTTP and HTTPS URLs
    if (!sanitized.startsWith('http://') && !sanitized.startsWith('https://')) {
      sanitized = 'https://' + sanitized;
    }

    if (!validator.isURL(sanitized, {
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true,
    })) {
      throw new Error('Invalid URL format');
    }

    return sanitized;
  }

  // Sanitize object recursively
  static sanitizeObject(obj: any, depth: number = 0): any {
    if (depth > VALIDATION_CONFIG.maxObjectDepth) {
      throw new Error('Object depth exceeded maximum allowed');
    }

    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    if (typeof obj === 'number' || typeof obj === 'boolean') {
      return obj;
    }

    if (Array.isArray(obj)) {
      if (obj.length > VALIDATION_CONFIG.maxArrayLength) {
        throw new Error('Array length exceeded maximum allowed');
      }
      return obj.map(item => this.sanitizeObject(item, depth + 1));
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      const keys = Object.keys(obj);

      if (keys.length > 100) { // Prevent object with too many keys
        throw new Error('Object has too many keys');
      }

      keys.forEach(key => {
        const sanitizedKey = this.sanitizeString(key, { maxLength: 100 });
        sanitized[sanitizedKey] = this.sanitizeObject(obj[key], depth + 1);
      });

      return sanitized;
    }

    return obj;
  }

  // File upload sanitization
  static sanitizeFileName(fileName: string): string {
    if (typeof fileName !== 'string') {
      throw new Error('File name must be a string');
    }

    // Remove path separators and dangerous characters
    let sanitized = fileName.replace(/[\/\\:*?"<>|]/g, '');

    // Remove leading dots and spaces
    sanitized = sanitized.replace(/^[\.\s]+/, '');

    // Limit length
    if (sanitized.length > 255) {
      const extension = sanitized.split('.').pop();
      const nameWithoutExt = sanitized.substring(0, sanitized.lastIndexOf('.'));
      sanitized = nameWithoutExt.substring(0, 255 - (extension?.length || 0) - 1) + '.' + extension;
    }

    // Ensure it has an extension
    if (!sanitized.includes('.')) {
      throw new Error('File must have an extension');
    }

    const extension = sanitized.split('.').pop()?.toLowerCase();
    if (!extension || !VALIDATION_CONFIG.allowedFileTypes.includes(extension)) {
      throw new Error('File type not allowed');
    }

    return sanitized;
  }
}

// Validation schemas using Zod
export const ValidationSchemas = {
  // User input schemas
  email: z.string().email().max(255).transform(InputSanitizer.sanitizeEmail),

  phone: z.string().max(20).transform(InputSanitizer.sanitizePhone),

  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long')
    .regex(PATTERNS.name, 'Invalid name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 100 })),

  businessName: z.string()
    .min(1, 'Business name is required')
    .max(200, 'Business name too long')
    .regex(PATTERNS.businessName, 'Invalid business name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 200 })),

  message: z.string()
    .min(10, 'Message must be at least 10 characters')
    .max(5000, 'Message too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 5000 })),

  url: z.string().url().transform(InputSanitizer.sanitizeUrl),

  // Investment-specific schemas
  investmentAmount: z.number()
    .min(1000, 'Minimum investment is $1,000')
    .max(100000000, 'Maximum investment is $100,000,000')
    .positive('Investment amount must be positive'),

  investmentType: z.enum([
    'equity',
    'debt',
    'convertible',
    'revenue-share',
    'real-estate',
    'other'
  ]),

  riskTolerance: z.enum(['low', 'medium', 'high']),

  timeHorizon: z.enum(['short', 'medium', 'long']),

  accreditedInvestor: z.boolean(),

  // Contact form schema
  contactForm: z.object({
    firstName: z.string().min(1).max(50).transform(val =>
      InputSanitizer.sanitizeString(val, { maxLength: 50 })
    ),
    lastName: z.string().min(1).max(50).transform(val =>
      InputSanitizer.sanitizeString(val, { maxLength: 50 })
    ),
    email: z.string().email().transform(InputSanitizer.sanitizeEmail),
    phone: z.string().optional().transform(val =>
      val ? InputSanitizer.sanitizePhone(val) : undefined
    ),
    company: z.string().optional().transform(val =>
      val ? InputSanitizer.sanitizeString(val, { maxLength: 200 }) : undefined
    ),
    message: z.string().min(10).max(5000).transform(val =>
      InputSanitizer.sanitizeString(val, { maxLength: 5000 })
    ),
    // Honeypot fields
    website: z.string().optional(),
    company_name_hidden: z.string().optional(),
    email_verify: z.string().optional(),
  }),

  // Investment interest form schema
  investmentForm: z.object({
    firstName: z.string().min(1).max(50),
    lastName: z.string().min(1).max(50),
    email: z.string().email(),
    phone: z.string().optional(),
    investmentAmount: z.number().min(1000).max(100000000),
    investmentType: z.enum(['equity', 'debt', 'convertible', 'revenue-share', 'real-estate', 'other']),
    riskTolerance: z.enum(['low', 'medium', 'high']),
    timeHorizon: z.enum(['short', 'medium', 'long']),
    accreditedInvestor: z.boolean(),
    experience: z.string().max(2000),
    // Honeypot fields
    website: z.string().optional(),
    company_name_hidden: z.string().optional(),
    email_verify: z.string().optional(),
  }),

  // File upload schema
  fileUpload: z.object({
    name: z.string().transform(InputSanitizer.sanitizeFileName),
    size: z.number().max(VALIDATION_CONFIG.maxFileSize, 'File too large'),
    type: z.string().refine(
      type => VALIDATION_CONFIG.allowedFileTypes.some(allowed =>
        type.includes(allowed)
      ),
      'File type not allowed'
    ),
  }),
};

// Validation middleware
export class ValidationMiddleware {
  // Validate request body
  static validateBody<T>(schema: z.ZodSchema<T>) {
    return (body: unknown): T => {
      try {
        return schema.parse(body);
      } catch (error) {
        if (error instanceof z.ZodError) {
          const errorMessages = error.errors.map(err =>
            `${err.path.join('.')}: ${err.message}`
          ).join(', ');
          throw new Error(`Validation failed: ${errorMessages}`);
        }
        throw error;
      }
    };
  }

  // Validate query parameters
  static validateQuery<T>(schema: z.ZodSchema<T>) {
    return (query: unknown): T => {
      try {
        return schema.parse(query);
      } catch (error) {
        if (error instanceof z.ZodError) {
          const errorMessages = error.errors.map(err =>
            `${err.path.join('.')}: ${err.message}`
          ).join(', ');
          throw new Error(`Query validation failed: ${errorMessages}`);
        }
        throw error;
      }
    };
  }

  // Validate headers
  static validateHeaders(requiredHeaders: string[]) {
    return (headers: Record<string, string | undefined>): void => {
      const missing = requiredHeaders.filter(header => !headers[header]);
      if (missing.length > 0) {
        throw new Error(`Missing required headers: ${missing.join(', ')}`);
      }
    };
  }
}

// Security validation functions
export class SecurityValidation {
  // Check for SQL injection patterns
  static containsSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b)/gi,
      /(\bor\b|\band\b).*=.*(\bor\b|\band\b)/gi,
      /['"].*[;].*['"]]/gi,
      /\b(exec|execute|sp_|xp_)\b/gi,
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  // Check for XSS patterns
  static containsXSS(input: string): boolean {
    return XSS_PATTERNS.some(pattern => pattern.test(input));
  }

  // Check for path traversal
  static containsPathTraversal(input: string): boolean {
    const pathPatterns = [
      /\.\.[\/\\]/g,
      /[\/\\]\.\.[\/\\]/g,
      /%2e%2e[\/\\]/gi,
      /\.\.%2f/gi,
      /\.\.%5c/gi,
    ];

    return pathPatterns.some(pattern => pattern.test(input));
  }

  // Check for command injection
  static containsCommandInjection(input: string): boolean {
    const commandPatterns = [
      /[;&|`$(){}[\]]/g,
      /\b(cat|ls|dir|type|copy|del|rm|mv|cp)\b/gi,
      /\b(wget|curl|nc|netcat)\b/gi,
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }

  // Comprehensive security check
  static isSecureInput(input: string): { secure: boolean; threats: string[] } {
    const threats: string[] = [];

    if (this.containsSQLInjection(input)) {
      threats.push('SQL Injection');
    }

    if (this.containsXSS(input)) {
      threats.push('XSS');
    }

    if (this.containsPathTraversal(input)) {
      threats.push('Path Traversal');
    }

    if (this.containsCommandInjection(input)) {
      threats.push('Command Injection');
    }

    return {
      secure: threats.length === 0,
      threats,
    };
  }
}

// Rate limiting validation
export class RateLimitValidation {
  private static readonly submissions = new Map<string, { count: number; resetTime: number }>();

  // Validate submission rate (5 per hour)
  static validateSubmissionRate(identifier: string): { allowed: boolean; remainingTime?: number } {
    const now = Date.now();
    const hourInMs = 60 * 60 * 1000;
    const maxSubmissions = 5;

    const existing = this.submissions.get(identifier);

    if (!existing || now > existing.resetTime) {
      this.submissions.set(identifier, {
        count: 1,
        resetTime: now + hourInMs,
      });
      return { allowed: true };
    }

    if (existing.count >= maxSubmissions) {
      return {
        allowed: false,
        remainingTime: Math.ceil((existing.resetTime - now) / 1000),
      };
    }

    existing.count++;
    this.submissions.set(identifier, existing);
    return { allowed: true };
  }

  // Clean up expired entries
  static cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.submissions.entries()) {
      if (now > value.resetTime) {
        this.submissions.delete(key);
      }
    }
  }
}

// Export utilities
export { PATTERNS, DANGEROUS_PATTERNS, XSS_PATTERNS, VALIDATION_CONFIG };

// Export default validation function
export const validate = ValidationMiddleware.validateBody;