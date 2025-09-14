/**
 * Input Validation Schemas
 * Comprehensive Zod schemas for all user inputs in Fynsor Consulting
 */

import { z } from 'zod';
import { InputSanitizer } from '../lib/validation';

// Constants for validation
const LIMITS = {
  name: { min: 1, max: 100 },
  email: { max: 255 },
  phone: { max: 20 },
  message: { min: 10, max: 5000 },
  businessName: { min: 1, max: 200 },
  address: { max: 500 },
  city: { max: 100 },
  state: { max: 50 },
  zipCode: { max: 20 },
  country: { max: 100 },
  website: { max: 255 },
  linkedIn: { max: 255 },
  title: { max: 100 },
  company: { max: 200 },
  industry: { max: 100 },
  experience: { max: 2000 },
  objectives: { max: 2000 },
  challenges: { max: 2000 },
  timeline: { max: 200 },
  budget: { min: 1000, max: 100000000 },
} as const;

// Investment amounts (in USD)
const INVESTMENT_LIMITS = {
  min: 1000,
  max: 100000000,
  accreditedMin: 25000,
} as const;

// Base validation schemas
const BaseSchemas = {
  // Personal information
  firstName: z.string()
    .min(LIMITS.name.min, 'First name is required')
    .max(LIMITS.name.max, 'First name too long')
    .regex(/^[a-zA-Z\s\-\.\']{1,100}$/, 'Invalid first name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.name.max })),

  lastName: z.string()
    .min(LIMITS.name.min, 'Last name is required')
    .max(LIMITS.name.max, 'Last name too long')
    .regex(/^[a-zA-Z\s\-\.\']{1,100}$/, 'Invalid last name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.name.max })),

  email: z.string()
    .email('Invalid email format')
    .max(LIMITS.email.max, 'Email too long')
    .transform(InputSanitizer.sanitizeEmail),

  phone: z.string()
    .max(LIMITS.phone.max, 'Phone number too long')
    .regex(/^\+?[\d\s\-\(\)\.]{10,20}$/, 'Invalid phone number format')
    .transform(InputSanitizer.sanitizePhone)
    .optional(),

  // Business information
  company: z.string()
    .max(LIMITS.company.max, 'Company name too long')
    .regex(/^[a-zA-Z0-9\s\-\.\'&,]{1,200}$/, 'Invalid company name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.company.max }))
    .optional(),

  title: z.string()
    .max(LIMITS.title.max, 'Title too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.title.max }))
    .optional(),

  industry: z.enum([
    'technology', 'healthcare', 'finance', 'real-estate', 'manufacturing',
    'retail', 'education', 'energy', 'agriculture', 'transportation',
    'hospitality', 'media', 'telecommunications', 'consulting', 'other'
  ]).optional(),

  // Contact information
  website: z.string()
    .url('Invalid website URL')
    .max(LIMITS.website.max, 'Website URL too long')
    .transform(InputSanitizer.sanitizeUrl)
    .optional(),

  linkedIn: z.string()
    .url('Invalid LinkedIn URL')
    .max(LIMITS.linkedIn.max, 'LinkedIn URL too long')
    .refine(url => url.includes('linkedin.com'), 'Must be a LinkedIn URL')
    .transform(InputSanitizer.sanitizeUrl)
    .optional(),

  // Address fields
  address: z.string()
    .max(LIMITS.address.max, 'Address too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.address.max }))
    .optional(),

  city: z.string()
    .max(LIMITS.city.max, 'City name too long')
    .regex(/^[a-zA-Z\s\-\.\']{1,100}$/, 'Invalid city name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.city.max }))
    .optional(),

  state: z.string()
    .max(LIMITS.state.max, 'State name too long')
    .regex(/^[a-zA-Z\s\-\.\']{1,50}$/, 'Invalid state name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.state.max }))
    .optional(),

  zipCode: z.string()
    .max(LIMITS.zipCode.max, 'ZIP code too long')
    .regex(/^[a-zA-Z0-9\s\-]{1,20}$/, 'Invalid ZIP code format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.zipCode.max }))
    .optional(),

  country: z.string()
    .max(LIMITS.country.max, 'Country name too long')
    .regex(/^[a-zA-Z\s\-\.\']{1,100}$/, 'Invalid country name format')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.country.max }))
    .default('United States'),

  // Messages and descriptions
  message: z.string()
    .min(LIMITS.message.min, `Message must be at least ${LIMITS.message.min} characters`)
    .max(LIMITS.message.max, `Message must be no more than ${LIMITS.message.max} characters`)
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.message.max })),

  experience: z.string()
    .max(LIMITS.experience.max, 'Experience description too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.experience.max }))
    .optional(),

  objectives: z.string()
    .max(LIMITS.objectives.max, 'Objectives description too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.objectives.max }))
    .optional(),

  challenges: z.string()
    .max(LIMITS.challenges.max, 'Challenges description too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.challenges.max }))
    .optional(),

  timeline: z.string()
    .max(LIMITS.timeline.max, 'Timeline description too long')
    .transform(val => InputSanitizer.sanitizeString(val, { maxLength: LIMITS.timeline.max }))
    .optional(),

  // Investment-specific fields
  investmentAmount: z.number()
    .min(INVESTMENT_LIMITS.min, `Minimum investment is $${INVESTMENT_LIMITS.min.toLocaleString()}`)
    .max(INVESTMENT_LIMITS.max, `Maximum investment is $${INVESTMENT_LIMITS.max.toLocaleString()}`)
    .positive('Investment amount must be positive'),

  investmentType: z.enum([
    'equity', 'debt', 'convertible', 'revenue-share', 'real-estate',
    'private-equity', 'venture-capital', 'hedge-fund', 'mutual-fund', 'other'
  ]),

  riskTolerance: z.enum(['conservative', 'moderate', 'aggressive']),

  timeHorizon: z.enum(['short-term', 'medium-term', 'long-term']),

  accreditedInvestor: z.boolean(),

  // Honeypot fields (should always be empty)
  honeypot_website: z.string().max(0, 'Honeypot field should be empty').optional(),
  honeypot_company: z.string().max(0, 'Honeypot field should be empty').optional(),
  honeypot_email: z.string().max(0, 'Honeypot field should be empty').optional(),
  honeypot_phone: z.string().max(0, 'Honeypot field should be empty').optional(),
};

// Form schemas
export const FormSchemas = {
  // General contact form
  contactForm: z.object({
    firstName: BaseSchemas.firstName,
    lastName: BaseSchemas.lastName,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,
    company: BaseSchemas.company,
    title: BaseSchemas.title,
    website: BaseSchemas.website,
    message: BaseSchemas.message,
    // Honeypot fields
    honeypot_website: BaseSchemas.honeypot_website,
    honeypot_company: BaseSchemas.honeypot_company,
    honeypot_email: BaseSchemas.honeypot_email,
  }),

  // Investment inquiry form
  investmentInquiry: z.object({
    // Personal information
    firstName: BaseSchemas.firstName,
    lastName: BaseSchemas.lastName,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,

    // Investment details
    investmentAmount: BaseSchemas.investmentAmount,
    investmentType: BaseSchemas.investmentType,
    riskTolerance: BaseSchemas.riskTolerance,
    timeHorizon: BaseSchemas.timeHorizon,
    accreditedInvestor: BaseSchemas.accreditedInvestor,

    // Additional information
    experience: BaseSchemas.experience,
    objectives: BaseSchemas.objectives,

    // Honeypot fields
    honeypot_website: BaseSchemas.honeypot_website,
    honeypot_company: BaseSchemas.honeypot_company,
    honeypot_email: BaseSchemas.honeypot_email,
  }).refine(
    data => !data.accreditedInvestor || data.investmentAmount >= INVESTMENT_LIMITS.accreditedMin,
    {
      message: `Accredited investors must invest at least $${INVESTMENT_LIMITS.accreditedMin.toLocaleString()}`,
      path: ['investmentAmount'],
    }
  ),

  // Business consultation form
  businessConsultation: z.object({
    // Contact information
    firstName: BaseSchemas.firstName,
    lastName: BaseSchemas.lastName,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,

    // Business information
    company: BaseSchemas.company.required('Company name is required'),
    title: BaseSchemas.title.required('Job title is required'),
    industry: BaseSchemas.industry.required('Industry is required'),
    website: BaseSchemas.website,

    // Consultation details
    challenges: BaseSchemas.challenges.required('Please describe your business challenges'),
    objectives: BaseSchemas.objectives.required('Please describe your objectives'),
    timeline: BaseSchemas.timeline,
    budget: z.number()
      .min(LIMITS.budget.min, 'Minimum budget is $1,000')
      .max(LIMITS.budget.max, 'Maximum budget is $100,000,000')
      .optional(),

    // Honeypot fields
    honeypot_website: BaseSchemas.honeypot_website,
    honeypot_company: BaseSchemas.honeypot_company,
    honeypot_email: BaseSchemas.honeypot_email,
  }),

  // Newsletter subscription
  newsletter: z.object({
    email: BaseSchemas.email,
    firstName: BaseSchemas.firstName.optional(),
    lastName: BaseSchemas.lastName.optional(),
    interests: z.array(z.enum([
      'investment-opportunities',
      'market-insights',
      'business-strategy',
      'financial-planning',
      'industry-news'
    ])).min(1, 'Please select at least one interest').max(5, 'Too many interests selected'),
    // Honeypot field
    honeypot_email: BaseSchemas.honeypot_email,
  }),

  // Document upload form
  documentUpload: z.object({
    title: z.string()
      .min(1, 'Document title is required')
      .max(200, 'Document title too long')
      .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 200 })),

    description: z.string()
      .max(1000, 'Description too long')
      .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 1000 }))
      .optional(),

    category: z.enum([
      'financial-statements',
      'business-plan',
      'legal-documents',
      'investment-proposal',
      'market-research',
      'other'
    ]),

    confidential: z.boolean().default(true),
  }),

  // Meeting request form
  meetingRequest: z.object({
    // Contact information
    firstName: BaseSchemas.firstName,
    lastName: BaseSchemas.lastName,
    email: BaseSchemas.email,
    phone: BaseSchemas.phone,
    company: BaseSchemas.company,
    title: BaseSchemas.title,

    // Meeting details
    meetingType: z.enum([
      'initial-consultation',
      'investment-discussion',
      'business-strategy',
      'follow-up',
      'other'
    ]),

    preferredDate: z.string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'Invalid date format (YYYY-MM-DD)')
      .refine(date => new Date(date) > new Date(), 'Date must be in the future'),

    preferredTime: z.enum([
      'morning', 'afternoon', 'evening', 'flexible'
    ]),

    duration: z.enum(['30-minutes', '1-hour', '2-hours', 'half-day']),

    format: z.enum(['in-person', 'video-call', 'phone-call']),

    agenda: BaseSchemas.message,

    // Honeypot fields
    honeypot_website: BaseSchemas.honeypot_website,
    honeypot_company: BaseSchemas.honeypot_company,
    honeypot_email: BaseSchemas.honeypot_email,
  }),
};

// API request schemas
export const APISchemas = {
  // Authentication
  login: z.object({
    email: BaseSchemas.email,
    password: z.string().min(8, 'Password must be at least 8 characters'),
    rememberMe: z.boolean().optional(),
  }),

  register: z.object({
    firstName: BaseSchemas.firstName,
    lastName: BaseSchemas.lastName,
    email: BaseSchemas.email,
    password: z.string()
      .min(12, 'Password must be at least 12 characters')
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
             'Password must contain uppercase, lowercase, number, and special character'),
    confirmPassword: z.string(),
    acceptTerms: z.boolean().refine(val => val === true, 'Must accept terms and conditions'),
  }).refine(data => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  }),

  // Password reset
  passwordReset: z.object({
    email: BaseSchemas.email,
  }),

  passwordResetConfirm: z.object({
    token: z.string().min(1, 'Reset token is required'),
    password: z.string()
      .min(12, 'Password must be at least 12 characters')
      .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
             'Password must contain uppercase, lowercase, number, and special character'),
    confirmPassword: z.string(),
  }).refine(data => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  }),

  // MFA
  mfaSetup: z.object({
    verificationCode: z.string()
      .length(6, 'Verification code must be 6 digits')
      .regex(/^\d{6}$/, 'Verification code must contain only digits'),
  }),

  mfaVerify: z.object({
    code: z.string()
      .length(6, 'MFA code must be 6 digits')
      .regex(/^\d{6}$/, 'MFA code must contain only digits'),
  }),

  // Search and filtering
  search: z.object({
    query: z.string()
      .min(1, 'Search query is required')
      .max(100, 'Search query too long')
      .transform(val => InputSanitizer.sanitizeString(val, { maxLength: 100 })),

    filters: z.object({
      category: z.string().optional(),
      dateRange: z.object({
        start: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
        end: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
      }).optional(),
      sortBy: z.enum(['date', 'relevance', 'title']).optional(),
      sortOrder: z.enum(['asc', 'desc']).optional(),
    }).optional(),

    pagination: z.object({
      page: z.number().min(1).max(1000),
      limit: z.number().min(1).max(100),
    }).optional(),
  }),
};

// Utility functions for schema validation
export const validateFormData = <T>(schema: z.ZodSchema<T>, data: unknown): T => {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
      }));
      throw new Error(`Validation failed: ${JSON.stringify(formattedErrors)}`);
    }
    throw error;
  }
};

export const getValidationErrors = (error: z.ZodError): Record<string, string> => {
  const errors: Record<string, string> = {};
  error.errors.forEach(err => {
    const field = err.path.join('.');
    errors[field] = err.message;
  });
  return errors;
};

// Export all schemas
export default {
  BaseSchemas,
  FormSchemas,
  APISchemas,
  validateFormData,
  getValidationErrors,
};