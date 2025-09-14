import { NextResponse } from 'next/server'
import { AuditService } from './supabase/client'

// Custom error classes
export class ApiError extends Error {
  public readonly statusCode: number
  public readonly code: string
  public readonly details?: any
  public readonly isOperational: boolean

  constructor(
    message: string,
    statusCode: number = 500,
    code: string = 'INTERNAL_ERROR',
    details?: any,
    isOperational: boolean = true
  ) {
    super(message)
    this.name = 'ApiError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
    this.isOperational = isOperational

    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiError)
    }
  }
}

export class ValidationError extends ApiError {
  constructor(message: string, details?: any) {
    super(message, 400, 'VALIDATION_ERROR', details)
    this.name = 'ValidationError'
  }
}

export class AuthenticationError extends ApiError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR')
    this.name = 'AuthenticationError'
  }
}

export class AuthorizationError extends ApiError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR')
    this.name = 'AuthorizationError'
  }
}

export class NotFoundError extends ApiError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 404, 'NOT_FOUND')
    this.name = 'NotFoundError'
  }
}

export class ConflictError extends ApiError {
  constructor(message: string = 'Resource conflict') {
    super(message, 409, 'CONFLICT')
    this.name = 'ConflictError'
  }
}

export class RateLimitError extends ApiError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_EXCEEDED')
    this.name = 'RateLimitError'
  }
}

export class DatabaseError extends ApiError {
  constructor(message: string = 'Database operation failed', details?: any) {
    super(message, 500, 'DATABASE_ERROR', details, false)
    this.name = 'DatabaseError'
  }
}

export class ExternalServiceError extends ApiError {
  constructor(service: string, message: string = 'External service error') {
    super(`${service}: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR')
    this.name = 'ExternalServiceError'
  }
}

export class SecurityError extends ApiError {
  constructor(message: string = 'Security violation detected') {
    super(message, 403, 'SECURITY_ERROR')
    this.name = 'SecurityError'
  }
}

// Error response interface
export interface ErrorResponse {
  success: false
  error: string
  code: string
  message: string
  details?: any
  timestamp: string
  requestId?: string
  stack?: string
}

// Error context interface
export interface ErrorContext {
  ipAddress?: string
  userAgent?: string
  requestId?: string
  userId?: string
  userEmail?: string
  endpoint?: string
  method?: string
  processingTime?: number
  additionalData?: Record<string, any>
}

// Error logging service
export class ErrorLogger {
  private static instance: ErrorLogger
  private isDevelopment: boolean

  private constructor() {
    this.isDevelopment = process.env.NODE_ENV === 'development'
  }

  static getInstance(): ErrorLogger {
    if (!ErrorLogger.instance) {
      ErrorLogger.instance = new ErrorLogger()
    }
    return ErrorLogger.instance
  }

  async logError(
    error: Error,
    context: ErrorContext = {},
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): Promise<void> {
    const errorData = {
      name: error.name,
      message: error.message,
      stack: error.stack,
      ...context,
      severity,
      timestamp: new Date().toISOString()
    }

    // Console logging for development
    if (this.isDevelopment) {
      console.error('Error occurred:', errorData)
    }

    // Log to audit system
    try {
      await AuditService.logEvent({
        action: 'error_occurred',
        userId: context.userId,
        userEmail: context.userEmail,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        requestId: context.requestId,
        resourceType: 'error',
        riskScore: this.calculateRiskScore(error, severity),
        metadata: {
          errorName: error.name,
          errorCode: error instanceof ApiError ? error.code : 'UNKNOWN',
          severity,
          endpoint: context.endpoint,
          method: context.method,
          processingTime: context.processingTime,
          ...context.additionalData
        }
      })
    } catch (auditError) {
      console.error('Failed to log error to audit system:', auditError)
    }

    // Send to external error tracking service (e.g., Sentry)
    if (process.env.SENTRY_DSN && severity !== 'low') {
      try {
        // This would integrate with Sentry or similar service
        await this.sendToExternalService(errorData)
      } catch (externalError) {
        console.error('Failed to send error to external service:', externalError)
      }
    }

    // Send critical errors to admin notification
    if (severity === 'critical' && process.env.CRITICAL_ERROR_WEBHOOK) {
      try {
        await this.sendCriticalErrorNotification(errorData)
      } catch (notificationError) {
        console.error('Failed to send critical error notification:', notificationError)
      }
    }
  }

  private calculateRiskScore(error: Error, severity: string): number {
    let score = 0

    // Base score by severity
    switch (severity) {
      case 'low': score = 10; break
      case 'medium': score = 25; break
      case 'high': score = 50; break
      case 'critical': score = 90; break
    }

    // Adjust based on error type
    if (error instanceof SecurityError) {
      score += 30
    } else if (error instanceof AuthenticationError) {
      score += 20
    } else if (error instanceof DatabaseError) {
      score += 15
    } else if (!error instanceof ApiError) {
      score += 10 // Unknown errors are riskier
    }

    return Math.min(100, score)
  }

  private async sendToExternalService(errorData: any): Promise<void> {
    // Implementation would depend on the chosen service (Sentry, LogRocket, etc.)
    console.log('Would send to external error tracking:', errorData.message)
  }

  private async sendCriticalErrorNotification(errorData: any): Promise<void> {
    if (!process.env.CRITICAL_ERROR_WEBHOOK) return

    try {
      await fetch(process.env.CRITICAL_ERROR_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: '🚨 Critical Error Alert',
          attachments: [{
            color: 'danger',
            title: 'Critical Error Occurred',
            fields: [
              { title: 'Error', value: errorData.name, short: true },
              { title: 'Message', value: errorData.message, short: false },
              { title: 'Timestamp', value: errorData.timestamp, short: true },
              { title: 'Request ID', value: errorData.requestId || 'N/A', short: true },
              { title: 'User', value: errorData.userEmail || 'Anonymous', short: true },
              { title: 'Endpoint', value: errorData.endpoint || 'Unknown', short: true }
            ]
          }]
        })
      })
    } catch (error) {
      console.error('Failed to send webhook notification:', error)
    }
  }
}

// Main error handler function
export async function handleApiError(
  error: unknown,
  context: ErrorContext = {}
): Promise<NextResponse> {
  const logger = ErrorLogger.getInstance()
  const isDevelopment = process.env.NODE_ENV === 'development'

  let apiError: ApiError

  // Convert unknown errors to ApiError
  if (error instanceof ApiError) {
    apiError = error
  } else if (error instanceof Error) {
    // Handle specific error types
    if (error.message.includes('validation') || error.message.includes('invalid')) {
      apiError = new ValidationError(error.message)
    } else if (error.message.includes('unauthorized') || error.message.includes('authentication')) {
      apiError = new AuthenticationError(error.message)
    } else if (error.message.includes('forbidden') || error.message.includes('permission')) {
      apiError = new AuthorizationError(error.message)
    } else if (error.message.includes('not found')) {
      apiError = new NotFoundError()
    } else if (error.message.includes('rate limit')) {
      apiError = new RateLimitError(error.message)
    } else {
      apiError = new ApiError(
        'An unexpected error occurred',
        500,
        'INTERNAL_ERROR',
        isDevelopment ? error.message : undefined,
        false
      )
    }
  } else {
    apiError = new ApiError(
      'An unexpected error occurred',
      500,
      'UNKNOWN_ERROR',
      undefined,
      false
    )
  }

  // Determine severity
  let severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  if (apiError.statusCode >= 500) {
    severity = apiError.isOperational ? 'high' : 'critical'
  } else if (apiError.statusCode >= 400) {
    severity = 'low'
  }

  // Log the error
  await logger.logError(
    apiError,
    {
      ...context,
      endpoint: context.endpoint,
      method: context.method
    },
    severity
  )

  // Create error response
  const errorResponse: ErrorResponse = {
    success: false,
    error: apiError.message,
    code: apiError.code,
    message: getClientSafeMessage(apiError),
    timestamp: new Date().toISOString(),
    requestId: context.requestId
  }

  // Include details and stack in development
  if (isDevelopment) {
    errorResponse.details = apiError.details
    errorResponse.stack = apiError.stack
  }

  // Set appropriate headers
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  }

  if (context.requestId) {
    headers['X-Request-ID'] = context.requestId
  }

  if (context.processingTime) {
    headers['X-Processing-Time'] = `${context.processingTime}ms`
  }

  // Add security headers for certain errors
  if (apiError instanceof SecurityError) {
    headers['X-Content-Type-Options'] = 'nosniff'
    headers['X-Frame-Options'] = 'DENY'
  }

  if (apiError instanceof RateLimitError) {
    headers['Retry-After'] = '3600' // 1 hour
  }

  return NextResponse.json(errorResponse, {
    status: apiError.statusCode,
    headers
  })
}

// Get client-safe error message
function getClientSafeMessage(error: ApiError): string {
  // Don't expose internal error details to clients in production
  if (process.env.NODE_ENV === 'production' && !error.isOperational) {
    return 'An internal server error occurred'
  }

  // Map specific error codes to user-friendly messages
  const messageMap: Record<string, string> = {
    'VALIDATION_ERROR': 'The provided data is invalid. Please check your input and try again.',
    'AUTHENTICATION_ERROR': 'Authentication is required to access this resource.',
    'AUTHORIZATION_ERROR': 'You do not have permission to access this resource.',
    'NOT_FOUND': 'The requested resource was not found.',
    'CONFLICT': 'The operation conflicts with the current state of the resource.',
    'RATE_LIMIT_EXCEEDED': 'Too many requests. Please wait before trying again.',
    'DATABASE_ERROR': 'A database error occurred. Please try again later.',
    'EXTERNAL_SERVICE_ERROR': 'An external service is temporarily unavailable.',
    'SECURITY_ERROR': 'A security violation was detected.',
    'INTERNAL_ERROR': 'An internal server error occurred.',
    'UNKNOWN_ERROR': 'An unexpected error occurred.'
  }

  return messageMap[error.code] || error.message
}

// Error boundary for catching unhandled errors
export class GlobalErrorHandler {
  static setup(): void {
    // Handle unhandled promise rejections
    process.on('unhandledRejection', async (reason: any, promise: Promise<any>) => {
      const logger = ErrorLogger.getInstance()
      const error = reason instanceof Error ? reason : new Error(String(reason))

      await logger.logError(
        error,
        {
          additionalData: {
            type: 'unhandledRejection',
            promise: promise.toString()
          }
        },
        'critical'
      )

      // In production, you might want to gracefully shut down
      if (process.env.NODE_ENV === 'production') {
        console.error('Unhandled promise rejection - shutting down gracefully')
        setTimeout(() => process.exit(1), 1000)
      }
    })

    // Handle uncaught exceptions
    process.on('uncaughtException', async (error: Error) => {
      const logger = ErrorLogger.getInstance()

      await logger.logError(
        error,
        {
          additionalData: {
            type: 'uncaughtException'
          }
        },
        'critical'
      )

      // Always shut down on uncaught exceptions
      console.error('Uncaught exception - shutting down')
      process.exit(1)
    })
  }
}

// Utility functions
export function isOperationalError(error: Error): boolean {
  if (error instanceof ApiError) {
    return error.isOperational
  }
  return false
}

export function createError(
  message: string,
  statusCode: number = 500,
  code: string = 'INTERNAL_ERROR',
  details?: any
): ApiError {
  return new ApiError(message, statusCode, code, details)
}

// Export default error handling configuration
export default {
  ApiError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  SecurityError,
  ErrorLogger,
  handleApiError,
  GlobalErrorHandler,
  isOperationalError,
  createError
}