/**
 * Security Integration
 * Unified security system for Fynsor Consulting - integrates all security components
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

// Import all security components
import { oauthManager, PKCEService } from '../auth/providers';
import { authService, authMiddleware, createAuthMiddleware } from '../auth/middleware';
import { authGuard, mfaGuard, adminGuard, GuardFactory } from '../auth/guards';
import { totpService, mfaMiddleware } from '../auth/mfa';
import { encryptionService, databaseEncryption, ClientSideEncryption } from './encryption';
import { secureStorage, dataPrivacyManager } from './secure-storage';
import { securityMiddleware, botProtection, ipValidation } from '../middleware/security';
import { InputSanitizer, ValidationMiddleware, SecurityValidation } from './validation';
import { FormSchemas, APISchemas, validateFormData } from '../schemas/input-schemas';
import { honeypotService } from './honeypot';
import { ipValidationService } from './ip-validation';
import { sessionManager, sessionMiddleware } from './session-management';

// Security integration configuration
const SECURITY_CONFIG = {
  enableRateLimit: true,
  enableHoneypot: true,
  enableIPValidation: true,
  enableMFA: true,
  enableEncryption: true,
  enableAuditLogging: true,
  strictMode: process.env.NODE_ENV === 'production',
  debugMode: process.env.SECURITY_DEBUG === 'true',
} as const;

// Security context interface
interface SecurityContext {
  user?: {
    id: string;
    email: string;
    roles: string[];
    mfaVerified: boolean;
  };
  session?: {
    sessionId: string;
    expiresAt: Date;
  };
  request: {
    ip: string;
    userAgent: string;
    method: string;
    path: string;
  };
  security: {
    threats: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    blockedBy?: string[];
  };
}

// Comprehensive security service
export class SecurityService {
  // Process secure form submission
  async processSecureSubmission(
    formData: Record<string, any>,
    formType: keyof typeof FormSchemas,
    request: NextRequest
  ): Promise<{
    success: boolean;
    data?: any;
    errors?: string[];
    securityEvents?: string[];
  }> {
    const errors: string[] = [];
    const securityEvents: string[] = [];

    try {
      // 1. Extract request context
      const context = this.extractRequestContext(request);

      // 2. Security validation
      const securityCheck = await this.performSecurityCheck(context);
      if (!securityCheck.allowed) {
        return {
          success: false,
          errors: securityCheck.reasons,
          securityEvents: ['security_check_failed'],
        };
      }

      // 3. Rate limiting
      if (SECURITY_CONFIG.enableRateLimit) {
        const rateLimitCheck = await this.checkRateLimit(context.request.ip, formType);
        if (!rateLimitCheck.allowed) {
          securityEvents.push('rate_limit_exceeded');
          return {
            success: false,
            errors: ['Rate limit exceeded. Please try again later.'],
            securityEvents,
          };
        }
      }

      // 4. Honeypot validation
      if (SECURITY_CONFIG.enableHoneypot) {
        const honeypotValid = honeypotService.validateHoneypotFields(formData);
        if (!honeypotValid) {
          securityEvents.push('honeypot_triggered');
          // Silently reject (don't inform the bot)
          return {
            success: false,
            errors: ['Submission failed. Please try again.'],
            securityEvents,
          };
        }
      }

      // 5. Input validation and sanitization
      const schema = FormSchemas[formType];
      const validatedData = validateFormData(schema, formData);

      // 6. Security threat analysis
      const threatAnalysis = this.analyzeThreatLevel(validatedData, context);
      securityEvents.push(...threatAnalysis.events);

      if (threatAnalysis.level === 'critical') {
        return {
          success: false,
          errors: ['Security validation failed.'],
          securityEvents,
        };
      }

      // 7. Client-side encryption verification
      if (SECURITY_CONFIG.enableEncryption && formData.encrypted) {
        try {
          const decryptedData = ClientSideEncryption.decryptFormData(formData.encrypted);
          Object.assign(validatedData, decryptedData);
        } catch (error) {
          securityEvents.push('encryption_verification_failed');
          return {
            success: false,
            errors: ['Data integrity verification failed.'],
            securityEvents,
          };
        }
      }

      // 8. Store with encryption
      const userId = context.user?.id || 'anonymous';
      const storageResult = await secureStorage.store(
        'form_submissions',
        {
          formType,
          data: validatedData,
          securityContext: context,
          submittedAt: new Date(),
        },
        userId,
        {
          ipAddress: context.request.ip,
          userAgent: context.request.userAgent,
          metadata: { securityEvents, threatLevel: threatAnalysis.level },
        }
      );

      if (!storageResult.success) {
        return {
          success: false,
          errors: ['Failed to process submission.'],
          securityEvents: [...securityEvents, 'storage_failed'],
        };
      }

      // 9. Send encrypted notification to admin
      await this.sendAdminNotification(formType, validatedData, context);

      securityEvents.push('submission_processed');

      return {
        success: true,
        data: { submissionId: storageResult.id },
        securityEvents,
      };
    } catch (error) {
      console.error('Secure submission processing failed:', error);
      return {
        success: false,
        errors: ['An unexpected error occurred.'],
        securityEvents: [...securityEvents, 'processing_error'],
      };
    }
  }

  // Perform comprehensive security check
  async performSecurityCheck(context: SecurityContext): Promise<{
    allowed: boolean;
    reasons: string[];
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  }> {
    const reasons: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // IP validation
    if (SECURITY_CONFIG.enableIPValidation) {
      const ipCheck = await ipValidationService.validateIP(
        context.request.ip,
        context.request.userAgent,
        { checkGeolocation: true, checkReputation: true }
      );

      if (!ipCheck.allowed) {
        reasons.push(ipCheck.reason || 'IP not allowed');
        riskLevel = ipCheck.threatLevel;
      }
    }

    // User agent analysis
    const botCheck = botProtection.isSuspiciousRequest({
      headers: { get: () => context.request.userAgent },
      method: context.request.method,
    } as NextRequest);

    if (botCheck) {
      reasons.push('Suspicious user agent detected');
      riskLevel = riskLevel === 'low' ? 'medium' : riskLevel;
    }

    // Authentication check for protected resources
    if (context.request.path.startsWith('/admin') || context.request.path.includes('/secure')) {
      if (!context.user) {
        reasons.push('Authentication required');
        riskLevel = 'high';
      } else if (SECURITY_CONFIG.enableMFA && !context.user.mfaVerified) {
        reasons.push('MFA verification required');
        riskLevel = 'medium';
      }
    }

    return {
      allowed: reasons.length === 0,
      reasons,
      riskLevel,
    };
  }

  // Check rate limits
  async checkRateLimit(
    ip: string,
    operation: string
  ): Promise<{ allowed: boolean; remainingTime?: number }> {
    // Implement specific rate limits for different operations
    const limits = {
      'contactForm': { max: 5, window: 60 * 60 * 1000 }, // 5 per hour
      'investmentInquiry': { max: 3, window: 60 * 60 * 1000 }, // 3 per hour
      'businessConsultation': { max: 2, window: 60 * 60 * 1000 }, // 2 per hour
      'newsletter': { max: 10, window: 60 * 60 * 1000 }, // 10 per hour
      default: { max: 20, window: 60 * 60 * 1000 }, // 20 per hour
    };

    const limit = limits[operation as keyof typeof limits] || limits.default;

    // Use rate limiting from validation library
    const { RateLimitValidation } = await import('./validation');
    return RateLimitValidation.validateSubmissionRate(`${ip}:${operation}`);
  }

  // Analyze threat level
  private analyzeThreatLevel(
    data: any,
    context: SecurityContext
  ): { level: 'low' | 'medium' | 'high' | 'critical'; events: string[] } {
    const events: string[] = [];
    let level: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // Check for security threats in data
    const dataString = JSON.stringify(data);

    if (SecurityValidation.containsSQLInjection(dataString)) {
      events.push('sql_injection_detected');
      level = 'critical';
    }

    if (SecurityValidation.containsXSS(dataString)) {
      events.push('xss_detected');
      level = level === 'low' ? 'high' : level;
    }

    if (SecurityValidation.containsCommandInjection(dataString)) {
      events.push('command_injection_detected');
      level = 'critical';
    }

    // Check for suspicious patterns
    if (data.email && data.email.includes('test') && data.email.includes('bot')) {
      events.push('suspicious_email_pattern');
      level = level === 'low' ? 'medium' : level;
    }

    // Investment amount anomalies
    if (data.investmentAmount && data.investmentAmount > 50000000) {
      events.push('unusual_investment_amount');
      level = level === 'low' ? 'medium' : level;
    }

    return { level, events };
  }

  // Extract request context
  private extractRequestContext(request: NextRequest): SecurityContext {
    const ip = this.getClientIP(request);
    const userAgent = request.headers.get('user-agent') || 'unknown';

    return {
      request: {
        ip,
        userAgent,
        method: request.method,
        path: request.nextUrl.pathname,
      },
      security: {
        threats: [],
        riskLevel: 'low',
      },
    };
  }

  // Get client IP
  private getClientIP(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for');
    const realIp = request.headers.get('x-real-ip');

    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }

    return realIp || 'unknown';
  }

  // Send encrypted admin notification
  private async sendAdminNotification(
    formType: string,
    data: any,
    context: SecurityContext
  ): Promise<void> {
    try {
      // Remove sensitive data from notification
      const { email, phone, ...safeData } = data;

      const notification = {
        type: formType,
        timestamp: new Date().toISOString(),
        userAgent: context.request.userAgent,
        ipAddress: context.request.ip,
        hasEmail: !!email,
        hasPhone: !!phone,
        dataFields: Object.keys(data),
        securityLevel: context.security.riskLevel,
      };

      // In production, send to admin via secure channel
      if (SECURITY_CONFIG.debugMode) {
        console.log('Admin Notification:', notification);
      }

      // Store encrypted notification
      await secureStorage.store(
        'admin_notifications',
        notification,
        'system',
        context.request
      );
    } catch (error) {
      console.error('Failed to send admin notification:', error);
    }
  }
}

// Security middleware factory
export function createSecurityMiddleware(options: {
  enableAuth?: boolean;
  requireMFA?: boolean;
  requiredRoles?: string[];
  enableRateLimit?: boolean;
  customValidation?: (context: SecurityContext) => Promise<boolean>;
} = {}) {
  return async (request: NextRequest) => {
    const securityService = new SecurityService();

    // Extract context
    const context = securityService['extractRequestContext'](request);

    // Perform security check
    const securityCheck = await securityService.performSecurityCheck(context);

    if (!securityCheck.allowed) {
      return NextResponse.json(
        {
          error: 'Security Validation Failed',
          message: 'Access denied due to security policy',
          code: 'SECURITY_VIOLATION',
        },
        { status: 403 }
      );
    }

    // Apply guards if needed
    if (options.enableAuth) {
      const guard = GuardFactory.create()
        .auth()
        .mfa()
        .roles(options.requiredRoles || [])
        .build();

      const guardResult = await guard.check(request);
      if (!guardResult.success) {
        return guard['createResponse'](guardResult, request);
      }
    }

    // Apply security headers
    const response = await securityMiddleware.handle(request);

    // Add security context headers
    response.headers.set('X-Security-Level', securityCheck.riskLevel);
    response.headers.set('X-Request-ID', crypto.randomUUID());

    return response;
  };
}

// Security utilities
export const SecurityUtils = {
  // Validate form with full security pipeline
  async validateSecureForm(
    formData: Record<string, any>,
    formType: keyof typeof FormSchemas,
    request: NextRequest
  ) {
    const securityService = new SecurityService();
    return await securityService.processSecureSubmission(formData, formType, request);
  },

  // Generate client-side security components
  generateClientSecurity() {
    return {
      honeypotFields: honeypotService.generateHoneypotFields(),
      encryptionKey: ClientSideEncryption.generateEphemeralKey(),
      formTiming: `
        window.formTiming = {
          startTime: Date.now(),
          keyPresses: 0,
          mouseEvents: 0
        };
      `,
    };
  },

  // Encrypt sensitive data for transmission
  encryptForTransmission(data: Record<string, any>) {
    return ClientSideEncryption.encryptFormData(data);
  },

  // Validate user session
  async validateUserSession(request: NextRequest) {
    return await sessionMiddleware.validateSession(request);
  },

  // Check if operation requires MFA
  requiresMFA(operation: string, user?: any): boolean {
    const mfaRequiredOps = [
      'high-value-investment',
      'admin-access',
      'data-export',
      'account-deletion',
      'security-settings',
    ];

    return mfaRequiredOps.includes(operation) ||
           (user?.roles?.includes('admin') && SECURITY_CONFIG.enableMFA);
  },
};

// Export singleton security service
export const securityService = new SecurityService();

// Export all security components for easy access
export {
  // Authentication
  oauthManager,
  authService,
  authMiddleware,
  totpService,
  mfaMiddleware,

  // Authorization
  authGuard,
  mfaGuard,
  adminGuard,
  GuardFactory,

  // Encryption & Storage
  encryptionService,
  databaseEncryption,
  secureStorage,
  dataPrivacyManager,

  // Security Middleware
  securityMiddleware,
  botProtection,
  ipValidation,

  // Validation
  InputSanitizer,
  ValidationMiddleware,
  SecurityValidation,
  FormSchemas,
  APISchemas,

  // Security Features
  honeypotService,
  ipValidationService,
  sessionManager,

  // Configuration
  SECURITY_CONFIG,
};