/**
 * Honeypot Bot Protection
 * Advanced bot detection and prevention for Fynsor Consulting forms
 */

import { z } from 'zod';
import crypto from 'crypto';

// Honeypot configuration
const HONEYPOT_CONFIG = {
  fields: [
    'website', // Classic honeypot field
    'company_name_hidden', // Hidden company field
    'email_verify', // Email verification field
    'phone_secondary', // Secondary phone field
    'address_line_3', // Third address line
    'fax_number', // Outdated fax field
    'url', // URL field
    'homepage', // Homepage field
  ],
  timeThreshold: 3000, // Minimum time to fill form (3 seconds)
  maxTimeThreshold: 3600000, // Maximum reasonable time (1 hour)
  keyPressThreshold: 10, // Minimum keypresses expected
  mouseMovementThreshold: 5, // Minimum mouse movements
} as const;

// Bot behavior patterns
const BOT_PATTERNS = {
  userAgents: [
    /bot|crawler|spider|scraper/i,
    /curl|wget|python|requests/i,
    /postman|insomnia|httpie/i,
    /automated|automation/i,
    /selenium|playwright|puppeteer/i,
    /phantom|headless/i,
  ],
  suspiciousHeaders: [
    'x-requested-with',
    'x-forwarded-for',
    'x-real-ip',
    'x-original-forwarded-for',
  ],
  rapidSubmission: 1000, // Less than 1 second
  identicalSubmissions: 5, // Same data submitted multiple times
} as const;

// Honeypot field schema
const HoneypotFieldSchema = z.object({
  name: z.string(),
  value: z.string(),
  type: z.enum(['text', 'email', 'tel', 'url', 'hidden']),
  label: z.string(),
  placeholder: z.string().optional(),
  required: z.boolean().default(false),
});

export type HoneypotField = z.infer<typeof HoneypotFieldSchema>;

// Form timing schema
const FormTimingSchema = z.object({
  startTime: z.number(),
  endTime: z.number(),
  keyPresses: z.number().default(0),
  mouseMovements: z.number().default(0),
  focusEvents: z.number().default(0),
  pasteEvents: z.number().default(0),
});

export type FormTiming = z.infer<typeof FormTimingSchema>;

// Submission analysis result
interface BotAnalysisResult {
  isBot: boolean;
  confidence: number; // 0-1 scale
  reasons: string[];
  honeypotTriggered: boolean;
  timingAnalysis: {
    tooFast: boolean;
    tooSlow: boolean;
    suspiciousPatterns: string[];
  };
  behaviorAnalysis: {
    suspiciousUserAgent: boolean;
    missingHeaders: string[];
    rapidSubmissions: boolean;
  };
}

// Honeypot service
export class HoneypotService {
  private submissionHistory = new Map<string, { count: number; lastSubmission: number; data: string[] }>();

  // Generate honeypot fields for forms
  generateHoneypotFields(): HoneypotField[] {
    return [
      {
        name: 'website',
        value: '',
        type: 'url',
        label: 'Website (leave blank)',
        placeholder: 'https://example.com',
        required: false,
      },
      {
        name: 'company_name_hidden',
        value: '',
        type: 'text',
        label: 'Company Name',
        placeholder: 'Your company name',
        required: false,
      },
      {
        name: 'email_verify',
        value: '',
        type: 'email',
        label: 'Email Verification',
        placeholder: 'verify@example.com',
        required: false,
      },
      {
        name: 'phone_secondary',
        value: '',
        type: 'tel',
        label: 'Secondary Phone',
        placeholder: '+1 (555) 123-4567',
        required: false,
      },
      {
        name: 'fax_number',
        value: '',
        type: 'tel',
        label: 'Fax Number',
        placeholder: '+1 (555) 123-4567',
        required: false,
      },
    ];
  }

  // Validate honeypot fields
  validateHoneypotFields(formData: Record<string, any>): boolean {
    const honeypotFields = HONEYPOT_CONFIG.fields;

    // Check if any honeypot field has been filled
    for (const field of honeypotFields) {
      const value = formData[field];
      if (value && typeof value === 'string' && value.trim() !== '') {
        console.warn(`Honeypot field '${field}' was filled with value: '${value}'`);
        return false;
      }
    }

    return true;
  }

  // Analyze form timing for bot behavior
  analyzeFormTiming(timing: FormTiming): { isBot: boolean; reasons: string[] } {
    const reasons: string[] = [];
    const fillTime = timing.endTime - timing.startTime;

    // Too fast (likely bot)
    if (fillTime < HONEYPOT_CONFIG.timeThreshold) {
      reasons.push(`Form filled too quickly: ${fillTime}ms`);
    }

    // Too slow (might be bot or abandoned session)
    if (fillTime > HONEYPOT_CONFIG.maxTimeThreshold) {
      reasons.push(`Form filled too slowly: ${fillTime}ms`);
    }

    // Insufficient interaction
    if (timing.keyPresses < HONEYPOT_CONFIG.keyPressThreshold) {
      reasons.push(`Insufficient key presses: ${timing.keyPresses}`);
    }

    if (timing.mouseMovements < HONEYPOT_CONFIG.mouseMovementThreshold) {
      reasons.push(`Insufficient mouse movements: ${timing.mouseMovements}`);
    }

    // Suspicious paste behavior
    if (timing.pasteEvents > timing.focusEvents) {
      reasons.push(`Excessive paste events: ${timing.pasteEvents}`);
    }

    // No focus events (form never focused)
    if (timing.focusEvents === 0) {
      reasons.push('No focus events detected');
    }

    return {
      isBot: reasons.length > 0,
      reasons,
    };
  }

  // Analyze user agent and headers
  analyzeUserAgent(userAgent: string, headers: Record<string, string>): {
    isBot: boolean;
    reasons: string[];
  } {
    const reasons: string[] = [];

    // Check user agent patterns
    for (const pattern of BOT_PATTERNS.userAgents) {
      if (pattern.test(userAgent)) {
        reasons.push(`Suspicious user agent: ${userAgent}`);
        break;
      }
    }

    // Check for missing common headers
    const commonHeaders = ['accept', 'accept-language', 'accept-encoding'];
    for (const header of commonHeaders) {
      if (!headers[header]) {
        reasons.push(`Missing common header: ${header}`);
      }
    }

    // Check for automation-specific headers
    const automationHeaders = ['x-requested-with', 'x-automation'];
    for (const header of automationHeaders) {
      if (headers[header]) {
        reasons.push(`Automation header detected: ${header}`);
      }
    }

    return {
      isBot: reasons.length > 0,
      reasons,
    };
  }

  // Track and analyze submission patterns
  analyzeSubmissionPattern(
    identifier: string,
    formData: Record<string, any>
  ): { isBot: boolean; reasons: string[] } {
    const reasons: string[] = [];
    const now = Date.now();
    const dataHash = this.hashFormData(formData);

    const existing = this.submissionHistory.get(identifier);

    if (existing) {
      // Check for rapid submissions
      if (now - existing.lastSubmission < BOT_PATTERNS.rapidSubmission) {
        reasons.push(`Rapid submission detected: ${now - existing.lastSubmission}ms`);
      }

      // Check for identical submissions
      if (existing.data.includes(dataHash)) {
        reasons.push('Identical submission detected');
      }

      // Update history
      existing.count++;
      existing.lastSubmission = now;
      existing.data.push(dataHash);

      // Keep only recent submissions
      if (existing.data.length > 10) {
        existing.data = existing.data.slice(-10);
      }
    } else {
      // First submission from this identifier
      this.submissionHistory.set(identifier, {
        count: 1,
        lastSubmission: now,
        data: [dataHash],
      });
    }

    return {
      isBot: reasons.length > 0,
      reasons,
    };
  }

  // Comprehensive bot analysis
  analyzeBotBehavior(
    userAgent: string,
    headers: Record<string, string>,
    formData: Record<string, any>,
    timing: FormTiming,
    clientIp: string
  ): BotAnalysisResult {
    const honeypotValid = this.validateHoneypotFields(formData);
    const timingAnalysis = this.analyzeFormTiming(timing);
    const userAgentAnalysis = this.analyzeUserAgent(userAgent, headers);
    const patternAnalysis = this.analyzeSubmissionPattern(clientIp, formData);

    const allReasons = [
      ...timingAnalysis.reasons,
      ...userAgentAnalysis.reasons,
      ...patternAnalysis.reasons,
    ];

    if (!honeypotValid) {
      allReasons.push('Honeypot fields were filled');
    }

    // Calculate confidence score
    let confidence = 0;
    if (!honeypotValid) confidence += 0.8; // High confidence for honeypot
    if (timingAnalysis.reasons.length > 0) confidence += 0.3;
    if (userAgentAnalysis.reasons.length > 0) confidence += 0.4;
    if (patternAnalysis.reasons.length > 0) confidence += 0.5;

    confidence = Math.min(confidence, 1.0);

    return {
      isBot: allReasons.length > 0,
      confidence,
      reasons: allReasons,
      honeypotTriggered: !honeypotValid,
      timingAnalysis: {
        tooFast: timing.endTime - timing.startTime < HONEYPOT_CONFIG.timeThreshold,
        tooSlow: timing.endTime - timing.startTime > HONEYPOT_CONFIG.maxTimeThreshold,
        suspiciousPatterns: timingAnalysis.reasons,
      },
      behaviorAnalysis: {
        suspiciousUserAgent: userAgentAnalysis.reasons.length > 0,
        missingHeaders: userAgentAnalysis.reasons.filter(r => r.includes('Missing')),
        rapidSubmissions: patternAnalysis.reasons.some(r => r.includes('Rapid')),
      },
    };
  }

  // Generate challenge for suspicious requests
  generateChallenge(): {
    question: string;
    answer: string;
    token: string;
  } {
    const challenges = [
      {
        question: 'What is 5 + 3?',
        answer: '8',
      },
      {
        question: 'What color is the sky on a clear day?',
        answer: 'blue',
      },
      {
        question: 'How many days are in a week?',
        answer: '7',
      },
      {
        question: 'What is the capital of the United States?',
        answer: 'washington',
      },
      {
        question: 'What comes after Monday?',
        answer: 'tuesday',
      },
    ];

    const challenge = challenges[Math.floor(Math.random() * challenges.length)];
    const token = crypto.randomBytes(16).toString('hex');

    // Store challenge-answer pair temporarily (in production, use Redis)
    global.challengeStore = global.challengeStore || new Map();
    global.challengeStore.set(token, {
      answer: challenge.answer.toLowerCase(),
      expires: Date.now() + 300000, // 5 minutes
    });

    return {
      question: challenge.question,
      answer: challenge.answer,
      token,
    };
  }

  // Verify challenge response
  verifyChallenge(token: string, answer: string): boolean {
    global.challengeStore = global.challengeStore || new Map();
    const stored = global.challengeStore.get(token);

    if (!stored || Date.now() > stored.expires) {
      global.challengeStore.delete(token);
      return false;
    }

    const isValid = stored.answer === answer.toLowerCase().trim();
    global.challengeStore.delete(token); // Use challenge only once

    return isValid;
  }

  // Clean up old entries
  cleanup(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [key, value] of this.submissionHistory.entries()) {
      if (now - value.lastSubmission > maxAge) {
        this.submissionHistory.delete(key);
      }
    }

    // Clean up challenge store
    global.challengeStore = global.challengeStore || new Map();
    for (const [token, challenge] of global.challengeStore.entries()) {
      if (now > challenge.expires) {
        global.challengeStore.delete(token);
      }
    }
  }

  // Hash form data for duplicate detection
  private hashFormData(formData: Record<string, any>): string {
    // Remove honeypot fields and timing data for hashing
    const cleanData = { ...formData };
    HONEYPOT_CONFIG.fields.forEach(field => delete cleanData[field]);
    delete cleanData.timing;
    delete cleanData.challenge;

    const serialized = JSON.stringify(cleanData, Object.keys(cleanData).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }
}

// React component for client-side honeypot fields
export const generateHoneypotFieldsHTML = (): string => {
  const fields = new HoneypotService().generateHoneypotFields();

  return fields.map(field => `
    <div style="position: absolute; left: -9999px; top: -9999px; visibility: hidden;">
      <label for="${field.name}">${field.label}</label>
      <input
        type="${field.type}"
        id="${field.name}"
        name="${field.name}"
        value="${field.value}"
        placeholder="${field.placeholder || ''}"
        tabindex="-1"
        autocomplete="off"
        ${field.required ? 'required' : ''}
      />
    </div>
  `).join('');
};

// Client-side timing tracker
export const generateTimingScript = (): string => {
  return `
    (function() {
      let formTiming = {
        startTime: Date.now(),
        endTime: 0,
        keyPresses: 0,
        mouseMovements: 0,
        focusEvents: 0,
        pasteEvents: 0
      };

      // Track form interactions
      document.addEventListener('keydown', () => formTiming.keyPresses++);
      document.addEventListener('mousemove', () => formTiming.mouseMovements++);
      document.addEventListener('focus', () => formTiming.focusEvents++);
      document.addEventListener('paste', () => formTiming.pasteEvents++);

      // Attach timing data to form submission
      document.addEventListener('submit', function(e) {
        formTiming.endTime = Date.now();

        // Add timing data to form
        const timingInput = document.createElement('input');
        timingInput.type = 'hidden';
        timingInput.name = 'formTiming';
        timingInput.value = JSON.stringify(formTiming);
        e.target.appendChild(timingInput);
      });
    })();
  `;
};

// Export singleton instance
export const honeypotService = new HoneypotService();

// Export utility functions
export {
  HONEYPOT_CONFIG,
  BOT_PATTERNS,
  HoneypotFieldSchema,
  FormTimingSchema,
};