/**
 * Google Analytics tracking utilities for Fynsor Consulting
 * Handles event tracking with privacy compliance
 */

interface GtagEvent {
  action: string;
  category?: string;
  label?: string;
  value?: number;
  custom_parameters?: Record<string, any>;
}

interface ContactFormData {
  name: string;
  email: string;
  company?: string;
  phone?: string;
  property_type?: string;
  investment_size?: string;
  message: string;
}

// Check if Google Analytics is loaded and consent given
const isGAEnabled = (): boolean => {
  return (
    typeof window !== 'undefined' &&
    typeof window.gtag === 'function' &&
    process.env.NODE_ENV === 'production' &&
    localStorage.getItem('ga-consent') === 'true'
  );
};

// Generic event tracking function
export const trackEvent = (eventName: string, parameters?: Record<string, any>) => {
  if (!isGAEnabled()) {
    console.log('GA tracking disabled or not available:', eventName, parameters);
    return;
  }

  try {
    window.gtag('event', eventName, {
      // Remove any PII from parameters
      ...sanitizeParameters(parameters),
      // Add session context
      session_id: getSessionId(),
      timestamp: Date.now(),
    });

    console.log('GA Event tracked:', eventName, parameters);
  } catch (error) {
    console.error('Error tracking GA event:', error);
  }
};

// Track page views (for SPA navigation)
export const trackPageView = (url: string, title?: string) => {
  if (!isGAEnabled()) return;

  try {
    window.gtag('event', 'page_view', {
      page_title: title || document.title,
      page_location: url,
      page_path: new URL(url).pathname,
    });
  } catch (error) {
    console.error('Error tracking page view:', error);
  }
};

// Track contact form submission (lead generation)
export const trackContactFormSubmission = (formData: ContactFormData) => {
  if (!isGAEnabled()) return;

  // Create sanitized parameters (no PII)
  const parameters = {
    // Business data only (no personal information)
    has_company: !!formData.company,
    has_phone: !!formData.phone,
    property_type: formData.property_type || 'not_specified',
    investment_size: formData.investment_size || 'not_specified',
    message_length: formData.message?.length || 0,
    form_completion_time: getFormCompletionTime(),
  };

  trackEvent('generate_lead', {
    currency: 'USD',
    value: getLeadValue(formData.investment_size),
    ...parameters,
  });

  // Also track as conversion
  trackEvent('contact_form_submit', parameters);
};

// Track button clicks and interactions
export const trackButtonClick = (buttonName: string, location: string) => {
  trackEvent('click', {
    event_category: 'engagement',
    event_label: buttonName,
    page_location: location,
  });
};

// Track service page interactions
export const trackServiceInteraction = (serviceName: string, action: string) => {
  trackEvent('service_interaction', {
    event_category: 'services',
    service_name: serviceName,
    interaction_type: action,
  });
};

// Track download events (if you add PDFs, whitepapers, etc.)
export const trackDownload = (fileName: string, fileType: string) => {
  trackEvent('file_download', {
    event_category: 'downloads',
    file_name: fileName,
    file_type: fileType,
  });
};

// Track external link clicks
export const trackExternalLink = (url: string, linkText?: string) => {
  trackEvent('click', {
    event_category: 'external_link',
    event_label: linkText || url,
    outbound: true,
  });
};

// Track scroll depth for engagement
export const trackScrollDepth = (percentage: number) => {
  if (percentage % 25 === 0) { // Track at 25%, 50%, 75%, 100%
    trackEvent('scroll', {
      event_category: 'engagement',
      event_label: `${percentage}%`,
      value: percentage,
    });
  }
};

// Track time on page
export const trackTimeOnPage = (timeInSeconds: number) => {
  trackEvent('timing_complete', {
    event_category: 'engagement',
    name: 'time_on_page',
    value: Math.round(timeInSeconds),
  });
};

// Utility functions

const sanitizeParameters = (params?: Record<string, any>): Record<string, any> => {
  if (!params) return {};

  const sanitized: Record<string, any> = {};

  for (const [key, value] of Object.entries(params)) {
    // Remove any fields that might contain PII
    if (isPIIField(key)) {
      continue;
    }

    // Truncate long strings
    if (typeof value === 'string' && value.length > 100) {
      sanitized[key] = value.substring(0, 100) + '...';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

const isPIIField = (fieldName: string): boolean => {
  const piiFields = ['name', 'email', 'phone', 'address', 'message', 'company'];
  return piiFields.some(field => fieldName.toLowerCase().includes(field));
};

const getSessionId = (): string => {
  if (typeof window === 'undefined') return 'unknown';

  let sessionId = sessionStorage.getItem('ga_session_id');
  if (!sessionId) {
    sessionId = Date.now().toString(36) + Math.random().toString(36);
    sessionStorage.setItem('ga_session_id', sessionId);
  }
  return sessionId;
};

const getFormCompletionTime = (): number => {
  const startTime = sessionStorage.getItem('form_start_time');
  if (!startTime) return 0;

  const completionTime = (Date.now() - parseInt(startTime)) / 1000;
  sessionStorage.removeItem('form_start_time');
  return Math.round(completionTime);
};

// Estimate lead value based on investment size for conversion tracking
const getLeadValue = (investmentSize?: string): number => {
  const valueMap: Record<string, number> = {
    'under-1m': 500,
    '1m-5m': 1000,
    '5m-10m': 2000,
    '10m-25m': 5000,
    '25m-50m': 10000,
    '50m-100m': 20000,
    'over-100m': 50000,
  };

  return valueMap[investmentSize || ''] || 1000; // Default lead value
};

// Track form field focus to measure engagement
export const trackFormEngagement = (fieldName: string) => {
  // Only track the start of form interaction once per session
  if (!sessionStorage.getItem('form_start_time')) {
    sessionStorage.setItem('form_start_time', Date.now().toString());

    trackEvent('form_start', {
      event_category: 'engagement',
      first_field: fieldName,
    });
  }
};

// Enhanced conversion tracking for CRE industry
export const trackCREEvent = (eventType: string, details: Record<string, any>) => {
  trackEvent(`cre_${eventType}`, {
    event_category: 'commercial_real_estate',
    industry_specific: true,
    ...sanitizeParameters(details),
  });
};

// Export measurement ID for use in components
export const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '';

// Debug function for development
export const debugGA = () => {
  if (process.env.NODE_ENV === 'development') {
    console.log('GA Debug Info:', {
      isEnabled: isGAEnabled(),
      measurementId: GA_MEASUREMENT_ID,
      consent: localStorage.getItem('ga-consent'),
      sessionId: getSessionId(),
    });
  }
};