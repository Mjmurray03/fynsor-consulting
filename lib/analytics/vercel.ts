/**
 * Vercel Analytics Integration
 * Institutional-grade analytics setup for Fynsor Consulting
 */

// Web Vitals tracking
export function reportWebVitals(metric: any) {
  // Send to Vercel Analytics
  if (typeof window !== 'undefined' && (window as any).va) {
    (window as any).va('track', 'Web Vitals', {
      name: metric.name,
      value: metric.value,
      id: metric.id,
      label: metric.label,
    });
  }

  // Send to custom analytics endpoint
  fetch('/api/analytics/web-vitals', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(metric),
  }).catch((err) => {
    console.error('Failed to send web vitals:', err);
  });

  // Console logging for development
  if (process.env.NODE_ENV === 'development') {
    console.log('Web Vital:', metric);
  }
}

// Performance monitoring
export class PerformanceMonitor {
  private static instance: PerformanceMonitor;
  private metrics: Map<string, number> = new Map();

  static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  // Track page load time
  trackPageLoad(pageName: string) {
    if (typeof window === 'undefined') return;

    const startTime = performance.now();

    window.addEventListener('load', () => {
      const loadTime = performance.now() - startTime;
      this.metrics.set(`page_load_${pageName}`, loadTime);

      this.sendMetric('page_load', {
        page: pageName,
        duration: loadTime,
        timestamp: Date.now(),
      });
    });
  }

  // Track user interactions
  trackInteraction(event: string, element: string, additionalData?: any) {
    this.sendMetric('user_interaction', {
      event,
      element,
      timestamp: Date.now(),
      ...additionalData,
    });
  }

  // Track business metrics
  trackBusinessMetric(metric: string, value: number, metadata?: any) {
    this.sendMetric('business_metric', {
      metric,
      value,
      timestamp: Date.now(),
      ...metadata,
    });
  }

  // Track errors
  trackError(error: Error, context?: string) {
    this.sendMetric('error', {
      message: error.message,
      stack: error.stack,
      context,
      timestamp: Date.now(),
      userAgent: typeof window !== 'undefined' ? window.navigator.userAgent : null,
    });
  }

  // Send metric to analytics endpoint
  private sendMetric(type: string, data: any) {
    if (typeof window === 'undefined') return;

    fetch('/api/analytics/track', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type,
        data,
        sessionId: this.getSessionId(),
        userId: this.getUserId(),
        url: window.location.href,
        referrer: document.referrer,
      }),
    }).catch((err) => {
      console.error('Failed to send metric:', err);
    });
  }

  // Get or create session ID
  private getSessionId(): string {
    if (typeof window === 'undefined') return '';

    let sessionId = sessionStorage.getItem('fynsor_session_id');
    if (!sessionId) {
      sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      sessionStorage.setItem('fynsor_session_id', sessionId);
    }
    return sessionId;
  }

  // Get user ID (if authenticated)
  private getUserId(): string | null {
    if (typeof window === 'undefined') return null;

    // This would integrate with your authentication system
    return localStorage.getItem('fynsor_user_id') || null;
  }
}

// Event tracking utilities
export const analytics = {
  // Track page views
  pageView: (pageName: string) => {
    PerformanceMonitor.getInstance().trackInteraction('page_view', pageName);
  },

  // Track button clicks
  buttonClick: (buttonName: string, location?: string) => {
    PerformanceMonitor.getInstance().trackInteraction('button_click', buttonName, { location });
  },

  // Track form submissions
  formSubmit: (formName: string, success: boolean) => {
    PerformanceMonitor.getInstance().trackInteraction('form_submit', formName, { success });
  },

  // Track contact form interactions
  contactForm: {
    start: () => analytics.trackInteraction('contact_form_start', 'contact_form'),
    submit: () => analytics.trackInteraction('contact_form_submit', 'contact_form'),
    success: () => analytics.trackBusinessMetric('contact_form_conversion', 1),
    error: (error: string) => analytics.trackInteraction('contact_form_error', 'contact_form', { error }),
  },

  // Track service page interactions
  serviceInteraction: (service: string, action: string) => {
    PerformanceMonitor.getInstance().trackInteraction('service_interaction', service, { action });
  },

  // Track newsletter signup
  newsletterSignup: (success: boolean) => {
    PerformanceMonitor.getInstance().trackBusinessMetric('newsletter_signup', success ? 1 : 0);
  },

  // Generic event tracking
  trackEvent: (category: string, action: string, label?: string, value?: number) => {
    PerformanceMonitor.getInstance().trackInteraction('custom_event', `${category}_${action}`, {
      category,
      action,
      label,
      value,
    });
  },

  // Track business metrics
  trackInteraction: (event: string, element: string, data?: any) => {
    PerformanceMonitor.getInstance().trackInteraction(event, element, data);
  },

  // Track errors
  trackError: (error: Error, context?: string) => {
    PerformanceMonitor.getInstance().trackError(error, context);
  },
};

// Initialize performance monitoring
export function initializeAnalytics() {
  if (typeof window === 'undefined') return;

  const monitor = PerformanceMonitor.getInstance();

  // Track page load performance
  monitor.trackPageLoad(window.location.pathname);

  // Track unhandled errors
  window.addEventListener('error', (event) => {
    monitor.trackError(new Error(event.message), 'unhandled_error');
  });

  // Track unhandled promise rejections
  window.addEventListener('unhandledrejection', (event) => {
    monitor.trackError(new Error(event.reason), 'unhandled_promise_rejection');
  });

  // Track page visibility changes
  document.addEventListener('visibilitychange', () => {
    analytics.trackEvent('engagement', 'visibility_change', document.hidden ? 'hidden' : 'visible');
  });

  console.log('Fynsor Analytics initialized');
}