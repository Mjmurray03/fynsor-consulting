/**
 * Sentry Error Tracking Configuration for Fynsor Consulting
 * Institutional-grade error monitoring and performance tracking
 */

import * as Sentry from '@sentry/nextjs';

// Sentry configuration options
const sentryConfig = {
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN || process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'development',
  release: process.env.VERCEL_GIT_COMMIT_SHA || 'unknown',

  // Performance monitoring
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,

  // Session replay sampling
  replaysSessionSampleRate: process.env.NODE_ENV === 'production' ? 0.01 : 0.1,
  replaysOnErrorSampleRate: 1.0,

  // Enhanced configuration for production
  beforeSend: (event) => {
    // Filter out development/local errors in production
    if (process.env.NODE_ENV === 'production') {
      // Don't send errors from localhost or development domains
      if (event.request?.url?.includes('localhost') ||
          event.request?.url?.includes('127.0.0.1') ||
          event.request?.url?.includes('.local')) {
        return null;
      }

      // Filter out specific error types that aren't actionable
      if (event.exception?.values?.[0]?.type === 'ChunkLoadError' ||
          event.exception?.values?.[0]?.value?.includes('Loading chunk')) {
        return null;
      }
    }

    return event;
  },

  // Custom error boundary fallback
  beforeErrorBoundary: (error, errorInfo) => {
    console.error('Error boundary caught error:', error, errorInfo);
  },

  // Additional tags for better error organization
  initialScope: {
    tags: {
      component: 'fynsor-consulting',
      platform: 'vercel',
      framework: 'nextjs',
    },
    contexts: {
      app: {
        name: 'Fynsor Consulting',
        version: process.env.npm_package_version || '1.0.0',
      },
    },
  },
};

// Initialize Sentry
export function initSentry() {
  if (sentryConfig.dsn) {
    Sentry.init(sentryConfig);
    console.log('Sentry initialized for error tracking');
  } else {
    console.warn('Sentry DSN not provided - error tracking disabled');
  }
}

// Enhanced error tracking utilities
export const errorTracking = {
  // Capture exceptions with context
  captureException: (error: Error, context?: any) => {
    Sentry.withScope((scope) => {
      if (context) {
        scope.setContext('error_context', context);
      }
      scope.setLevel('error');
      Sentry.captureException(error);
    });
  },

  // Capture messages with different severity levels
  captureMessage: (message: string, level: 'info' | 'warning' | 'error' = 'info', context?: any) => {
    Sentry.withScope((scope) => {
      if (context) {
        scope.setContext('message_context', context);
      }
      scope.setLevel(level);
      Sentry.captureMessage(message, level);
    });
  },

  // Capture business-critical errors
  captureBusinessError: (error: Error, businessContext: any) => {
    Sentry.withScope((scope) => {
      scope.setTag('error_type', 'business_critical');
      scope.setContext('business_context', businessContext);
      scope.setLevel('error');
      Sentry.captureException(error);
    });
  },

  // Capture user feedback with errors
  captureUserFeedback: (user: { email: string; name?: string }, feedback: string) => {
    const eventId = Sentry.captureMessage('User feedback received', 'info');
    Sentry.captureUserFeedback({
      event_id: eventId,
      name: user.name || 'Anonymous',
      email: user.email,
      comments: feedback,
    });
  },

  // Security incident tracking
  captureSecurityIncident: (incident: string, details: any) => {
    Sentry.withScope((scope) => {
      scope.setTag('security_incident', true);
      scope.setTag('incident_type', incident);
      scope.setContext('security_details', details);
      scope.setLevel('error');
      Sentry.captureMessage(`Security incident: ${incident}`, 'error');
    });
  },

  // Performance issue tracking
  capturePerformanceIssue: (metric: string, value: number, threshold: number) => {
    if (value > threshold) {
      Sentry.withScope((scope) => {
        scope.setTag('performance_issue', true);
        scope.setContext('performance_data', {
          metric,
          value,
          threshold,
          exceeded_by: value - threshold,
        });
        scope.setLevel('warning');
        Sentry.captureMessage(`Performance threshold exceeded: ${metric}`, 'warning');
      });
    }
  },

  // API error tracking
  captureAPIError: (endpoint: string, status: number, error: any) => {
    Sentry.withScope((scope) => {
      scope.setTag('api_error', true);
      scope.setTag('endpoint', endpoint);
      scope.setTag('status_code', status);
      scope.setContext('api_details', {
        endpoint,
        status,
        error: error.message || error,
        timestamp: new Date().toISOString(),
      });
      scope.setLevel('error');
      Sentry.captureException(new Error(`API Error: ${endpoint} returned ${status}`));
    });
  },

  // Database error tracking
  captureDatabaseError: (operation: string, error: any) => {
    Sentry.withScope((scope) => {
      scope.setTag('database_error', true);
      scope.setTag('operation', operation);
      scope.setContext('database_details', {
        operation,
        error: error.message || error,
        timestamp: new Date().toISOString(),
      });
      scope.setLevel('error');
      Sentry.captureException(error);
    });
  },
};

// Performance monitoring utilities
export const performanceMonitoring = {
  // Start a performance transaction
  startTransaction: (name: string, op: string) => {
    return Sentry.startTransaction({
      name,
      op,
      tags: {
        component: 'fynsor-consulting',
      },
    });
  },

  // Measure function execution time
  measureFunction: async <T>(name: string, fn: () => Promise<T>): Promise<T> => {
    const transaction = performanceMonitoring.startTransaction(name, 'function');

    try {
      const result = await fn();
      transaction.setStatus('ok');
      return result;
    } catch (error) {
      transaction.setStatus('internal_error');
      errorTracking.captureException(error as Error, { function: name });
      throw error;
    } finally {
      transaction.finish();
    }
  },

  // Track page load performance
  trackPageLoad: (pageName: string, loadTime: number) => {
    Sentry.addBreadcrumb({
      message: `Page loaded: ${pageName}`,
      category: 'navigation',
      data: {
        loadTime,
        page: pageName,
      },
      level: 'info',
    });

    // Alert if page load is slow
    if (loadTime > 3000) {
      errorTracking.capturePerformanceIssue('page_load_time', loadTime, 3000);
    }
  },

  // Track API response times
  trackAPIResponse: (endpoint: string, responseTime: number, status: number) => {
    Sentry.addBreadcrumb({
      message: `API call: ${endpoint}`,
      category: 'http',
      data: {
        endpoint,
        responseTime,
        status,
      },
      level: status >= 400 ? 'error' : 'info',
    });

    // Alert if API response is slow
    if (responseTime > 2000) {
      errorTracking.capturePerformanceIssue('api_response_time', responseTime, 2000);
    }
  },
};

// User context utilities
export const userContext = {
  // Set user context for error tracking
  setUser: (user: { id: string; email?: string; username?: string }) => {
    Sentry.setUser(user);
  },

  // Clear user context (on logout)
  clearUser: () => {
    Sentry.setUser(null);
  },

  // Add user breadcrumb
  addUserAction: (action: string, data?: any) => {
    Sentry.addBreadcrumb({
      message: `User action: ${action}`,
      category: 'user',
      data,
      level: 'info',
    });
  },
};

// Feature flag integration
export const featureFlags = {
  // Track feature flag usage
  trackFeatureUsage: (flag: string, enabled: boolean, context?: any) => {
    Sentry.addBreadcrumb({
      message: `Feature flag: ${flag} = ${enabled}`,
      category: 'feature',
      data: {
        flag,
        enabled,
        ...context,
      },
      level: 'info',
    });
  },
};

// Custom Sentry integrations for Next.js
export const sentryIntegrations = [
  new Sentry.Integrations.Breadcrumbs({
    console: true,
    dom: true,
    fetch: true,
    history: true,
    sentry: true,
    xhr: true,
  }),
  new Sentry.Integrations.GlobalHandlers({
    onerror: true,
    onunhandledrejection: true,
  }),
  new Sentry.Integrations.Dedupe(),
  new Sentry.Integrations.HttpContext(),
];

// Export configured Sentry instance
export { Sentry };

// Auto-initialize in browser
if (typeof window !== 'undefined') {
  initSentry();
}