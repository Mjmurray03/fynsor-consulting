/**
 * Performance Monitoring System for Fynsor Consulting
 * Comprehensive performance tracking and optimization
 */

// Performance metrics tracking
export class PerformanceTracker {
  private static instance: PerformanceTracker;
  private metrics: Map<string, PerformanceMetric[]> = new Map();
  private observers: PerformanceObserver[] = [];

  static getInstance(): PerformanceTracker {
    if (!PerformanceTracker.instance) {
      PerformanceTracker.instance = new PerformanceTracker();
    }
    return PerformanceTracker.instance;
  }

  constructor() {
    if (typeof window !== 'undefined') {
      this.initializeObservers();
    }
  }

  // Initialize performance observers
  private initializeObservers() {
    // Core Web Vitals observer
    if ('PerformanceObserver' in window) {
      // Largest Contentful Paint (LCP)
      this.observePerformanceEntry('largest-contentful-paint', (entries) => {
        entries.forEach((entry: any) => {
          this.recordMetric('LCP', entry.startTime, {
            element: entry.element?.tagName,
            url: entry.url,
          });
        });
      });

      // First Input Delay (FID)
      this.observePerformanceEntry('first-input', (entries) => {
        entries.forEach((entry: any) => {
          this.recordMetric('FID', entry.processingStart - entry.startTime, {
            eventType: entry.name,
            target: entry.target?.tagName,
          });
        });
      });

      // Cumulative Layout Shift (CLS)
      this.observePerformanceEntry('layout-shift', (entries) => {
        let clsValue = 0;
        entries.forEach((entry: any) => {
          if (!entry.hadRecentInput) {
            clsValue += entry.value;
          }
        });
        if (clsValue > 0) {
          this.recordMetric('CLS', clsValue);
        }
      });

      // Navigation timing
      this.observePerformanceEntry('navigation', (entries) => {
        entries.forEach((entry: any) => {
          this.recordMetric('TTFB', entry.responseStart - entry.requestStart);
          this.recordMetric('DOM_LOAD', entry.domContentLoadedEventEnd - entry.domContentLoadedEventStart);
          this.recordMetric('FULL_LOAD', entry.loadEventEnd - entry.loadEventStart);
        });
      });

      // Resource timing
      this.observePerformanceEntry('resource', (entries) => {
        entries.forEach((entry: any) => {
          this.recordResourceMetric(entry);
        });
      });
    }
  }

  // Observe specific performance entries
  private observePerformanceEntry(type: string, callback: (entries: PerformanceEntry[]) => void) {
    try {
      const observer = new PerformanceObserver((list) => {
        callback(list.getEntries());
      });
      observer.observe({ entryTypes: [type] });
      this.observers.push(observer);
    } catch (error) {
      console.warn(`Could not observe ${type} performance entries:`, error);
    }
  }

  // Record a performance metric
  recordMetric(name: string, value: number, metadata?: any) {
    const metric: PerformanceMetric = {
      name,
      value,
      timestamp: Date.now(),
      url: typeof window !== 'undefined' ? window.location.href : '',
      metadata,
    };

    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }

    this.metrics.get(name)!.push(metric);

    // Send to analytics
    this.sendMetricToAnalytics(metric);

    // Check thresholds and alert if necessary
    this.checkThresholds(metric);
  }

  // Record resource loading metrics
  private recordResourceMetric(entry: PerformanceResourceTiming) {
    const resourceType = this.getResourceType(entry.name);
    const loadTime = entry.responseEnd - entry.requestStart;

    this.recordMetric(`RESOURCE_${resourceType.toUpperCase()}`, loadTime, {
      url: entry.name,
      size: entry.transferSize,
      cached: entry.transferSize === 0,
      protocol: entry.nextHopProtocol,
    });
  }

  // Determine resource type from URL
  private getResourceType(url: string): string {
    if (url.match(/\.(js|jsx|ts|tsx)$/)) return 'script';
    if (url.match(/\.(css|scss|sass)$/)) return 'stylesheet';
    if (url.match(/\.(jpg|jpeg|png|gif|webp|svg)$/)) return 'image';
    if (url.match(/\.(woff|woff2|ttf|eot)$/)) return 'font';
    if (url.includes('/api/')) return 'api';
    return 'other';
  }

  // Send metric to analytics service
  private async sendMetricToAnalytics(metric: PerformanceMetric) {
    try {
      await fetch('/api/analytics/performance', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(metric),
      });
    } catch (error) {
      console.error('Failed to send performance metric:', error);
    }
  }

  // Check performance thresholds
  private checkThresholds(metric: PerformanceMetric) {
    const thresholds: Record<string, { warning: number; critical: number }> = {
      LCP: { warning: 2500, critical: 4000 },
      FID: { warning: 100, critical: 300 },
      CLS: { warning: 0.1, critical: 0.25 },
      TTFB: { warning: 800, critical: 1800 },
      DOM_LOAD: { warning: 1000, critical: 2000 },
      FULL_LOAD: { warning: 2000, critical: 4000 },
    };

    const threshold = thresholds[metric.name];
    if (!threshold) return;

    if (metric.value > threshold.critical) {
      this.alertPerformanceIssue(metric, 'critical');
    } else if (metric.value > threshold.warning) {
      this.alertPerformanceIssue(metric, 'warning');
    }
  }

  // Alert on performance issues
  private alertPerformanceIssue(metric: PerformanceMetric, severity: 'warning' | 'critical') {
    console.warn(`Performance ${severity}: ${metric.name} = ${metric.value}ms`);

    // Send to error tracking
    if (typeof window !== 'undefined' && (window as any).Sentry) {
      (window as any).Sentry.captureMessage(
        `Performance ${severity}: ${metric.name}`,
        severity === 'critical' ? 'error' : 'warning'
      );
    }
  }

  // Get performance summary
  getPerformanceSummary(): PerformanceSummary {
    const summary: PerformanceSummary = {
      timestamp: Date.now(),
      metrics: {},
    };

    this.metrics.forEach((values, name) => {
      if (values.length > 0) {
        const recent = values.slice(-10); // Last 10 measurements
        summary.metrics[name] = {
          current: recent[recent.length - 1].value,
          average: recent.reduce((sum, m) => sum + m.value, 0) / recent.length,
          min: Math.min(...recent.map(m => m.value)),
          max: Math.max(...recent.map(m => m.value)),
          count: values.length,
        };
      }
    });

    return summary;
  }

  // Clean up observers
  disconnect() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
  }
}

// Performance metric interface
interface PerformanceMetric {
  name: string;
  value: number;
  timestamp: number;
  url: string;
  metadata?: any;
}

// Performance summary interface
interface PerformanceSummary {
  timestamp: number;
  metrics: Record<string, {
    current: number;
    average: number;
    min: number;
    max: number;
    count: number;
  }>;
}

// Business performance metrics
export class BusinessPerformanceTracker {
  // Track form conversion rates
  static trackFormConversion(formName: string, step: 'start' | 'submit' | 'success' | 'error') {
    const metric = {
      type: 'form_conversion',
      form: formName,
      step,
      timestamp: Date.now(),
    };

    this.sendBusinessMetric(metric);
  }

  // Track page engagement
  static trackPageEngagement(page: string, engagementTime: number) {
    const metric = {
      type: 'page_engagement',
      page,
      duration: engagementTime,
      timestamp: Date.now(),
    };

    this.sendBusinessMetric(metric);
  }

  // Track service interactions
  static trackServiceInteraction(service: string, action: string, value?: number) {
    const metric = {
      type: 'service_interaction',
      service,
      action,
      value,
      timestamp: Date.now(),
    };

    this.sendBusinessMetric(metric);
  }

  // Track conversion funnel
  static trackConversionFunnel(step: string, metadata?: any) {
    const metric = {
      type: 'conversion_funnel',
      step,
      metadata,
      timestamp: Date.now(),
    };

    this.sendBusinessMetric(metric);
  }

  // Send business metric to analytics
  private static async sendBusinessMetric(metric: any) {
    try {
      await fetch('/api/analytics/business', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(metric),
      });
    } catch (error) {
      console.error('Failed to send business metric:', error);
    }
  }
}

// Real User Monitoring (RUM)
export class RealUserMonitoring {
  private static startTime = Date.now();
  private static interactions: UserInteraction[] = [];

  // Track user interactions
  static trackInteraction(type: string, element: string, metadata?: any) {
    const interaction: UserInteraction = {
      type,
      element,
      timestamp: Date.now() - this.startTime,
      metadata,
    };

    this.interactions.push(interaction);

    // Keep only last 50 interactions
    if (this.interactions.length > 50) {
      this.interactions = this.interactions.slice(-50);
    }

    this.sendInteraction(interaction);
  }

  // Track scroll depth
  static trackScrollDepth() {
    if (typeof window === 'undefined') return;

    let maxScroll = 0;
    const trackScroll = () => {
      const scrollPercent = Math.round(
        (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100
      );

      if (scrollPercent > maxScroll) {
        maxScroll = scrollPercent;

        // Track milestone scrolls
        if (maxScroll >= 25 && maxScroll < 50) {
          this.trackInteraction('scroll_milestone', 'page', { depth: '25%' });
        } else if (maxScroll >= 50 && maxScroll < 75) {
          this.trackInteraction('scroll_milestone', 'page', { depth: '50%' });
        } else if (maxScroll >= 75 && maxScroll < 100) {
          this.trackInteraction('scroll_milestone', 'page', { depth: '75%' });
        } else if (maxScroll >= 100) {
          this.trackInteraction('scroll_milestone', 'page', { depth: '100%' });
        }
      }
    };

    window.addEventListener('scroll', trackScroll, { passive: true });
  }

  // Track time on page
  static trackTimeOnPage() {
    if (typeof window === 'undefined') return;

    const startTime = Date.now();

    const sendTimeOnPage = () => {
      const timeOnPage = Date.now() - startTime;
      this.trackInteraction('time_on_page', 'page', { duration: timeOnPage });
    };

    // Send time on page when user leaves
    window.addEventListener('beforeunload', sendTimeOnPage);

    // Also send periodically for long sessions
    setInterval(sendTimeOnPage, 30000); // Every 30 seconds
  }

  // Send interaction to analytics
  private static async sendInteraction(interaction: UserInteraction) {
    try {
      await fetch('/api/analytics/rum', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(interaction),
      });
    } catch (error) {
      console.error('Failed to send RUM data:', error);
    }
  }

  // Get user session summary
  static getSessionSummary() {
    return {
      duration: Date.now() - this.startTime,
      interactions: this.interactions.length,
      lastInteraction: this.interactions[this.interactions.length - 1],
    };
  }
}

// User interaction interface
interface UserInteraction {
  type: string;
  element: string;
  timestamp: number;
  metadata?: any;
}

// Initialize performance monitoring
export function initializePerformanceMonitoring() {
  if (typeof window === 'undefined') return;

  // Initialize trackers
  PerformanceTracker.getInstance();
  RealUserMonitoring.trackScrollDepth();
  RealUserMonitoring.trackTimeOnPage();

  // Track page visibility changes
  document.addEventListener('visibilitychange', () => {
    RealUserMonitoring.trackInteraction(
      'visibility_change',
      'page',
      { hidden: document.hidden }
    );
  });

  console.log('Performance monitoring initialized');
}

// Export singleton instance
export const performanceTracker = PerformanceTracker.getInstance();