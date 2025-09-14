import { NextRequest, NextResponse } from 'next/server';

/**
 * Analytics tracking endpoint for Fynsor Consulting
 * Handles custom event tracking and business metrics
 */

interface AnalyticsEvent {
  type: string;
  data: any;
  sessionId?: string;
  userId?: string;
  url?: string;
  referrer?: string;
  timestamp?: number;
  country?: string;
}

interface BusinessMetric {
  metric: string;
  value: number;
  metadata?: any;
}

interface UserInteraction {
  event: string;
  element: string;
  timestamp: number;
  [key: string]: any;
}

export async function POST(request: NextRequest) {
  try {
    const event: AnalyticsEvent = await request.json();

    // Validate required fields
    if (!event.type || !event.data) {
      return NextResponse.json(
        { error: 'Missing required fields: type and data' },
        { status: 400 }
      );
    }

    // Add server-side metadata
    const enhancedEvent = {
      ...event,
      serverTimestamp: Date.now(),
      userAgent: request.headers.get('user-agent') || '',
      ip: getClientIP(request),
      country: request.geo?.country || 'unknown',
      region: request.geo?.region || 'unknown',
      city: request.geo?.city || 'unknown',
    };

    // Process different types of events
    await processAnalyticsEvent(enhancedEvent);

    return NextResponse.json(
      { success: true, eventId: generateEventId() },
      { status: 200 }
    );
  } catch (error) {
    console.error('Error processing analytics event:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * Process analytics events based on type
 */
async function processAnalyticsEvent(event: AnalyticsEvent) {
  console.log(`Analytics Event [${event.type}]:`, event.data);

  switch (event.type) {
    case 'user_interaction':
      await processUserInteraction(event.data as UserInteraction, event);
      break;

    case 'business_metric':
      await processBusinessMetric(event.data as BusinessMetric, event);
      break;

    case 'error':
      await processErrorEvent(event.data, event);
      break;

    case 'page_view':
      await processPageView(event.data, event);
      break;

    default:
      await processGenericEvent(event);
  }

  // Store in database (implement based on your database choice)
  // await storeEventInDatabase(event);

  // Send to external analytics services
  if (process.env.NODE_ENV === 'production') {
    await sendToExternalServices(event);
  }
}

/**
 * Process user interaction events
 */
async function processUserInteraction(interaction: UserInteraction, event: AnalyticsEvent) {
  // Track high-value interactions
  const highValueInteractions = [
    'contact_form_submit',
    'service_page_view',
    'newsletter_signup',
    'phone_click',
    'email_click',
  ];

  if (highValueInteractions.includes(interaction.event)) {
    console.log(`High-value interaction: ${interaction.event}`);
    // Trigger lead scoring or CRM integration
    await trackLeadInteraction(interaction, event);
  }

  // Track conversion funnel
  await updateConversionFunnel(interaction, event);
}

/**
 * Process business metrics
 */
async function processBusinessMetric(metric: BusinessMetric, event: AnalyticsEvent) {
  console.log(`Business Metric: ${metric.metric} = ${metric.value}`);

  // Define KPIs to track
  const kpis = [
    'contact_form_conversion',
    'newsletter_signup',
    'service_inquiry',
    'page_engagement_time',
    'bounce_rate',
  ];

  if (kpis.includes(metric.metric)) {
    await updateKPIDashboard(metric, event);
  }

  // Alert on significant changes
  await checkForAnomalies(metric, event);
}

/**
 * Process error events
 */
async function processErrorEvent(errorData: any, event: AnalyticsEvent) {
  console.error('Client Error:', errorData);

  // Send to error monitoring service (Sentry, LogRocket, etc.)
  if (process.env.NODE_ENV === 'production') {
    // await sendToSentry(errorData, event);
  }

  // Track error patterns
  await updateErrorMetrics(errorData, event);
}

/**
 * Process page view events
 */
async function processPageView(pageData: any, event: AnalyticsEvent) {
  // Track popular pages
  await updatePageViewStats(pageData, event);

  // Track user journey
  await updateUserJourney(pageData, event);
}

/**
 * Process generic events
 */
async function processGenericEvent(event: AnalyticsEvent) {
  console.log('Generic event:', event);
  // Default processing for unknown event types
}

/**
 * Track lead interactions for sales/marketing
 */
async function trackLeadInteraction(interaction: UserInteraction, event: AnalyticsEvent) {
  const leadData = {
    sessionId: event.sessionId,
    userId: event.userId,
    interaction: interaction.event,
    timestamp: interaction.timestamp,
    location: event.country,
    source: event.referrer,
  };

  // In production, integrate with CRM
  console.log('Lead interaction tracked:', leadData);
}

/**
 * Update conversion funnel metrics
 */
async function updateConversionFunnel(interaction: UserInteraction, event: AnalyticsEvent) {
  const funnelSteps = [
    'page_view',
    'service_interaction',
    'contact_form_start',
    'contact_form_submit',
    'contact_form_success',
  ];

  if (funnelSteps.includes(interaction.event)) {
    console.log(`Funnel step: ${interaction.event}`);
    // Update funnel analytics
  }
}

/**
 * Update KPI dashboard
 */
async function updateKPIDashboard(metric: BusinessMetric, event: AnalyticsEvent) {
  // In production, update real-time dashboard
  console.log(`KPI Update: ${metric.metric} = ${metric.value}`);
}

/**
 * Check for anomalies in metrics
 */
async function checkForAnomalies(metric: BusinessMetric, event: AnalyticsEvent) {
  // Implement anomaly detection logic
  // Alert if metrics are outside normal ranges
}

/**
 * Update error metrics
 */
async function updateErrorMetrics(errorData: any, event: AnalyticsEvent) {
  // Track error frequency and patterns
  console.log('Error metrics updated');
}

/**
 * Update page view statistics
 */
async function updatePageViewStats(pageData: any, event: AnalyticsEvent) {
  // Track popular content and user behavior
  console.log('Page view stats updated');
}

/**
 * Update user journey tracking
 */
async function updateUserJourney(pageData: any, event: AnalyticsEvent) {
  // Track user paths through the site
  console.log('User journey updated');
}

/**
 * Send events to external analytics services
 */
async function sendToExternalServices(event: AnalyticsEvent) {
  // Google Analytics 4
  // await sendToGA4(event);

  // Mixpanel
  // await sendToMixpanel(event);

  // Custom analytics pipeline
  // await sendToCustomPipeline(event);

  console.log('Event sent to external services');
}

/**
 * Get client IP address
 */
function getClientIP(request: NextRequest): string {
  const forwardedFor = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const connectingIP = request.headers.get('x-connecting-ip');

  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }
  if (realIP) {
    return realIP.trim();
  }
  if (connectingIP) {
    return connectingIP.trim();
  }

  return 'unknown';
}

/**
 * Generate unique event ID
 */
function generateEventId(): string {
  return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * GET endpoint for analytics dashboard data
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const timeframe = url.searchParams.get('timeframe') || '24h';
    const metric = url.searchParams.get('metric');

    // In production, query your analytics database
    const mockDashboardData = {
      timeframe,
      summary: {
        totalEvents: 5847,
        uniqueUsers: 1234,
        pageViews: 3452,
        conversionRate: 3.2,
        bounceRate: 45.8,
      },
      topPages: [
        { path: '/', views: 1234, uniqueViews: 987 },
        { path: '/services', views: 856, uniqueViews: 643 },
        { path: '/about', views: 534, uniqueViews: 421 },
        { path: '/contact', views: 432, uniqueViews: 387 },
      ],
      conversionFunnel: {
        pageView: 3452,
        serviceInteraction: 1234,
        contactFormStart: 234,
        contactFormSubmit: 123,
        contactFormSuccess: 110,
      },
      userGeo: {
        US: 45,
        CA: 15,
        UK: 12,
        AU: 8,
        other: 20,
      },
      lastUpdated: new Date().toISOString(),
    };

    return NextResponse.json(mockDashboardData);
  } catch (error) {
    console.error('Error retrieving analytics dashboard:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}