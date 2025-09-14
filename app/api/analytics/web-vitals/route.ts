import { NextRequest, NextResponse } from 'next/server';

/**
 * Web Vitals API endpoint for Fynsor Consulting
 * Collects and processes Core Web Vitals data
 */

interface WebVitalMetric {
  name: string;
  value: number;
  id: string;
  label?: string;
  rating?: 'good' | 'needs-improvement' | 'poor';
}

export async function POST(request: NextRequest) {
  try {
    const metric: WebVitalMetric = await request.json();

    // Validate the metric data
    if (!metric.name || typeof metric.value !== 'number' || !metric.id) {
      return NextResponse.json(
        { error: 'Invalid metric data' },
        { status: 400 }
      );
    }

    // Get additional context
    const userAgent = request.headers.get('user-agent') || '';
    const referer = request.headers.get('referer') || '';
    const timestamp = new Date().toISOString();

    // Determine rating based on Core Web Vitals thresholds
    const rating = getWebVitalRating(metric.name, metric.value);

    // Enhanced metric data
    const enhancedMetric = {
      ...metric,
      rating,
      timestamp,
      userAgent,
      referer,
      url: referer,
    };

    // Log the metric (in production, send to your analytics service)
    console.log('Web Vital Metric:', enhancedMetric);

    // Here you would typically:
    // 1. Send to your analytics database
    // 2. Send to monitoring services (DataDog, New Relic, etc.)
    // 3. Trigger alerts if performance degrades

    // For demonstration, we'll simulate different actions based on the metric
    await processWebVital(enhancedMetric);

    return NextResponse.json(
      { success: true, received: metric.name },
      { status: 200 }
    );
  } catch (error) {
    console.error('Error processing web vital:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * Determine the rating for a web vital metric
 */
function getWebVitalRating(name: string, value: number): 'good' | 'needs-improvement' | 'poor' {
  const thresholds: Record<string, { good: number; poor: number }> = {
    CLS: { good: 0.1, poor: 0.25 },
    FID: { good: 100, poor: 300 },
    FCP: { good: 1800, poor: 3000 },
    LCP: { good: 2500, poor: 4000 },
    TTFB: { good: 800, poor: 1800 },
    INP: { good: 200, poor: 500 },
  };

  const threshold = thresholds[name];
  if (!threshold) return 'good';

  if (value <= threshold.good) return 'good';
  if (value <= threshold.poor) return 'needs-improvement';
  return 'poor';
}

/**
 * Process and store web vital data
 */
async function processWebVital(metric: any) {
  // In a real implementation, you would:

  // 1. Store in database
  // await storeMetricInDatabase(metric);

  // 2. Send to external monitoring services
  if (process.env.NODE_ENV === 'production') {
    // Send to Vercel Analytics
    // await sendToVercelAnalytics(metric);

    // Send to Sentry for performance monitoring
    // await sendToSentry(metric);

    // Send to custom analytics pipeline
    // await sendToAnalyticsPipeline(metric);
  }

  // 3. Check for performance regressions and alert if necessary
  if (metric.rating === 'poor') {
    await handlePoorPerformance(metric);
  }

  // 4. Update real-time dashboards
  // await updateDashboard(metric);
}

/**
 * Handle poor performance metrics
 */
async function handlePoorPerformance(metric: any) {
  console.warn(`Poor performance detected: ${metric.name} = ${metric.value}`);

  // In production, you might:
  // 1. Send alerts to development team
  // 2. Create incident tickets
  // 3. Trigger automated scaling
  // 4. Update status page
}

/**
 * GET endpoint for retrieving web vitals statistics
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const timeframe = url.searchParams.get('timeframe') || '24h';
    const metric = url.searchParams.get('metric');

    // In a real implementation, you would query your database
    // const stats = await getWebVitalsStats(timeframe, metric);

    // For demonstration, return mock data
    const mockStats = {
      timeframe,
      metric: metric || 'all',
      summary: {
        totalMeasurements: 1250,
        averageScore: 85,
        goodMeasurements: 1062,
        needsImprovementMeasurements: 125,
        poorMeasurements: 63,
      },
      metrics: {
        LCP: { average: 2100, p75: 2400, p95: 3200 },
        FID: { average: 85, p75: 120, p95: 180 },
        CLS: { average: 0.08, p75: 0.12, p95: 0.18 },
        FCP: { average: 1600, p75: 1800, p95: 2200 },
        TTFB: { average: 650, p75: 750, p95: 950 },
      },
      trend: 'improving',
      lastUpdated: new Date().toISOString(),
    };

    return NextResponse.json(mockStats);
  } catch (error) {
    console.error('Error retrieving web vitals stats:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}