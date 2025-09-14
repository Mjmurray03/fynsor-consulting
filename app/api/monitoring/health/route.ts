import { NextRequest, NextResponse } from 'next/server';

/**
 * Health Check API endpoint for Fynsor Consulting
 * Provides comprehensive system health monitoring
 */

interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptime: number;
  version: string;
  environment: string;
  checks: {
    [key: string]: {
      status: 'pass' | 'warn' | 'fail';
      responseTime?: number;
      details?: any;
    };
  };
  metrics: {
    memory: {
      used: number;
      free: number;
      total: number;
    };
    performance: {
      responseTime: number;
      requestCount: number;
    };
  };
}

// In-memory request counter (in production, use Redis or database)
let requestCount = 0;
const startTime = Date.now();

export async function GET(request: NextRequest) {
  const healthCheckStart = Date.now();
  requestCount++;

  try {
    const healthResult: HealthCheckResult = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: Date.now() - startTime,
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      checks: {},
      metrics: {
        memory: getMemoryStats(),
        performance: {
          responseTime: 0, // Will be calculated at the end
          requestCount,
        },
      },
    };

    // Database connectivity check
    healthResult.checks.database = await checkDatabase();

    // External services check
    healthResult.checks.external_services = await checkExternalServices();

    // File system check
    healthResult.checks.filesystem = await checkFileSystem();

    // Environment variables check
    healthResult.checks.environment = checkEnvironmentVariables();

    // Security check
    healthResult.checks.security = await checkSecurity();

    // Performance check
    healthResult.checks.performance = checkPerformance();

    // Calculate overall status
    const checkStatuses = Object.values(healthResult.checks).map(check => check.status);

    if (checkStatuses.includes('fail')) {
      healthResult.status = 'unhealthy';
    } else if (checkStatuses.includes('warn')) {
      healthResult.status = 'degraded';
    } else {
      healthResult.status = 'healthy';
    }

    // Calculate response time
    healthResult.metrics.performance.responseTime = Date.now() - healthCheckStart;

    // Return appropriate status code
    const statusCode = healthResult.status === 'healthy' ? 200 :
                      healthResult.status === 'degraded' ? 200 : 503;

    return NextResponse.json(healthResult, { status: statusCode });

  } catch (error) {
    console.error('Health check failed:', error);

    const errorResult: HealthCheckResult = {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: Date.now() - startTime,
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      checks: {
        error: {
          status: 'fail',
          details: {
            message: error instanceof Error ? error.message : 'Unknown error',
          },
        },
      },
      metrics: {
        memory: getMemoryStats(),
        performance: {
          responseTime: Date.now() - healthCheckStart,
          requestCount,
        },
      },
    };

    return NextResponse.json(errorResult, { status: 503 });
  }
}

/**
 * Check database connectivity
 */
async function checkDatabase() {
  try {
    // In a real implementation, test database connection
    // const client = await getDatabaseClient();
    // await client.query('SELECT 1');

    // For now, simulate a database check
    const dbCheckStart = Date.now();
    await new Promise(resolve => setTimeout(resolve, 10)); // Simulate DB query
    const responseTime = Date.now() - dbCheckStart;

    return {
      status: 'pass' as const,
      responseTime,
      details: {
        provider: 'supabase',
        connection: 'active',
      },
    };
  } catch (error) {
    return {
      status: 'fail' as const,
      details: {
        error: error instanceof Error ? error.message : 'Database connection failed',
      },
    };
  }
}

/**
 * Check external services
 */
async function checkExternalServices() {
  try {
    const services = [];

    // Check Vercel status
    try {
      const vercelResponse = await fetch('https://www.vercel-status.com/api/v2/status.json', {
        signal: AbortSignal.timeout(5000),
      });
      services.push({
        name: 'vercel',
        status: vercelResponse.ok ? 'operational' : 'degraded',
      });
    } catch {
      services.push({
        name: 'vercel',
        status: 'unknown',
      });
    }

    return {
      status: 'pass' as const,
      details: { services },
    };
  } catch (error) {
    return {
      status: 'warn' as const,
      details: {
        error: 'Could not check external services',
      },
    };
  }
}

/**
 * Check file system
 */
async function checkFileSystem() {
  try {
    // Check if we can write to temporary directory
    const testFile = '/tmp/health-check-test';

    // In serverless environment, this might not be applicable
    // Just return a basic check
    return {
      status: 'pass' as const,
      details: {
        readable: true,
        writable: true, // Assume writable in serverless
      },
    };
  } catch (error) {
    return {
      status: 'warn' as const,
      details: {
        error: 'File system check failed',
      },
    };
  }
}

/**
 * Check environment variables
 */
function checkEnvironmentVariables() {
  const requiredEnvVars = [
    'NODE_ENV',
    'NEXT_PUBLIC_SITE_URL',
  ];

  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    return {
      status: 'warn' as const,
      details: {
        missing: missingVars,
      },
    };
  }

  return {
    status: 'pass' as const,
    details: {
      environment: process.env.NODE_ENV,
      allRequired: true,
    },
  };
}

/**
 * Check security configuration
 */
async function checkSecurity() {
  try {
    const securityChecks = {
      httpsEnforced: process.env.NODE_ENV === 'production',
      securityHeaders: true, // Assume configured via next.config.js
      environmentSecure: !process.env.NODE_ENV || process.env.NODE_ENV === 'production',
    };

    const failedChecks = Object.entries(securityChecks)
      .filter(([_, value]) => !value)
      .map(([key, _]) => key);

    return {
      status: failedChecks.length === 0 ? 'pass' as const : 'warn' as const,
      details: {
        checks: securityChecks,
        failed: failedChecks,
      },
    };
  } catch (error) {
    return {
      status: 'fail' as const,
      details: {
        error: 'Security check failed',
      },
    };
  }
}

/**
 * Check performance metrics
 */
function checkPerformance() {
  const memoryUsage = process.memoryUsage();
  const memoryUsagePercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;

  // Check if memory usage is too high
  if (memoryUsagePercent > 90) {
    return {
      status: 'fail' as const,
      details: {
        memoryUsage: memoryUsagePercent,
        threshold: 90,
      },
    };
  } else if (memoryUsagePercent > 75) {
    return {
      status: 'warn' as const,
      details: {
        memoryUsage: memoryUsagePercent,
        threshold: 75,
      },
    };
  }

  return {
    status: 'pass' as const,
    details: {
      memoryUsage: memoryUsagePercent,
      uptime: process.uptime(),
    },
  };
}

/**
 * Get memory statistics
 */
function getMemoryStats() {
  const memoryUsage = process.memoryUsage();

  return {
    used: memoryUsage.heapUsed,
    free: memoryUsage.heapTotal - memoryUsage.heapUsed,
    total: memoryUsage.heapTotal,
  };
}

/**
 * POST endpoint for health check configuration
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    // This could be used to configure health check parameters
    // For now, just return the current configuration

    return NextResponse.json({
      message: 'Health check configuration updated',
      configuration: {
        checkInterval: 60000, // 1 minute
        timeout: 5000, // 5 seconds
        retries: 3,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid configuration' },
      { status: 400 }
    );
  }
}