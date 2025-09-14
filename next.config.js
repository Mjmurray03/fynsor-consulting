/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: true,
  },

  // Security headers configuration
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // Content Security Policy
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://vercel.live https://va.vercel-scripts.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "img-src 'self' data: https: blob:",
              "font-src 'self' https://fonts.gstatic.com",
              "connect-src 'self' https://api.supabase.co wss://api.supabase.co https://*.supabase.co https://vitals.vercel-insights.com https://vercel.live",
              "media-src 'self'",
              "object-src 'none'",
              "child-src 'none'",
              "worker-src 'self' blob:",
              "frame-ancestors 'none'",
              "form-action 'self'",
              "base-uri 'self'",
              "manifest-src 'self'",
              "upgrade-insecure-requests",
              "block-all-mixed-content",
            ].join('; '),
          },

          // HTTP Strict Transport Security
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },

          // X-Frame-Options
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },

          // X-Content-Type-Options
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },

          // X-XSS-Protection
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },

          // Referrer Policy
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },

          // Permissions Policy
          {
            key: 'Permissions-Policy',
            value: [
              'accelerometer=()',
              'ambient-light-sensor=()',
              'autoplay=(self)',
              'battery=()',
              'camera=()',
              'cross-origin-isolated=()',
              'display-capture=()',
              'document-domain=()',
              'encrypted-media=()',
              'execution-while-not-rendered=()',
              'execution-while-out-of-viewport=()',
              'fullscreen=(self)',
              'geolocation=()',
              'gyroscope=()',
              'magnetometer=()',
              'microphone=()',
              'midi=()',
              'navigation-override=()',
              'payment=(self)',
              'picture-in-picture=()',
              'publickey-credentials-get=(self)',
              'screen-wake-lock=()',
              'sync-xhr=()',
              'usb=()',
              'web-share=(self)',
              'xr-spatial-tracking=()',
            ].join(', '),
          },

          // Cross-Origin Policies
          {
            key: 'Cross-Origin-Embedder-Policy',
            value: 'credentialless',
          },
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin',
          },
          {
            key: 'Cross-Origin-Resource-Policy',
            value: 'same-origin',
          },

          // Additional Security Headers
          {
            key: 'X-Permitted-Cross-Domain-Policies',
            value: 'none',
          },

          // Remove server identification
          {
            key: 'Server',
            value: '',
          },
        ],
      },

      // API specific headers
      {
        source: '/api/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, max-age=0',
          },
          {
            key: 'Pragma',
            value: 'no-cache',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
        ],
      },

      // Static assets caching
      {
        source: '/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
    ];
  },

  // Security-focused redirects
  async redirects() {
    return [
      // Force HTTPS in production
      {
        source: '/:path*',
        has: [
          {
            type: 'header',
            key: 'x-forwarded-proto',
            value: 'http',
          },
        ],
        destination: 'https://fynsor.com/:path*',
        permanent: true,
      },
    ];
  },

  // Rewrite rules for security
  async rewrites() {
    return [
      // Hide sensitive paths
      {
        source: '/admin-panel',
        destination: '/404',
      },
      {
        source: '/wp-admin/:path*',
        destination: '/404',
      },
      {
        source: '/.env',
        destination: '/404',
      },
      {
        source: '/config/:path*',
        destination: '/404',
      },
    ];
  },

  // Environment variables validation
  env: {
    CUSTOM_KEY: process.env.CUSTOM_KEY,
  },

  // Image optimization with security
  images: {
    domains: ['fynsor.com', 'secure-cdn.fynsor.com'],
    formats: ['image/webp', 'image/avif'],
    minimumCacheTTL: 60,
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Webpack configuration for security
  webpack: (config, { dev, isServer }) => {
    // Security-focused webpack configuration
    if (!dev) {
      // Minimize bundle exposure
      config.optimization.splitChunks = {
        chunks: 'all',
        cacheGroups: {
          default: false,
          vendors: false,
          vendor: {
            name: 'vendor',
            chunks: 'all',
            test: /node_modules/,
          },
        },
      };
    }

    // Add security-focused plugins
    config.resolve.alias = {
      ...config.resolve.alias,
      // Prevent accidental exposure of server-side modules
      'fs': false,
      'net': false,
      'tls': false,
    };

    return config;
  },

  // Output configuration
  output: 'standalone',

  // Disable x-powered-by header
  poweredByHeader: false,

  // Enable compression
  compress: true,

  // Strict mode
  reactStrictMode: true,

  // SWC minification
  swcMinify: true,

  // TypeScript configuration
  typescript: {
    // Type checking during build
    ignoreBuildErrors: false,
  },

  // ESLint configuration
  eslint: {
    // Lint during build
    ignoreDuringBuilds: false,
  },

  // Experimental features for security
  experimental: {
    // Runtime configuration
    serverComponentsExternalPackages: ['crypto', 'bcryptjs'],

    // Security optimizations
    optimizeCss: true,
    optimizePackageImports: ['lodash', 'date-fns'],
  },
};

module.exports = nextConfig;