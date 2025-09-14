/**
 * IP Validation and Security
 * Advanced IP-based security controls for Fynsor Consulting
 */

import { z } from 'zod';
import crypto from 'crypto';

// IP validation configuration
const IP_CONFIG = {
  maxFailedAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
  bruteForceWindow: 15 * 60 * 1000, // 15 minutes
  geoLocationEnabled: process.env.GEO_LOCATION_ENABLED === 'true',
  vpnDetectionEnabled: process.env.VPN_DETECTION_ENABLED === 'true',
  torDetectionEnabled: process.env.TOR_DETECTION_ENABLED === 'true',
} as const;

// IP address schemas
const IPAddressSchema = z.string().ip();
const IPRangeSchema = z.string().regex(/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/);

// Geolocation schema
const GeoLocationSchema = z.object({
  country: z.string(),
  countryCode: z.string().length(2),
  region: z.string(),
  regionCode: z.string(),
  city: z.string(),
  latitude: z.number(),
  longitude: z.number(),
  timezone: z.string(),
  isp: z.string(),
  organization: z.string(),
  asn: z.string(),
  isVPN: z.boolean().default(false),
  isTor: z.boolean().default(false),
  isProxy: z.boolean().default(false),
  threatLevel: z.enum(['low', 'medium', 'high']).default('low'),
});

export type GeoLocation = z.infer<typeof GeoLocationSchema>;

// Security event schema
const SecurityEventSchema = z.object({
  id: z.string(),
  ip: z.string().ip(),
  eventType: z.enum([
    'failed_login',
    'brute_force',
    'ip_blocked',
    'suspicious_activity',
    'geo_anomaly',
    'vpn_detected',
    'tor_detected',
    'rate_limit_exceeded'
  ]),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  timestamp: z.date(),
  userAgent: z.string(),
  location: GeoLocationSchema.optional(),
  metadata: z.record(z.any()).optional(),
});

export type SecurityEvent = z.infer<typeof SecurityEventSchema>;

// IP tracking entry
interface IPTrackingEntry {
  ip: string;
  failedAttempts: number;
  firstFailure: number;
  lastFailure: number;
  isBlocked: boolean;
  blockUntil?: number;
  location?: GeoLocation;
  userAgents: Set<string>;
  attempts: Array<{
    timestamp: number;
    type: string;
    success: boolean;
  }>;
}

// Known malicious IP ranges (examples)
const MALICIOUS_RANGES = [
  // These would be loaded from threat intelligence feeds
  '0.0.0.0/8',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '192.0.2.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

// Allowed countries (ISO 3166-1 alpha-2 codes)
const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || 'US,CA,GB,AU,DE,FR,JP,NL,SG').split(',');

// High-risk countries
const HIGH_RISK_COUNTRIES = (process.env.HIGH_RISK_COUNTRIES || 'CN,RU,KP,IR,SY').split(',');

// IP validation service
export class IPValidationService {
  private ipTracking = new Map<string, IPTrackingEntry>();
  private allowedIPs = new Set<string>();
  private blockedIPs = new Set<string>();
  private whitelistedIPs = new Set<string>();
  private highValueInvestorIPs = new Set<string>();

  constructor() {
    this.loadIPLists();
    this.startCleanupTimer();
  }

  // Load IP lists from environment variables
  private loadIPLists(): void {
    // Load allowed IPs
    const allowed = (process.env.ALLOWED_IPS || '').split(',').filter(ip => ip.trim());
    allowed.forEach(ip => this.allowedIPs.add(ip.trim()));

    // Load blocked IPs
    const blocked = (process.env.BLOCKED_IPS || '').split(',').filter(ip => ip.trim());
    blocked.forEach(ip => this.blockedIPs.add(ip.trim()));

    // Load whitelisted IPs
    const whitelisted = (process.env.WHITELISTED_IPS || '').split(',').filter(ip => ip.trim());
    whitelisted.forEach(ip => this.whitelistedIPs.add(ip.trim()));

    // Load high-value investor IPs
    const hvInvestor = (process.env.HIGH_VALUE_INVESTOR_IPS || '').split(',').filter(ip => ip.trim());
    hvInvestor.forEach(ip => this.highValueInvestorIPs.add(ip.trim()));
  }

  // Validate IP address format
  validateIPFormat(ip: string): boolean {
    try {
      IPAddressSchema.parse(ip);
      return true;
    } catch {
      return false;
    }
  }

  // Check if IP is in a range
  private isIPInRange(ip: string, range: string): boolean {
    try {
      const [network, prefixLength] = range.split('/');
      const networkParts = network.split('.').map(Number);
      const ipParts = ip.split('.').map(Number);

      const prefixLengthNum = parseInt(prefixLength, 10);
      const mask = (0xffffffff << (32 - prefixLengthNum)) >>> 0;

      const networkInt = (networkParts[0] << 24) | (networkParts[1] << 16) | (networkParts[2] << 8) | networkParts[3];
      const ipInt = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];

      return ((networkInt & mask) === (ipInt & mask));
    } catch {
      return false;
    }
  }

  // Check if IP is in malicious ranges
  isMaliciousIP(ip: string): boolean {
    return MALICIOUS_RANGES.some(range => this.isIPInRange(ip, range));
  }

  // Check if IP is explicitly blocked
  isBlockedIP(ip: string): boolean {
    return this.blockedIPs.has(ip);
  }

  // Check if IP is whitelisted
  isWhitelistedIP(ip: string): boolean {
    return this.whitelistedIPs.has(ip) || this.highValueInvestorIPs.has(ip);
  }

  // Get geolocation for IP (mock implementation)
  async getGeoLocation(ip: string): Promise<GeoLocation | null> {
    if (!IP_CONFIG.geoLocationEnabled) {
      return null;
    }

    try {
      // In production, use a real geolocation service like MaxMind, IPinfo, etc.
      // This is a mock implementation
      const mockData: GeoLocation = {
        country: 'United States',
        countryCode: 'US',
        region: 'California',
        regionCode: 'CA',
        city: 'San Francisco',
        latitude: 37.7749,
        longitude: -122.4194,
        timezone: 'America/Los_Angeles',
        isp: 'Example ISP',
        organization: 'Example Org',
        asn: 'AS12345',
        isVPN: false,
        isTor: false,
        isProxy: false,
        threatLevel: 'low',
      };

      // Simulate VPN/Tor detection based on IP patterns
      if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) {
        mockData.isVPN = true;
        mockData.threatLevel = 'medium';
      }

      return mockData;
    } catch (error) {
      console.error('Geolocation lookup failed:', error);
      return null;
    }
  }

  // Check if country is allowed
  isCountryAllowed(countryCode: string): boolean {
    return ALLOWED_COUNTRIES.includes(countryCode.toUpperCase());
  }

  // Check if country is high-risk
  isHighRiskCountry(countryCode: string): boolean {
    return HIGH_RISK_COUNTRIES.includes(countryCode.toUpperCase());
  }

  // Track failed attempt
  trackFailedAttempt(ip: string, userAgent: string, eventType: string): void {
    const now = Date.now();
    let entry = this.ipTracking.get(ip);

    if (!entry) {
      entry = {
        ip,
        failedAttempts: 0,
        firstFailure: now,
        lastFailure: now,
        isBlocked: false,
        userAgents: new Set(),
        attempts: [],
      };
      this.ipTracking.set(ip, entry);
    }

    // Add user agent
    entry.userAgents.add(userAgent);

    // Add attempt
    entry.attempts.push({
      timestamp: now,
      type: eventType,
      success: false,
    });

    // Clean old attempts (outside brute force window)
    entry.attempts = entry.attempts.filter(
      attempt => now - attempt.timestamp <= IP_CONFIG.bruteForceWindow
    );

    // Count failed attempts in window
    const recentFailures = entry.attempts.filter(attempt => !attempt.success).length;

    entry.failedAttempts = recentFailures;
    entry.lastFailure = now;

    // Check if should be blocked
    if (recentFailures >= IP_CONFIG.maxFailedAttempts && !entry.isBlocked) {
      this.blockIP(ip, 'brute_force');
    }
  }

  // Track successful attempt
  trackSuccessfulAttempt(ip: string, userAgent: string, eventType: string): void {
    const now = Date.now();
    let entry = this.ipTracking.get(ip);

    if (!entry) {
      entry = {
        ip,
        failedAttempts: 0,
        firstFailure: now,
        lastFailure: now,
        isBlocked: false,
        userAgents: new Set(),
        attempts: [],
      };
      this.ipTracking.set(ip, entry);
    }

    // Add attempt
    entry.attempts.push({
      timestamp: now,
      type: eventType,
      success: true,
    });

    // Reset failed attempts on success
    entry.failedAttempts = 0;
  }

  // Block IP address
  blockIP(ip: string, reason: string, duration?: number): void {
    const blockDuration = duration || IP_CONFIG.lockoutDuration;
    const entry = this.ipTracking.get(ip);

    if (entry) {
      entry.isBlocked = true;
      entry.blockUntil = Date.now() + blockDuration;
    }

    // Add to blocked IPs set
    this.blockedIPs.add(ip);

    // Log security event
    this.logSecurityEvent(ip, 'ip_blocked', 'high', {
      reason,
      blockDuration,
      blockUntil: entry?.blockUntil,
    });

    console.warn(`IP ${ip} blocked for ${reason}. Block duration: ${blockDuration}ms`);
  }

  // Unblock IP address
  unblockIP(ip: string): void {
    const entry = this.ipTracking.get(ip);

    if (entry) {
      entry.isBlocked = false;
      entry.blockUntil = undefined;
      entry.failedAttempts = 0;
    }

    this.blockedIPs.delete(ip);

    console.info(`IP ${ip} unblocked`);
  }

  // Check if IP is currently blocked
  isCurrentlyBlocked(ip: string): { blocked: boolean; reason?: string; unblockTime?: number } {
    // Check explicit block list
    if (this.isBlockedIP(ip)) {
      return { blocked: true, reason: 'explicitly_blocked' };
    }

    // Check malicious IP ranges
    if (this.isMaliciousIP(ip)) {
      return { blocked: true, reason: 'malicious_range' };
    }

    // Check tracking data
    const entry = this.ipTracking.get(ip);
    if (entry?.isBlocked) {
      if (entry.blockUntil && Date.now() < entry.blockUntil) {
        return {
          blocked: true,
          reason: 'temporary_block',
          unblockTime: entry.blockUntil,
        };
      } else {
        // Block expired, unblock
        this.unblockIP(ip);
        return { blocked: false };
      }
    }

    return { blocked: false };
  }

  // Comprehensive IP validation
  async validateIP(
    ip: string,
    userAgent: string,
    options: {
      checkGeolocation?: boolean;
      checkReputation?: boolean;
      requireWhitelist?: boolean;
    } = {}
  ): Promise<{
    allowed: boolean;
    reason?: string;
    location?: GeoLocation;
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    recommendations: string[];
  }> {
    const recommendations: string[] = [];
    let threatLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

    // Validate IP format
    if (!this.validateIPFormat(ip)) {
      return {
        allowed: false,
        reason: 'invalid_ip_format',
        threatLevel: 'high',
        recommendations: ['Reject request with invalid IP'],
      };
    }

    // Check if whitelisted (always allow)
    if (this.isWhitelistedIP(ip)) {
      return {
        allowed: true,
        threatLevel: 'low',
        recommendations: ['IP is whitelisted'],
      };
    }

    // Check if currently blocked
    const blockStatus = this.isCurrentlyBlocked(ip);
    if (blockStatus.blocked) {
      return {
        allowed: false,
        reason: blockStatus.reason,
        threatLevel: 'high',
        recommendations: [
          'IP is blocked',
          blockStatus.unblockTime ? `Unblock time: ${new Date(blockStatus.unblockTime)}` : 'Permanent block',
        ],
      };
    }

    // Check geolocation if enabled
    let location: GeoLocation | undefined;
    if (options.checkGeolocation) {
      location = await this.getGeoLocation(ip);

      if (location) {
        // Check country restrictions
        if (!this.isCountryAllowed(location.countryCode)) {
          threatLevel = 'high';
          recommendations.push(`Country not allowed: ${location.country}`);
          return {
            allowed: false,
            reason: 'country_restricted',
            location,
            threatLevel,
            recommendations,
          };
        }

        // Check high-risk countries
        if (this.isHighRiskCountry(location.countryCode)) {
          threatLevel = 'medium';
          recommendations.push(`High-risk country: ${location.country}`);
        }

        // Check VPN/Tor
        if (location.isVPN && IP_CONFIG.vpnDetectionEnabled) {
          threatLevel = 'medium';
          recommendations.push('VPN detected');
        }

        if (location.isTor && IP_CONFIG.torDetectionEnabled) {
          threatLevel = 'high';
          recommendations.push('Tor network detected');
          return {
            allowed: false,
            reason: 'tor_detected',
            location,
            threatLevel,
            recommendations,
          };
        }
      }
    }

    // Check if whitelist is required
    if (options.requireWhitelist && !this.isWhitelistedIP(ip)) {
      return {
        allowed: false,
        reason: 'not_whitelisted',
        location,
        threatLevel: 'medium',
        recommendations: ['IP not in whitelist'],
      };
    }

    // Check tracking data for suspicious patterns
    const entry = this.ipTracking.get(ip);
    if (entry) {
      // Multiple user agents (possible bot)
      if (entry.userAgents.size > 5) {
        threatLevel = 'medium';
        recommendations.push(`Multiple user agents: ${entry.userAgents.size}`);
      }

      // Recent failed attempts
      if (entry.failedAttempts > 2) {
        threatLevel = 'medium';
        recommendations.push(`Recent failed attempts: ${entry.failedAttempts}`);
      }
    }

    return {
      allowed: true,
      location,
      threatLevel,
      recommendations: recommendations.length > 0 ? recommendations : ['IP validation passed'],
    };
  }

  // Log security event
  private logSecurityEvent(
    ip: string,
    eventType: SecurityEvent['eventType'],
    severity: SecurityEvent['severity'],
    metadata?: Record<string, any>
  ): void {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      ip,
      eventType,
      severity,
      timestamp: new Date(),
      userAgent: 'system',
      metadata,
    };

    // In production, send to SIEM or security monitoring system
    console.log('Security Event:', JSON.stringify(event, null, 2));

    // Store in database or send to monitoring service
    // await this.storeSecurityEvent(event);
  }

  // Get IP statistics
  getIPStatistics(ip: string): {
    entry?: IPTrackingEntry;
    isTracked: boolean;
    failedAttempts: number;
    isBlocked: boolean;
    riskScore: number;
  } {
    const entry = this.ipTracking.get(ip);

    if (!entry) {
      return {
        isTracked: false,
        failedAttempts: 0,
        isBlocked: false,
        riskScore: 0,
      };
    }

    // Calculate risk score (0-100)
    let riskScore = 0;
    riskScore += entry.failedAttempts * 10; // 10 points per failed attempt
    riskScore += entry.userAgents.size * 5; // 5 points per unique user agent
    if (entry.isBlocked) riskScore += 50; // 50 points if blocked

    riskScore = Math.min(riskScore, 100);

    return {
      entry,
      isTracked: true,
      failedAttempts: entry.failedAttempts,
      isBlocked: entry.isBlocked,
      riskScore,
    };
  }

  // Cleanup expired entries
  cleanup(): void {
    const now = Date.now();

    for (const [ip, entry] of this.ipTracking.entries()) {
      // Remove expired blocks
      if (entry.isBlocked && entry.blockUntil && now > entry.blockUntil) {
        this.unblockIP(ip);
      }

      // Remove old tracking entries (older than 24 hours)
      if (now - entry.lastFailure > 24 * 60 * 60 * 1000) {
        this.ipTracking.delete(ip);
      }
    }
  }

  // Start cleanup timer
  private startCleanupTimer(): void {
    setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000); // Cleanup every 5 minutes
  }
}

// Export singleton instance
export const ipValidationService = new IPValidationService();

// Export utility functions
export {
  IP_CONFIG,
  MALICIOUS_RANGES,
  ALLOWED_COUNTRIES,
  HIGH_RISK_COUNTRIES,
  IPAddressSchema,
  GeoLocationSchema,
  SecurityEventSchema,
};