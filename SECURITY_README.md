# Fynsor Consulting - Security Infrastructure

This document provides a comprehensive overview of the institutional-grade security infrastructure implemented for Fynsor Consulting's website.

## 🔒 Security Overview

The security implementation follows zero-trust architecture principles and includes multiple layers of protection:

- **Authentication**: OAuth 2.0 + PKCE with MFA using TOTP
- **Encryption**: AES-256-GCM for data at rest and in transit
- **Input Validation**: Comprehensive sanitization and threat detection
- **Rate Limiting**: 5 submissions per hour for forms
- **Bot Protection**: Advanced honeypot fields and behavior analysis
- **Session Management**: Secure 30-minute timeout sessions
- **IP Validation**: Geolocation and threat intelligence
- **Security Headers**: Comprehensive CSP, HSTS, and more

## 📁 File Structure

```
security/
├── auth/
│   ├── providers.ts          # OAuth 2.0 + PKCE implementation
│   ├── middleware.ts         # Authentication middleware
│   ├── guards.ts             # Route protection guards
│   └── mfa.ts                # TOTP multi-factor authentication
├── lib/
│   ├── encryption.ts         # AES-256-GCM encryption service
│   ├── secure-storage.ts     # Encrypted data storage with audit
│   ├── validation.ts         # Input validation and sanitization
│   ├── honeypot.ts           # Bot protection and detection
│   ├── ip-validation.ts      # IP-based security controls
│   ├── session-management.ts # Secure session handling
│   └── security-integration.ts # Unified security service
├── middleware/
│   └── security.ts           # Security headers and middleware
├── schemas/
│   └── input-schemas.ts      # Zod validation schemas
└── next.config.js            # Security configuration
```

## 🛡️ Security Components

### 1. Authentication System (`auth/`)

#### OAuth 2.0 + PKCE (`providers.ts`)
- Google and Microsoft OAuth integration
- PKCE (Proof Key for Code Exchange) implementation
- Secure state management and code verification
- Session-based PKCE parameter storage

```typescript
// Usage example
const authFlow = await oauthManager.initiateAuthFlow('google');
const tokens = await oauthManager.completeAuthFlow('google', code, codeVerifier);
```

#### Authentication Middleware (`middleware.ts`)
- JWT token generation and verification
- Secure session creation and management
- Role-based access control
- IP address validation for sessions

```typescript
// Usage example
const { user, session, error } = await authMiddleware.authenticate(request);
```

#### Route Guards (`guards.ts`)
- Authentication guards for protected routes
- MFA requirement enforcement
- Role-based authorization
- IP whitelist validation
- High-value investor access control

```typescript
// Usage example
const guard = GuardFactory.create()
  .auth()
  .mfa()
  .roles(['admin'])
  .build();
```

#### Multi-Factor Authentication (`mfa.ts`)
- TOTP (Time-based One-Time Password) implementation
- Base32 encoding for secret generation
- Backup codes for account recovery
- QR code generation for authenticator apps

```typescript
// Usage example
const { secret, qrCodeData, backupCodes } = await totpService.setupMFA(userId, email);
const isValid = await totpService.verifyMFA(userId, code, ipAddress, userAgent);
```

### 2. Encryption & Storage (`lib/`)

#### Encryption Service (`encryption.ts`)
- AES-256-GCM encryption for maximum security
- Key derivation using PBKDF2 with 100,000 iterations
- Context-specific key generation
- Client-side encryption capabilities
- Field-level encryption for sensitive data
- Key rotation support

```typescript
// Usage example
const encrypted = encryptionService.encrypt(sensitiveData, 'user_context');
const decrypted = encryptionService.decrypt(encrypted, 'user_context');
```

#### Secure Storage (`secure-storage.ts`)
- Encrypted data storage with checksums
- Comprehensive audit logging
- Data versioning and backup
- GDPR/CCPA compliance features
- Automated data retention policies

```typescript
// Usage example
const result = await secureStorage.store('users', userData, userId, context);
const data = await secureStorage.retrieve('users', id, userId, context);
```

### 3. Input Validation (`lib/validation.ts` & `schemas/`)

#### Validation Library (`validation.ts`)
- XSS and SQL injection prevention
- Input sanitization using DOMPurify
- Security threat pattern detection
- File upload validation
- Recursive object sanitization

```typescript
// Usage example
const sanitized = InputSanitizer.sanitizeString(userInput, { allowHtml: false });
const isSecure = SecurityValidation.isSecureInput(input);
```

#### Input Schemas (`input-schemas.ts`)
- Comprehensive Zod schemas for all forms
- Built-in sanitization transformers
- Business logic validation
- Honeypot field definitions

```typescript
// Usage example
const validatedData = validateFormData(FormSchemas.contactForm, formData);
```

### 4. Bot Protection (`lib/honeypot.ts`)

#### Advanced Bot Detection
- Multiple honeypot field types
- Form timing analysis
- User agent pattern detection
- Submission behavior analysis
- Mathematical challenges for suspicious requests

```typescript
// Usage example
const analysis = honeypotService.analyzeBotBehavior(
  userAgent, headers, formData, timing, clientIp
);
```

### 5. IP Validation (`lib/ip-validation.ts`)

#### IP-based Security
- IP format validation and range checking
- Geolocation-based access control
- VPN and Tor detection
- Brute force protection
- Country-based restrictions
- Threat intelligence integration

```typescript
// Usage example
const validation = await ipValidationService.validateIP(
  clientIp, userAgent, { checkGeolocation: true }
);
```

### 6. Session Management (`lib/session-management.ts`)

#### Secure Session Handling
- 30-minute session timeout
- Device fingerprinting
- Concurrent session limits (3 per user)
- Automatic session renewal
- Secure token generation with HMAC signatures

```typescript
// Usage example
const { sessionData, sessionToken } = await sessionManager.createSession(
  userId, email, name, roles, permissions, ipAddress, userAgent
);
```

### 7. Security Middleware (`middleware/security.ts`)

#### Comprehensive Security Headers
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- Frame Options and Content Type protection
- Permissions Policy
- Cross-Origin policies
- Rate limiting implementation

```typescript
// Usage example
const response = await securityMiddleware.handle(request);
```

## 🔧 Configuration

### Environment Variables

Create a `.env.security` file with the following variables:

```bash
# Encryption
ENCRYPTION_MASTER_KEY=your-256-bit-encryption-key
MFA_ENCRYPTION_KEY=your-mfa-encryption-key

# Authentication
JWT_SECRET=your-jwt-secret-key
SESSION_SECRET=your-session-secret-key

# OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-google-client-secret
MICROSOFT_OAUTH_CLIENT_ID=your-microsoft-client-id
MICROSOFT_OAUTH_CLIENT_SECRET=your-microsoft-client-secret

# Database
SUPABASE_URL=your-supabase-url
SUPABASE_ANON_KEY=your-supabase-anon-key
SUPABASE_SERVICE_KEY=your-supabase-service-key

# Security Features
MFA_REQUIRED=true
IP_WHITELIST_ENABLED=false
ALLOWED_IPS=192.168.1.1,10.0.0.1
HIGH_VALUE_INVESTOR_IPS=203.0.113.1,198.51.100.1
ALLOWED_COUNTRIES=US,CA,GB,AU,DE,FR,JP
HIGH_RISK_COUNTRIES=CN,RU,KP,IR

# Rate Limiting
API_RATE_LIMIT_ENABLED=true
API_RATE_LIMIT_MAX_REQUESTS=100
API_RATE_LIMIT_WINDOW_MS=900000

# CORS
CORS_ORIGIN=https://fynsor.com,https://admin.fynsor.com
CORS_CREDENTIALS=true
```

### Next.js Configuration

The `next.config.js` file includes comprehensive security headers:

- Content Security Policy with nonce support
- HSTS with preload and subdomain inclusion
- Frame protection and content type validation
- Permissions policy for browser features
- Cross-origin policies

## 🚀 Usage Examples

### 1. Protecting API Routes

```typescript
import { createSecurityMiddleware } from '@/lib/security-integration';

export const middleware = createSecurityMiddleware({
  enableAuth: true,
  requireMFA: true,
  requiredRoles: ['admin'],
  enableRateLimit: true,
});

export const config = {
  matcher: ['/api/admin/:path*', '/api/secure/:path*']
};
```

### 2. Secure Form Processing

```typescript
import { SecurityUtils } from '@/lib/security-integration';

export async function POST(request: NextRequest) {
  const formData = await request.json();

  const result = await SecurityUtils.validateSecureForm(
    formData,
    'contactForm',
    request
  );

  if (!result.success) {
    return NextResponse.json(
      { errors: result.errors },
      { status: 400 }
    );
  }

  return NextResponse.json({ success: true });
}
```

### 3. Client-Side Security

```typescript
// Generate security components for forms
const security = SecurityUtils.generateClientSecurity();

// Encrypt form data before submission
const encryptedData = SecurityUtils.encryptForTransmission(formData);
```

### 4. Session Validation

```typescript
import { sessionMiddleware } from '@/lib/session-management';

export async function GET(request: NextRequest) {
  const session = await sessionMiddleware.validateSession(request);

  if (!session) {
    return NextResponse.redirect('/login');
  }

  // Process authenticated request
}
```

## 🔍 Security Monitoring

### Audit Logging

All security events are logged with the following information:
- User ID and session information
- IP address and geolocation
- User agent and device fingerprint
- Timestamp and event type
- Success/failure status
- Additional metadata

### Security Events

The system tracks various security events:
- Authentication attempts (success/failure)
- MFA verifications
- Session creation/destruction
- IP blocking events
- Bot detection triggers
- Rate limit violations
- Data access and modifications

### Compliance Features

- **GDPR Article 20**: Data export functionality
- **GDPR Article 17**: Right to be forgotten
- **SOC 2 Type II**: Comprehensive audit trails
- **CCPA**: Data privacy controls
- **Data retention**: Configurable retention policies

## 🛠️ Database Schema

### Required Tables

```sql
-- Sessions table
CREATE TABLE sessions (
  session_id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  encrypted_data TEXT NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  ip_address INET NOT NULL,
  user_agent TEXT NOT NULL,
  device_fingerprint VARCHAR(32) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  last_activity TIMESTAMP DEFAULT NOW(),
  is_active BOOLEAN DEFAULT TRUE
);

-- MFA secrets table
CREATE TABLE mfa_secrets (
  user_id UUID PRIMARY KEY,
  secret TEXT NOT NULL,
  backup_codes TEXT NOT NULL,
  enabled BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);

-- Audit logs table
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  user_id UUID,
  action VARCHAR(50) NOT NULL,
  resource VARCHAR(100) NOT NULL,
  resource_id VARCHAR(100) NOT NULL,
  ip_address INET NOT NULL,
  user_agent TEXT NOT NULL,
  timestamp TIMESTAMP DEFAULT NOW(),
  success BOOLEAN NOT NULL,
  error_message TEXT,
  metadata JSONB
);

-- Form submissions table
CREATE TABLE form_submissions (
  id UUID PRIMARY KEY,
  user_id UUID,
  form_type VARCHAR(50) NOT NULL,
  encrypted_data TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  ip_address INET NOT NULL,
  user_agent TEXT NOT NULL,
  _encrypted_fields TEXT[]
);
```

## 🧪 Testing

### Security Testing Commands

```bash
# Run security audit
npm audit

# Test input validation
npm run test:validation

# Test encryption/decryption
npm run test:encryption

# Test authentication flow
npm run test:auth

# Security scan
npm run security:scan
```

### Manual Security Testing

1. **XSS Testing**: Submit forms with various XSS payloads
2. **SQL Injection**: Test with SQL injection patterns
3. **Rate Limiting**: Rapidly submit forms to test limits
4. **Session Security**: Test session timeout and renewal
5. **MFA Testing**: Verify TOTP codes and backup codes

## 📊 Performance Considerations

### Optimization Features

- **Memory Caching**: Active sessions cached in memory
- **Database Indexing**: Optimized queries for security lookups
- **Encryption Performance**: Context-specific key derivation
- **Rate Limiting**: Efficient in-memory storage with cleanup
- **Session Cleanup**: Automatic expired session removal

### Scalability

- **Horizontal Scaling**: Stateless security components
- **Redis Integration**: Ready for Redis-based session storage
- **CDN Compatibility**: Security headers work with CDNs
- **Microservices**: Modular security components

## 🚨 Incident Response

### Security Incident Handling

1. **Detection**: Automated threat detection and alerting
2. **Investigation**: Comprehensive audit logs for forensics
3. **Response**: Automatic IP blocking and session termination
4. **Recovery**: Data backup and recovery procedures
5. **Prevention**: Continuous security monitoring and updates

### Emergency Procedures

- **Immediate IP Blocking**: `ipValidationService.blockIP(ip, reason)`
- **User Session Termination**: `sessionManager.invalidateAllUserSessions(userId)`
- **MFA Reset**: `totpService.disableMFA(userId, adminCode)`
- **Data Encryption Key Rotation**: `keyRotation.rotateKey()`

## 📚 Security Best Practices

### Development Guidelines

1. **Never log sensitive data**: Use secure logging practices
2. **Validate all inputs**: Apply validation at multiple layers
3. **Encrypt sensitive data**: Use field-level encryption
4. **Implement proper authentication**: Always verify user identity
5. **Use secure defaults**: Fail secure in all cases
6. **Regular security updates**: Keep dependencies updated
7. **Code reviews**: Security-focused code review process

### Deployment Security

1. **Environment Isolation**: Separate staging and production
2. **Secret Management**: Use secure secret storage
3. **Network Security**: Implement proper firewalls
4. **Monitoring**: Continuous security monitoring
5. **Backup Security**: Encrypted backups with key rotation

## 📞 Support

For security questions or incidents:

- **Security Team**: security@fynsor.com
- **Emergency**: Call security hotline
- **Documentation**: This README and inline code comments
- **Updates**: Security advisories via security@fynsor.com

---

**Last Updated**: September 2024
**Security Review**: Completed
**Compliance Status**: SOC 2 Type II, GDPR, CCPA Ready