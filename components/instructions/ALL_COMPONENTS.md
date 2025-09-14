# Fynsor Component Build Instructions

## SECURITY COMPONENTS (Priority 1)

### SecureContactForm.tsx

- Implement rate limiting (5 submissions per hour)
- Add honeypot fields for bot protection
- Client-side encryption before submission
- Server-side validation with Zod schemas
- Sanitize all inputs against XSS
- Store encrypted in Supabase
- Send notification to admin (not user data)

### AuthWrapper.tsx

- Implement OAuth 2.0 with PKCE
- MFA using TOTP
- Session management with secure cookies
- Automatic session timeout after 30 mins
- IP validation for sensitive operations

## UI COMPONENTS (Priority 2)

### TensorLogo.tsx

- 4x4 grid matching uploaded logo
- Gray border (#666666)
- White dots forming F pattern
- Subtle pulse animation on hover
- Responsive sizing
- Dark mode only

### Navigation.tsx

- Black background (#000000)
- Tensor logo left aligned
- Menu items: About, Services, Insights, Contact
- Mobile hamburger with slide animation
- Sticky header with backdrop blur

### HomePage.tsx

HERO SECTION:
- Animated tensor logo (dots appear sequentially)
- 'Where Finance Meets Intelligence' tagline
- Subtle grid background from banner
- No colors except black/white/gray

SERVICES CARDS:
- Three black cards with gray borders
- Financial Modeling
- Investment Analysis
- Strategic Advisory
- Hover effect: subtle border glow

### AboutPage.tsx

- Explain Fynsor name (Finance + Tensor)
- Institutional standards emphasis
- Team credentials section
- Clean typography, no images

### ServicesPage.tsx

- Detailed service descriptions
- CRE property types supported
- Financial modeling capabilities
- No pricing (contact for quotes)
- Professional tone throughout

### ContactPage.tsx

- Split layout: form left, logo right
- Fields: Name, Company, Email, Phone
- Property type dropdown
- Investment size dropdown
- Encrypted submission to Supabase

## DATA MODELS

### Supabase Tables

contacts:
  - id: UUID
  - name: TEXT (encrypted)
  - email: TEXT (encrypted)
  - company: TEXT (encrypted)
  - phone: TEXT (encrypted)
  - property_type: TEXT
  - investment_size: TEXT
  - message: TEXT (encrypted)
  - ip_address: INET
  - created_at: TIMESTAMP

audit_log:
  - id: UUID
  - action: TEXT
  - user_id: UUID
  - metadata: JSONB
  - created_at: TIMESTAMP

## STYLING RULES

- Colors: #000000, #FFFFFF, #666666 only
- Font: Inter or system-ui
- No gradients or shadows
- Clean, minimal design
- Professional spacing
- Mobile-first responsive

## SECURITY HEADERS

Content-Security-Policy: strict
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin
Permissions-Policy: restrictive