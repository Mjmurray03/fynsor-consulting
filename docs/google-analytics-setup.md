# Google Analytics Setup for Fynsor Consulting

## Overview

Google Analytics has been implemented with GDPR compliance and comprehensive event tracking specifically tailored for commercial real estate lead generation.

## Features Implemented

### ✅ GDPR Compliance
- **Consent Banner**: Users must explicitly consent to analytics tracking
- **Privacy-Focused**: Anonymized IP, disabled ad personalization
- **Local Storage**: Consent preferences stored locally
- **Production Only**: Analytics disabled in development mode

### ✅ Event Tracking
- **Contact Form Submissions**: Lead generation tracking with investment size values
- **Form Engagement**: Tracks when users start interacting with forms
- **Button Clicks**: Tracks important user interactions
- **Page Views**: Automatic tracking for SPA navigation
- **Scroll Depth**: Engagement tracking at 25%, 50%, 75%, 100%

### ✅ CRE-Specific Tracking
- **Investment Size Mapping**: Assigns lead values based on investment ranges
- **Property Type Tracking**: Tracks interest in different CRE sectors
- **Lead Qualification**: Identifies high-value prospects

## Files Structure

```
components/
├── GoogleAnalytics.tsx      # Main GA component with consent banner
└── AnalyticsProvider.tsx    # Page view tracking wrapper

lib/
└── gtag.ts                  # Analytics utilities and event tracking

hooks/
└── usePageTracking.ts       # Automatic page view tracking hook

docs/
└── google-analytics-setup.md # This documentation
```

## Configuration

### Environment Variables

The following are configured in `.env.local`:

```bash
# Google Analytics Measurement ID
NEXT_PUBLIC_GA_MEASUREMENT_ID=G-KC55N329QZ

# Admin email for notifications
ADMIN_EMAIL=michael.murray@fynsor.com
```

### Measurement ID Location

- **Production**: Uses the configured measurement ID
- **Development**: Analytics completely disabled
- **Environment Check**: Only loads scripts in production

## Event Tracking Details

### 1. Contact Form Submissions

**Event Name**: `generate_lead`

**Parameters**:
- `currency`: 'USD'
- `value`: Estimated lead value based on investment size
- `has_company`: Boolean indicating if company provided
- `has_phone`: Boolean indicating if phone provided
- `property_type`: Selected property type or 'not_specified'
- `investment_size`: Selected investment range or 'not_specified'
- `message_length`: Length of message field
- `form_completion_time`: Time taken to complete form

**Lead Value Mapping**:
```typescript
'under-1m': $500
'1m-5m': $1,000
'5m-10m': $2,000
'10m-25m': $5,000
'25m-50m': $10,000
'50m-100m': $20,000
'over-100m': $50,000
```

### 2. Form Engagement

**Event Name**: `form_start`

**Triggered**: When user first focuses on any form field

**Parameters**:
- `event_category`: 'engagement'
- `first_field`: Name of the first field focused

### 3. Button Clicks

**Event Name**: `click`

**Parameters**:
- `event_category`: 'engagement'
- `event_label`: Button name/identifier
- `page_location`: Current page URL

### 4. Page Views

**Event Name**: `page_view`

**Auto-tracked**: On route changes in Next.js

**Parameters**:
- `page_title`: Document title
- `page_location`: Full URL
- `page_path`: URL pathname

## Privacy & Data Protection

### Data Anonymization
- **IP Addresses**: Automatically anonymized
- **Personal Information**: Removed from all tracked events
- **Message Content**: Not tracked, only message length
- **Contact Details**: Not included in analytics data

### GDPR Compliance Features
- **Explicit Consent**: Required before any tracking
- **Consent Storage**: Preferences saved locally
- **Opt-out Option**: Users can decline analytics
- **Data Minimization**: Only essential business metrics tracked

### Tracked vs. Not Tracked

**✅ Tracked (Safe)**:
- Property type interest
- Investment size ranges
- Form interaction patterns
- Page navigation
- Time on site
- Scroll depth

**❌ Not Tracked (Private)**:
- Names
- Email addresses
- Phone numbers
- Company names
- Message content
- Any personally identifiable information

## Usage Examples

### Track Custom Events

```typescript
import { trackEvent } from '@/lib/gtag';

// Track service page interaction
trackEvent('service_view', {
  service_name: 'financial_modeling',
  investment_focus: 'office_buildings'
});
```

### Track CRE-Specific Events

```typescript
import { trackCREEvent } from '@/lib/gtag';

// Track property type interest
trackCREEvent('property_interest', {
  property_type: 'multifamily',
  page_section: 'services_overview'
});
```

### Track Downloads

```typescript
import { trackDownload } from '@/lib/gtag';

// Track whitepaper downloads
trackDownload('cre_market_analysis_2024.pdf', 'whitepaper');
```

## Benefits for Fynsor

### Lead Quality Insights
- **Investment Size Distribution**: Understand prospect portfolio sizes
- **Property Type Preferences**: Identify most popular CRE sectors
- **Geographic Patterns**: Analyze visitor locations and timing
- **Form Conversion Rates**: Optimize contact form performance

### Marketing Optimization
- **Content Performance**: Track which pages drive conversions
- **User Journey Analysis**: Understand path to contact form
- **Engagement Metrics**: Identify high-value content
- **Campaign Attribution**: Measure marketing channel effectiveness

### Business Intelligence
- **Lead Scoring**: Automatic qualification based on investment size
- **Market Trends**: Track changing property type interests
- **Conversion Funnels**: Optimize prospect experience
- **ROI Measurement**: Connect website traffic to business results

## Compliance Notes

### Legal Requirements Met
- **GDPR Article 6**: Lawful basis for processing (consent)
- **GDPR Article 7**: Conditions for consent (explicit, informed)
- **CCPA**: Consumer choice and transparency
- **Privacy by Design**: Built-in privacy protections

### Data Retention
- **Google Analytics**: Standard 26-month retention
- **Consent Records**: Stored locally, no server transmission
- **Event Data**: Anonymized, no personal identifiers

## Testing & Verification

### Development Mode
```bash
# Check if analytics is disabled in development
npm run dev
# Console should show: "Google Analytics disabled in development mode"
```

### Production Mode
```bash
# Verify analytics in production
npm run build && npm start
# Should load GA scripts and show consent banner
```

### Debug Analytics
```typescript
import { debugGA } from '@/lib/gtag';

// In browser console (development only)
debugGA();
```

## Monitoring & Maintenance

### Regular Checks
1. **Consent Rate**: Monitor banner acceptance rate
2. **Event Tracking**: Verify custom events in GA dashboard
3. **Lead Values**: Ensure conversion tracking accuracy
4. **Privacy Compliance**: Regular privacy policy updates

### GA4 Dashboard Setup
1. **Custom Events**: Configure form submission tracking
2. **Conversion Goals**: Set up lead generation conversions
3. **Audience Segments**: Create CRE investor audiences
4. **Attribution Models**: Track marketing channel performance

## Troubleshooting

### Common Issues

**No events showing in GA**:
- Check if user consented to analytics
- Verify production environment
- Confirm measurement ID is correct

**Consent banner not showing**:
- Clear localStorage
- Check if consent already given
- Verify production environment

**Form tracking not working**:
- Ensure form submission successful
- Check browser console for errors
- Verify gtag functions available

### Debug Commands

```typescript
// Check consent status
localStorage.getItem('ga-consent')

// Clear consent (test banner)
localStorage.removeItem('ga-consent')

// Verify GA loaded
typeof window.gtag === 'function'
```

## Future Enhancements

### Planned Features
- **A/B Testing**: Form optimization experiments
- **Heatmaps**: User interaction visualization
- **Lead Scoring**: Enhanced qualification metrics
- **Custom Dimensions**: CRE-specific data points

### Integration Opportunities
- **CRM Connection**: Sync GA data with Supabase
- **Marketing Automation**: Trigger campaigns based on behavior
- **Reporting Dashboard**: Custom analytics for team
- **API Integration**: Enhanced lead intelligence

This implementation provides institutional-grade analytics while maintaining strict privacy compliance for high-value commercial real estate prospects.