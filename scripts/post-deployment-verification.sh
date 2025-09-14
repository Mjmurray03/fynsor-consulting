#!/bin/bash

# =============================================================================
# FYNSOR CONSULTING - POST-DEPLOYMENT VERIFICATION SCRIPT
# =============================================================================
# This script performs comprehensive verification after deployment
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="${1:-fynsor.com}"
STAGING_DOMAIN="fynsor-staging.vercel.app"

# Test endpoints
ENDPOINTS=(
    "/"
    "/about"
    "/services"
    "/contact"
    "/api/health"
    "/api/monitoring/health"
)

# Expected response times (milliseconds)
MAX_RESPONSE_TIME=3000
IDEAL_RESPONSE_TIME=1500

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

# Increment test counters
pass_test() {
    ((TOTAL_TESTS++))
    ((PASSED_TESTS++))
    success "$1"
}

fail_test() {
    ((TOTAL_TESTS++))
    ((FAILED_TESTS++))
    error "$1"
}

warn_test() {
    ((TOTAL_TESTS++))
    ((WARNING_TESTS++))
    warning "$1"
}

# Test site accessibility
test_site_accessibility() {
    log "Testing site accessibility..."

    for endpoint in "${ENDPOINTS[@]}"; do
        local url="https://$DOMAIN$endpoint"
        local start_time=$(date +%s%3N)

        if curl -s --head --max-time 10 "$url" | head -n 1 | grep -q "200\|301\|302"; then
            local end_time=$(date +%s%3N)
            local response_time=$((end_time - start_time))

            if [ $response_time -le $IDEAL_RESPONSE_TIME ]; then
                pass_test "✓ $endpoint accessible (${response_time}ms)"
            elif [ $response_time -le $MAX_RESPONSE_TIME ]; then
                warn_test "⚠ $endpoint accessible but slow (${response_time}ms)"
            else
                fail_test "✗ $endpoint too slow (${response_time}ms)"
            fi
        else
            fail_test "✗ $endpoint not accessible"
        fi
    done
}

# Test HTTPS enforcement
test_https_enforcement() {
    log "Testing HTTPS enforcement..."

    local http_url="http://$DOMAIN"
    local response=$(curl -s -I --max-time 10 "$http_url")

    if echo "$response" | grep -q "301\|302"; then
        local redirect_location=$(echo "$response" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')
        if [[ "$redirect_location" == "https://"* ]]; then
            pass_test "✓ HTTP redirects to HTTPS"
        else
            fail_test "✗ HTTP does not redirect to HTTPS"
        fi
    else
        fail_test "✗ No HTTP to HTTPS redirect found"
    fi
}

# Test security headers
test_security_headers() {
    log "Testing security headers..."

    local url="https://$DOMAIN"
    local headers=$(curl -I -s --max-time 10 "$url")

    # Required security headers
    local required_headers=(
        "strict-transport-security:HSTS"
        "x-frame-options:X-Frame-Options"
        "x-content-type-options:X-Content-Type-Options"
        "content-security-policy:Content-Security-Policy"
        "referrer-policy:Referrer-Policy"
    )

    for header_check in "${required_headers[@]}"; do
        local header_name=$(echo "$header_check" | cut -d':' -f1)
        local display_name=$(echo "$header_check" | cut -d':' -f2)

        if echo "$headers" | grep -qi "$header_name"; then
            pass_test "✓ $display_name header present"
        else
            fail_test "✗ $display_name header missing"
        fi
    done

    # Check HSTS configuration
    local hsts=$(echo "$headers" | grep -i "strict-transport-security" | cut -d':' -f2-)
    if [ -n "$hsts" ]; then
        if echo "$hsts" | grep -q "includeSubDomains"; then
            pass_test "✓ HSTS includes subdomains"
        else
            warn_test "⚠ HSTS does not include subdomains"
        fi

        if echo "$hsts" | grep -q "preload"; then
            pass_test "✓ HSTS preload enabled"
        else
            warn_test "⚠ HSTS preload not enabled"
        fi
    fi
}

# Test SSL certificate
test_ssl_certificate() {
    log "Testing SSL certificate..."

    # Check certificate validity
    if openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        pass_test "✓ SSL certificate is valid"
    else
        fail_test "✗ SSL certificate validation failed"
    fi

    # Check certificate expiration
    local cert_info=$(openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -dates)
    if [ -n "$cert_info" ]; then
        local expire_date=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2)
        local expire_epoch=$(date -d "$expire_date" +%s 2>/dev/null || echo "0")
        local current_epoch=$(date +%s)
        local days_until_expire=$(( (expire_epoch - current_epoch) / 86400 ))

        if [ "$days_until_expire" -gt 30 ]; then
            pass_test "✓ SSL certificate expires in $days_until_expire days"
        elif [ "$days_until_expire" -gt 7 ]; then
            warn_test "⚠ SSL certificate expires in $days_until_expire days"
        else
            fail_test "✗ SSL certificate expires in $days_until_expire days - URGENT"
        fi
    fi
}

# Test Core Web Vitals
test_core_web_vitals() {
    log "Testing Core Web Vitals..."

    # This would require a more sophisticated setup with Lighthouse CI
    # For now, we'll do basic performance checks

    local url="https://$DOMAIN"
    local start_time=$(date +%s%3N)

    # Download the page and measure time
    local content=$(curl -s --max-time 30 "$url")
    local end_time=$(date +%s%3N)
    local load_time=$((end_time - start_time))

    if [ $load_time -le 2500 ]; then
        pass_test "✓ Page load time: ${load_time}ms (Good)"
    elif [ $load_time -le 4000 ]; then
        warn_test "⚠ Page load time: ${load_time}ms (Needs improvement)"
    else
        fail_test "✗ Page load time: ${load_time}ms (Poor)"
    fi

    # Check if content is compressed
    local content_encoding=$(curl -H "Accept-Encoding: gzip" -I -s "$url" | grep -i "content-encoding")
    if echo "$content_encoding" | grep -qi "gzip"; then
        pass_test "✓ Content compression enabled"
    else
        warn_test "⚠ Content compression not detected"
    fi

    # Check content size
    local content_size=${#content}
    if [ $content_size -lt 100000 ]; then  # Less than 100KB
        pass_test "✓ Page size optimized: ${content_size} bytes"
    elif [ $content_size -lt 500000 ]; then  # Less than 500KB
        warn_test "⚠ Page size acceptable: ${content_size} bytes"
    else
        fail_test "✗ Page size too large: ${content_size} bytes"
    fi
}

# Test API endpoints
test_api_endpoints() {
    log "Testing API endpoints..."

    # Health check endpoint
    local health_url="https://$DOMAIN/api/monitoring/health"
    local health_response=$(curl -s --max-time 10 "$health_url")

    if echo "$health_response" | grep -q '"status":"healthy"'; then
        pass_test "✓ Health check endpoint returns healthy"
    elif echo "$health_response" | grep -q '"status":"degraded"'; then
        warn_test "⚠ Health check endpoint returns degraded"
    else
        fail_test "✗ Health check endpoint not responding correctly"
    fi

    # Analytics endpoint
    local analytics_url="https://$DOMAIN/api/analytics/track"
    local analytics_test='{"type":"test","data":{"test":true}}'

    if curl -s -X POST -H "Content-Type: application/json" -d "$analytics_test" --max-time 10 "$analytics_url" | grep -q '"success":true'; then
        pass_test "✓ Analytics endpoint functioning"
    else
        warn_test "⚠ Analytics endpoint may not be functioning"
    fi
}

# Test mobile responsiveness
test_mobile_responsiveness() {
    log "Testing mobile responsiveness..."

    local url="https://$DOMAIN"
    local mobile_user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"

    local mobile_response=$(curl -s --max-time 10 -H "User-Agent: $mobile_user_agent" "$url")

    # Check for viewport meta tag
    if echo "$mobile_response" | grep -q 'viewport.*width=device-width'; then
        pass_test "✓ Mobile viewport meta tag present"
    else
        fail_test "✗ Mobile viewport meta tag missing"
    fi

    # Check for responsive classes (basic check)
    if echo "$mobile_response" | grep -q -E "(responsive|mobile|sm:|md:|lg:)"; then
        pass_test "✓ Responsive design classes detected"
    else
        warn_test "⚠ Responsive design classes not detected"
    fi
}

# Test SEO basics
test_seo_basics() {
    log "Testing SEO basics..."

    local url="https://$DOMAIN"
    local content=$(curl -s --max-time 10 "$url")

    # Check for title tag
    if echo "$content" | grep -q "<title>.*</title>"; then
        pass_test "✓ Title tag present"
    else
        fail_test "✗ Title tag missing"
    fi

    # Check for meta description
    if echo "$content" | grep -q 'meta.*name="description"'; then
        pass_test "✓ Meta description present"
    else
        fail_test "✗ Meta description missing"
    fi

    # Check for Open Graph tags
    if echo "$content" | grep -q 'meta.*property="og:'; then
        pass_test "✓ Open Graph tags present"
    else
        warn_test "⚠ Open Graph tags missing"
    fi

    # Check for robots.txt
    if curl -s --max-time 10 "https://$DOMAIN/robots.txt" | grep -q "User-agent"; then
        pass_test "✓ Robots.txt accessible"
    else
        fail_test "✗ Robots.txt not accessible"
    fi

    # Check for sitemap
    if curl -s --max-time 10 "https://$DOMAIN/sitemap.xml" | grep -q "<urlset"; then
        pass_test "✓ Sitemap accessible"
    else
        warn_test "⚠ Sitemap not accessible"
    fi
}

# Test form functionality
test_form_functionality() {
    log "Testing form functionality..."

    local contact_url="https://$DOMAIN/contact"
    local contact_page=$(curl -s --max-time 10 "$contact_url")

    # Check if contact form exists
    if echo "$contact_page" | grep -q "<form"; then
        pass_test "✓ Contact form detected"
    else
        fail_test "✗ Contact form not found"
    fi

    # Check for CSRF protection (if forms have tokens)
    if echo "$contact_page" | grep -q -E "(csrf|token|_token)"; then
        pass_test "✓ CSRF protection detected"
    else
        warn_test "⚠ CSRF protection not detected"
    fi
}

# Test monitoring integration
test_monitoring_integration() {
    log "Testing monitoring integration..."

    local url="https://$DOMAIN"
    local content=$(curl -s --max-time 10 "$url")

    # Check for analytics scripts
    if echo "$content" | grep -q -E "(gtag|analytics|ga\(|Google Analytics)"; then
        pass_test "✓ Analytics integration detected"
    else
        warn_test "⚠ Analytics integration not detected"
    fi

    # Check for error tracking
    if echo "$content" | grep -q -E "(sentry|bugsnag|rollbar)"; then
        pass_test "✓ Error tracking integration detected"
    else
        warn_test "⚠ Error tracking integration not detected"
    fi
}

# Generate verification report
generate_verification_report() {
    log "Generating verification report..."

    local report_file="verification-report-$(date +%Y%m%d-%H%M%S).txt"
    local timestamp=$(date)

    cat > "$report_file" << EOF
# Post-Deployment Verification Report
# Fynsor Consulting - $DOMAIN
# Generated: $timestamp

## Summary
Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Warnings: $WARNING_TESTS

## Test Results
$(if [ $FAILED_TESTS -eq 0 ]; then echo "✅ All critical tests passed"; else echo "❌ $FAILED_TESTS tests failed"; fi)
$(if [ $WARNING_TESTS -eq 0 ]; then echo "✅ No warnings"; else echo "⚠️ $WARNING_TESTS warnings require attention"; fi)

## Performance Metrics
$(curl -w "Response Time: %{time_total}s\nDNS Lookup: %{time_namelookup}s\nConnect Time: %{time_connect}s\nSSL Handshake: %{time_appconnect}s\n" -o /dev/null -s "https://$DOMAIN")

## Security Headers
$(curl -I -s "https://$DOMAIN" | grep -E -i "(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy)")

## SSL Certificate
$(openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "Could not retrieve certificate info")

## Recommendations
$(if [ $FAILED_TESTS -gt 0 ]; then echo "- Address failed tests before going live"; fi)
$(if [ $WARNING_TESTS -gt 0 ]; then echo "- Review and resolve warnings for optimal performance"; fi)
- Monitor performance metrics continuously
- Set up automated monitoring alerts
- Schedule regular security audits
- Keep dependencies updated

EOF

    success "Verification report saved to $report_file"
}

# Main verification function
main() {
    echo -e "${BLUE}"
    echo "============================================================================="
    echo "                POST-DEPLOYMENT VERIFICATION - FYNSOR CONSULTING"
    echo "============================================================================="
    echo -e "${NC}"
    echo "Domain: $DOMAIN"
    echo "Timestamp: $(date)"
    echo ""

    # Check prerequisites
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        exit 1
    fi

    if ! command -v openssl &> /dev/null; then
        warning "openssl is recommended but not installed"
    fi

    # Run all verification tests
    test_site_accessibility
    echo ""

    test_https_enforcement
    echo ""

    test_security_headers
    echo ""

    test_ssl_certificate
    echo ""

    test_core_web_vitals
    echo ""

    test_api_endpoints
    echo ""

    test_mobile_responsiveness
    echo ""

    test_seo_basics
    echo ""

    test_form_functionality
    echo ""

    test_monitoring_integration
    echo ""

    # Generate final report
    generate_verification_report

    echo ""
    echo -e "${BLUE}"
    echo "============================================================================="
    echo "                        VERIFICATION COMPLETED!"
    echo "============================================================================="
    echo -e "${NC}"

    echo "Summary:"
    echo "  Total Tests: $TOTAL_TESTS"
    echo "  Passed: $PASSED_TESTS"
    echo "  Failed: $FAILED_TESTS"
    echo "  Warnings: $WARNING_TESTS"
    echo ""

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 All critical tests passed! Site is ready for production.${NC}"
    else
        echo -e "${RED}❌ $FAILED_TESTS tests failed. Please address issues before going live.${NC}"
    fi

    if [ $WARNING_TESTS -gt 0 ]; then
        echo -e "${YELLOW}⚠️ $WARNING_TESTS warnings require attention for optimal performance.${NC}"
    fi

    echo ""
    echo "Next steps:"
    echo "1. Review any failed tests and warnings"
    echo "2. Monitor site performance and uptime"
    echo "3. Set up automated monitoring alerts"
    echo "4. Schedule regular security audits"
    echo ""

    # Return appropriate exit code
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"