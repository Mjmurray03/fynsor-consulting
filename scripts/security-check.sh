#!/bin/bash

# =============================================================================
# FYNSOR CONSULTING - SECURITY HEADERS & SSL VERIFICATION SCRIPT
# =============================================================================
# This script verifies SSL configuration and security headers for fynsor.com
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

# Check if site is accessible
check_site_accessibility() {
    log "Checking site accessibility..."

    local url="https://$DOMAIN"

    if curl -s --head "$url" | head -n 1 | grep -q "200 OK"; then
        success "Site is accessible at $url"
        return 0
    else
        error "Site is not accessible at $url"
        return 1
    fi
}

# Check SSL certificate
check_ssl_certificate() {
    log "Checking SSL certificate for $DOMAIN..."

    # Check certificate validity
    if openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        success "SSL certificate is valid"
    else
        warning "SSL certificate verification failed"
    fi

    # Get certificate details
    local cert_info=$(openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -dates)

    if [ -n "$cert_info" ]; then
        echo "Certificate Details:"
        echo "$cert_info"

        # Check expiration
        local expire_date=$(echo "$cert_info" | grep "notAfter" | cut -d'=' -f2)
        local expire_epoch=$(date -d "$expire_date" +%s 2>/dev/null || echo "0")
        local current_epoch=$(date +%s)
        local days_until_expire=$(( (expire_epoch - current_epoch) / 86400 ))

        if [ "$days_until_expire" -gt 30 ]; then
            success "Certificate expires in $days_until_expire days"
        elif [ "$days_until_expire" -gt 7 ]; then
            warning "Certificate expires in $days_until_expire days - consider renewal"
        else
            error "Certificate expires in $days_until_expire days - URGENT renewal needed"
        fi
    fi

    # Check cipher suites
    log "Checking supported cipher suites..."
    local ciphers=$(nmap --script ssl-enum-ciphers -p 443 "$DOMAIN" 2>/dev/null | grep -E "TLS|cipher" | head -10)
    if [ -n "$ciphers" ]; then
        echo "Supported cipher suites (top 10):"
        echo "$ciphers"
    fi
}

# Check security headers
check_security_headers() {
    log "Checking security headers for $DOMAIN..."

    local url="https://$DOMAIN"
    local headers=$(curl -I -s "$url")

    # Required security headers
    local required_headers=(
        "strict-transport-security"
        "x-frame-options"
        "x-content-type-options"
        "content-security-policy"
        "x-xss-protection"
        "referrer-policy"
    )

    echo ""
    echo "Security Headers Check:"
    echo "======================"

    for header in "${required_headers[@]}"; do
        if echo "$headers" | grep -qi "$header"; then
            local value=$(echo "$headers" | grep -i "$header" | cut -d':' -f2- | xargs)
            success "$header: $value"
        else
            error "Missing: $header"
        fi
    done

    # Additional checks for specific headers
    echo ""
    log "Detailed Security Header Analysis:"

    # HSTS Check
    local hsts=$(echo "$headers" | grep -i "strict-transport-security" | cut -d':' -f2- | xargs)
    if [ -n "$hsts" ]; then
        if echo "$hsts" | grep -q "includeSubDomains"; then
            success "HSTS includes subdomains"
        else
            warning "HSTS does not include subdomains"
        fi

        if echo "$hsts" | grep -q "preload"; then
            success "HSTS preload is enabled"
        else
            warning "HSTS preload is not enabled"
        fi

        local max_age=$(echo "$hsts" | grep -o "max-age=[0-9]*" | cut -d'=' -f2)
        if [ "$max_age" -ge 31536000 ]; then
            success "HSTS max-age is adequate (${max_age}s)"
        else
            warning "HSTS max-age is too short (${max_age}s)"
        fi
    fi

    # CSP Check
    local csp=$(echo "$headers" | grep -i "content-security-policy" | cut -d':' -f2-)
    if [ -n "$csp" ]; then
        if echo "$csp" | grep -q "default-src"; then
            success "CSP has default-src directive"
        else
            warning "CSP missing default-src directive"
        fi

        if echo "$csp" | grep -q "script-src"; then
            success "CSP has script-src directive"
        else
            warning "CSP missing script-src directive"
        fi

        if echo "$csp" | grep -q "unsafe-inline"; then
            warning "CSP allows unsafe-inline"
        else
            success "CSP does not allow unsafe-inline"
        fi
    fi

    # X-Frame-Options Check
    local xfo=$(echo "$headers" | grep -i "x-frame-options" | cut -d':' -f2- | xargs)
    if [ -n "$xfo" ]; then
        if echo "$xfo" | grep -qi "deny\|sameorigin"; then
            success "X-Frame-Options is properly configured"
        else
            warning "X-Frame-Options may not be secure: $xfo"
        fi
    fi
}

# Check HTTPS redirection
check_https_redirect() {
    log "Checking HTTPS redirection..."

    local http_url="http://$DOMAIN"
    local https_url="https://$DOMAIN"

    # Check if HTTP redirects to HTTPS
    local redirect_location=$(curl -s -I "$http_url" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')

    if [[ "$redirect_location" == "https://"* ]]; then
        success "HTTP redirects to HTTPS"
    else
        warning "HTTP does not redirect to HTTPS"
    fi

    # Check redirect status code
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$http_url")
    if [ "$status_code" = "301" ] || [ "$status_code" = "302" ]; then
        success "Redirect uses proper status code: $status_code"
    else
        warning "Unexpected redirect status code: $status_code"
    fi
}

# Check for mixed content
check_mixed_content() {
    log "Checking for mixed content issues..."

    local url="https://$DOMAIN"
    local page_content=$(curl -s "$url")

    # Check for HTTP resources in HTTPS page
    local http_resources=$(echo "$page_content" | grep -o 'http://[^"]*' | head -10)

    if [ -n "$http_resources" ]; then
        warning "Potential mixed content found:"
        echo "$http_resources"
    else
        success "No obvious mixed content issues found"
    fi
}

# Check subdomain security
check_subdomain_security() {
    log "Checking subdomain security..."

    local subdomains=("www.$DOMAIN" "api.$DOMAIN" "admin.$DOMAIN")

    for subdomain in "${subdomains[@]}"; do
        if curl -s --head "https://$subdomain" >/dev/null 2>&1; then
            log "Checking $subdomain..."

            local sub_headers=$(curl -I -s "https://$subdomain")
            if echo "$sub_headers" | grep -qi "strict-transport-security"; then
                success "$subdomain has HSTS enabled"
            else
                warning "$subdomain missing HSTS header"
            fi
        else
            log "Subdomain $subdomain is not accessible (this may be expected)"
        fi
    done
}

# Performance security check
check_performance_security() {
    log "Checking performance and security..."

    local url="https://$DOMAIN"

    # Check response time
    local response_time=$(curl -o /dev/null -s -w "%{time_total}" "$url")
    local response_ms=$(echo "$response_time * 1000" | bc 2>/dev/null || echo "unknown")

    if (( $(echo "$response_time < 2.0" | bc -l 2>/dev/null || echo 0) )); then
        success "Response time is good: ${response_ms}ms"
    elif (( $(echo "$response_time < 5.0" | bc -l 2>/dev/null || echo 0) )); then
        warning "Response time is acceptable: ${response_ms}ms"
    else
        warning "Response time is slow: ${response_ms}ms"
    fi

    # Check compression
    local encoding=$(curl -H "Accept-Encoding: gzip" -I -s "$url" | grep -i "content-encoding")
    if echo "$encoding" | grep -qi "gzip"; then
        success "Gzip compression is enabled"
    else
        warning "Gzip compression is not enabled"
    fi

    # Check caching headers
    local cache_control=$(curl -I -s "$url" | grep -i "cache-control")
    if [ -n "$cache_control" ]; then
        success "Cache-Control header present: $(echo $cache_control | cut -d':' -f2- | xargs)"
    else
        warning "Cache-Control header missing"
    fi
}

# Generate security report
generate_security_report() {
    log "Generating security report..."

    local report_file="security-report-$(date +%Y%m%d-%H%M%S).txt"

    cat > "$report_file" << EOF
# Security Report for $DOMAIN
Generated on: $(date)

## SSL Certificate Status
$(openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "Could not retrieve certificate info")

## Security Headers
$(curl -I -s "https://$DOMAIN" | grep -E -i "(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy|x-xss-protection|referrer-policy)")

## HTTPS Redirect Test
HTTP Status: $(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN")
Redirect Location: $(curl -s -I "http://$DOMAIN" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')

## Performance Metrics
Response Time: $(curl -o /dev/null -s -w "%{time_total}s" "https://$DOMAIN")
Content Encoding: $(curl -H "Accept-Encoding: gzip" -I -s "https://$DOMAIN" | grep -i "content-encoding" | cut -d':' -f2- | xargs)

## Recommendations
- Ensure all security headers are properly configured
- Monitor SSL certificate expiration
- Regularly update security policies
- Consider implementing additional security measures like CAA records
- Set up automated security monitoring
EOF

    success "Security report saved to $report_file"
}

# Main security check function
main() {
    echo -e "${BLUE}"
    echo "============================================================================="
    echo "                    FYNSOR CONSULTING - SECURITY CHECK"
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

    # Run all security checks
    check_site_accessibility || exit 1
    echo ""

    check_ssl_certificate
    echo ""

    check_security_headers
    echo ""

    check_https_redirect
    echo ""

    check_mixed_content
    echo ""

    check_subdomain_security
    echo ""

    check_performance_security
    echo ""

    # Generate report
    generate_security_report

    echo ""
    echo -e "${GREEN}"
    echo "============================================================================="
    echo "                         SECURITY CHECK COMPLETED!"
    echo "============================================================================="
    echo -e "${NC}"
    echo "Review the results above and address any warnings or errors."
    echo ""
    echo "Additional tools for comprehensive security testing:"
    echo "- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
    echo "- Security Headers: https://securityheaders.com/?q=https://$DOMAIN"
    echo "- Mozilla Observatory: https://observatory.mozilla.org/analyze/$DOMAIN"
    echo "- HSTS Preload: https://hstspreload.org/?domain=$DOMAIN"
    echo ""
}

# Handle command line options
case "${1:-}" in
    -h|--help)
        echo "Usage: $0 [domain]"
        echo "Example: $0 fynsor.com"
        exit 0
        ;;
    -v|--version)
        echo "Security Check Script v1.0"
        exit 0
        ;;
    *)
        main
        ;;
esac