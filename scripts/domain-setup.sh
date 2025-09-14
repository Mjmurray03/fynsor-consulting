#!/bin/bash

# =============================================================================
# FYNSOR CONSULTING - DOMAIN SETUP AUTOMATION SCRIPT
# =============================================================================
# This script automates the domain setup process for fynsor.com
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="fynsor.com"
WWW_DOMAIN="www.fynsor.com"
VERCEL_A_RECORD="76.76.19.61"
VERCEL_CNAME="cname.vercel-dns.com"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if Vercel CLI is installed
    if ! command -v vercel &> /dev/null; then
        error "Vercel CLI is not installed. Please install it first: npm install -g vercel"
    fi

    # Check if dig is available
    if ! command -v dig &> /dev/null; then
        warning "dig command not found. DNS checks will be limited."
    fi

    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        error "curl command not found. Please install curl."
    fi

    success "Prerequisites check passed"
}

# Login to Vercel
login_vercel() {
    log "Checking Vercel authentication..."

    if vercel whoami &> /dev/null; then
        success "Already logged in to Vercel as $(vercel whoami)"
    else
        log "Please login to Vercel..."
        vercel login
        success "Logged in to Vercel"
    fi
}

# Add domain to Vercel
add_domain_to_vercel() {
    log "Adding domain to Vercel..."

    # Add primary domain
    if vercel domains add "$DOMAIN" 2>/dev/null; then
        success "Added $DOMAIN to Vercel"
    else
        warning "Domain $DOMAIN may already be added or there was an error"
    fi

    # Add www subdomain
    if vercel domains add "$WWW_DOMAIN" 2>/dev/null; then
        success "Added $WWW_DOMAIN to Vercel"
    else
        warning "Domain $WWW_DOMAIN may already be added or there was an error"
    fi

    # Get verification record
    log "Getting domain verification record..."
    echo "Please add the following TXT record to your DNS:"
    echo "Name: _vercel"
    echo "Value: [Check Vercel dashboard for the verification code]"
    echo ""
    echo "Vercel Dashboard: https://vercel.com/dashboard"
}

# Check DNS records
check_dns_records() {
    log "Checking DNS records..."

    if command -v dig &> /dev/null; then
        echo ""
        log "Current DNS records for $DOMAIN:"

        # Check A record
        A_RECORD=$(dig +short "$DOMAIN" A)
        if [ -n "$A_RECORD" ]; then
            echo "A Record: $A_RECORD"
            if [ "$A_RECORD" = "$VERCEL_A_RECORD" ]; then
                success "A record is correctly configured"
            else
                warning "A record does not match Vercel's IP: $VERCEL_A_RECORD"
            fi
        else
            warning "No A record found for $DOMAIN"
        fi

        # Check CNAME record for www
        CNAME_RECORD=$(dig +short "$WWW_DOMAIN" CNAME)
        if [ -n "$CNAME_RECORD" ]; then
            echo "CNAME Record (www): $CNAME_RECORD"
            if [[ "$CNAME_RECORD" == *"vercel-dns.com"* ]]; then
                success "CNAME record is correctly configured"
            else
                warning "CNAME record does not point to Vercel"
            fi
        else
            warning "No CNAME record found for $WWW_DOMAIN"
        fi

        # Check TXT records
        TXT_RECORDS=$(dig +short "$DOMAIN" TXT)
        if [ -n "$TXT_RECORDS" ]; then
            echo "TXT Records:"
            echo "$TXT_RECORDS"
        fi

        echo ""
    else
        warning "Cannot check DNS records without dig command"
    fi
}

# Display required DNS records
display_dns_requirements() {
    echo ""
    log "Required DNS records for your domain registrar:"
    echo ""
    echo -e "${YELLOW}Root Domain (A Record):${NC}"
    echo "Type: A"
    echo "Name: @ (or leave empty)"
    echo "Value: $VERCEL_A_RECORD"
    echo "TTL: 300"
    echo ""
    echo -e "${YELLOW}WWW Subdomain (CNAME Record):${NC}"
    echo "Type: CNAME"
    echo "Name: www"
    echo "Value: $VERCEL_CNAME"
    echo "TTL: 300"
    echo ""
    echo -e "${YELLOW}Domain Verification (TXT Record):${NC}"
    echo "Type: TXT"
    echo "Name: _vercel"
    echo "Value: [Get from Vercel dashboard]"
    echo "TTL: 300"
    echo ""
}

# Test SSL certificate
test_ssl() {
    log "Testing SSL certificate..."

    if curl -I "https://$DOMAIN" &> /dev/null; then
        success "SSL certificate is working for $DOMAIN"

        # Check security headers
        log "Checking security headers..."
        HEADERS=$(curl -I "https://$DOMAIN" 2>/dev/null)

        if echo "$HEADERS" | grep -qi "strict-transport-security"; then
            success "HSTS header is present"
        else
            warning "HSTS header is missing"
        fi

        if echo "$HEADERS" | grep -qi "x-frame-options"; then
            success "X-Frame-Options header is present"
        else
            warning "X-Frame-Options header is missing"
        fi

        if echo "$HEADERS" | grep -qi "content-security-policy"; then
            success "CSP header is present"
        else
            warning "Content-Security-Policy header is missing"
        fi
    else
        warning "SSL certificate test failed or site is not accessible"
    fi
}

# Test domain aliases
test_domain_aliases() {
    log "Testing domain aliases..."

    # Test primary domain
    if curl -I "https://$DOMAIN" &> /dev/null; then
        success "$DOMAIN is accessible"
    else
        warning "$DOMAIN is not accessible"
    fi

    # Test www domain
    if curl -I "https://$WWW_DOMAIN" &> /dev/null; then
        success "$WWW_DOMAIN is accessible"
    else
        warning "$WWW_DOMAIN is not accessible"
    fi

    # Test redirect from www to non-www
    WWW_REDIRECT=$(curl -I "https://$WWW_DOMAIN" 2>/dev/null | grep -i location | cut -d' ' -f2 | tr -d '\r')
    if [[ "$WWW_REDIRECT" == "https://$DOMAIN"* ]]; then
        success "WWW redirect is working correctly"
    else
        warning "WWW redirect may not be configured correctly"
    fi
}

# Set up domain aliases
setup_domain_aliases() {
    log "Setting up domain aliases..."

    # Get current deployment URL
    DEPLOYMENT_URL=$(vercel ls --scope="$(vercel whoami)" | grep "$PROJECT_NAME" | head -1 | awk '{print $2}')

    if [ -z "$DEPLOYMENT_URL" ]; then
        warning "Could not find deployment URL. Please set up aliases manually."
        return
    fi

    # Set up aliases
    log "Setting up aliases for $DEPLOYMENT_URL..."

    if vercel alias "$DEPLOYMENT_URL" "$DOMAIN"; then
        success "Alias created: $DEPLOYMENT_URL -> $DOMAIN"
    else
        warning "Failed to create alias for $DOMAIN"
    fi

    if vercel alias "$DEPLOYMENT_URL" "$WWW_DOMAIN"; then
        success "Alias created: $DEPLOYMENT_URL -> $WWW_DOMAIN"
    else
        warning "Failed to create alias for $WWW_DOMAIN"
    fi
}

# Generate DNS record file
generate_dns_file() {
    log "Generating DNS record file..."

    cat > dns-records.txt << EOF
# DNS Records for $DOMAIN
# Generated on $(date)

# A Record (Root Domain)
Type: A
Name: @
Value: $VERCEL_A_RECORD
TTL: 300

# CNAME Record (WWW Subdomain)
Type: CNAME
Name: www
Value: $VERCEL_CNAME
TTL: 300

# TXT Record (Domain Verification)
Type: TXT
Name: _vercel
Value: [Get verification code from Vercel dashboard]
TTL: 300

# Optional: CAA Records (Certificate Authority Authorization)
Type: CAA
Name: @
Value: 0 issue "letsencrypt.org"
TTL: 3600

Type: CAA
Name: @
Value: 0 issuewild "letsencrypt.org"
TTL: 3600

# Optional: Security TXT Record
Type: TXT
Name: @
Value: v=spf1 -all
TTL: 3600

EOF

    success "DNS records saved to dns-records.txt"
}

# Main function
main() {
    echo -e "${BLUE}"
    echo "============================================================================="
    echo "                    FYNSOR CONSULTING - DOMAIN SETUP"
    echo "============================================================================="
    echo -e "${NC}"
    echo "Domain: $DOMAIN"
    echo "WWW Domain: $WWW_DOMAIN"
    echo ""

    check_prerequisites
    login_vercel

    echo ""
    echo "Choose an option:"
    echo "1. Add domain to Vercel"
    echo "2. Check DNS records"
    echo "3. Display required DNS records"
    echo "4. Test SSL and security headers"
    echo "5. Test domain aliases"
    echo "6. Set up domain aliases"
    echo "7. Generate DNS record file"
    echo "8. Full setup (options 1, 3, 7)"
    echo "9. Full test (options 2, 4, 5)"
    echo ""
    read -p "Enter your choice (1-9): " -n 1 -r
    echo

    case $REPLY in
        1)
            add_domain_to_vercel
            ;;
        2)
            check_dns_records
            ;;
        3)
            display_dns_requirements
            ;;
        4)
            test_ssl
            ;;
        5)
            test_domain_aliases
            ;;
        6)
            setup_domain_aliases
            ;;
        7)
            generate_dns_file
            ;;
        8)
            add_domain_to_vercel
            display_dns_requirements
            generate_dns_file
            ;;
        9)
            check_dns_records
            test_ssl
            test_domain_aliases
            ;;
        *)
            error "Invalid option selected"
            ;;
    esac

    echo ""
    echo -e "${GREEN}"
    echo "============================================================================="
    echo "                         DOMAIN SETUP COMPLETED!"
    echo "============================================================================="
    echo -e "${NC}"
    echo "Next steps:"
    echo "1. Configure DNS records with your domain registrar"
    echo "2. Wait for DNS propagation (24-48 hours)"
    echo "3. Verify domain in Vercel dashboard"
    echo "4. Test the live site"
    echo ""
    echo "Useful links:"
    echo "- Vercel Dashboard: https://vercel.com/dashboard"
    echo "- DNS Checker: https://dnschecker.org/"
    echo "- SSL Test: https://www.ssllabs.com/ssltest/"
    echo "- Security Headers: https://securityheaders.com/"
    echo ""
}

# Run main function
main "$@"