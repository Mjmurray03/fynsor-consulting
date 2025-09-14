#!/bin/bash

# =============================================================================
# FYNSOR CONSULTING - VERCEL DEPLOYMENT SCRIPT
# =============================================================================
# This script handles the complete deployment of Fynsor Consulting to Vercel
# with institutional-grade production configuration.
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="fynsor-consulting"
DOMAIN="fynsor.com"
STAGING_DOMAIN="fynsor-staging.vercel.app"

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

    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        error "Node.js is not installed. Please install Node.js 18 or later."
    fi

    # Check Node.js version
    NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        error "Node.js version 18 or later is required. Current version: $(node --version)"
    fi

    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        error "package.json not found. Please run this script from the project root."
    fi

    # Check if vercel.json exists
    if [ ! -f "vercel.json" ]; then
        error "vercel.json not found. Please ensure the deployment configuration is in place."
    fi

    success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    log "Setting up environment..."

    # Check if .env.example exists
    if [ ! -f ".env.example" ]; then
        warning ".env.example not found. Creating basic template..."
        cat > .env.example << EOF
# Vercel Environment Variables
NEXT_PUBLIC_SITE_URL=https://fynsor.com
NEXTAUTH_SECRET=your-secret-here
DATABASE_URL=your-database-url-here
EOF
    fi

    # Ensure all necessary environment variables are documented
    log "Environment setup complete"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."

    if [ -f "package-lock.json" ]; then
        npm ci
    else
        npm install
    fi

    success "Dependencies installed"
}

# Run security checks
run_security_checks() {
    log "Running security checks..."

    # Audit dependencies
    npm audit --audit-level high || {
        warning "Security vulnerabilities found in dependencies"
        npm audit fix --force || warning "Could not automatically fix all vulnerabilities"
    }

    # Check for secrets in code (if tools are available)
    if command -v gitleaks &> /dev/null; then
        gitleaks detect --no-git || warning "Potential secrets detected"
    fi

    success "Security checks completed"
}

# Build and test
build_and_test() {
    log "Building and testing application..."

    # Run tests if available
    if npm run test --silent 2>/dev/null; then
        log "Running tests..."
        npm test -- --watchAll=false --coverage=false
    fi

    # Build application
    log "Building application..."
    npm run build

    # Check build output
    if [ ! -d ".next" ]; then
        error "Build failed - .next directory not found"
    fi

    success "Build and test completed"
}

# Login to Vercel
login_vercel() {
    log "Checking Vercel authentication..."

    # Check if already logged in
    if vercel whoami &> /dev/null; then
        success "Already logged in to Vercel"
        return
    fi

    # Login required
    log "Please login to Vercel..."
    vercel login

    success "Logged in to Vercel"
}

# Initialize Vercel project
init_vercel_project() {
    log "Initializing Vercel project..."

    # Check if project is already linked
    if [ -f ".vercel/project.json" ]; then
        log "Project already linked to Vercel"
        return
    fi

    # Link or create project
    vercel link --yes || {
        log "Creating new Vercel project..."
        vercel --name "$PROJECT_NAME" --yes
    }

    success "Vercel project initialized"
}

# Configure environment variables
configure_env_vars() {
    log "Configuring environment variables..."

    # List of required environment variables
    REQUIRED_VARS=(
        "NEXTAUTH_SECRET"
        "DATABASE_URL"
        "NEXT_PUBLIC_SITE_URL"
    )

    warning "Please ensure the following environment variables are set in your Vercel dashboard:"
    for var in "${REQUIRED_VARS[@]}"; do
        echo "  - $var"
    done

    log "You can set them using: vercel env add [name]"
    log "Or through the Vercel dashboard: https://vercel.com/dashboard"

    read -p "Have you configured all required environment variables? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        warning "Please configure environment variables before continuing"
        exit 0
    fi
}

# Deploy to staging
deploy_staging() {
    log "Deploying to staging..."

    # Deploy to preview environment
    STAGING_URL=$(vercel deploy --yes)

    if [ -z "$STAGING_URL" ]; then
        error "Staging deployment failed"
    fi

    success "Staging deployed to: $STAGING_URL"

    # Run basic health checks
    log "Running staging health checks..."
    sleep 10  # Wait for deployment to be ready

    if curl -f "$STAGING_URL/api/health" &> /dev/null; then
        success "Staging health check passed"
    else
        warning "Staging health check failed - please verify manually"
    fi

    echo "Staging URL: $STAGING_URL"
}

# Deploy to production
deploy_production() {
    log "Deploying to production..."

    # Confirm production deployment
    echo -e "${YELLOW}You are about to deploy to PRODUCTION.${NC}"
    echo "Domain: $DOMAIN"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Production deployment cancelled"
        exit 0
    fi

    # Deploy to production
    PRODUCTION_URL=$(vercel deploy --prod --yes)

    if [ -z "$PRODUCTION_URL" ]; then
        error "Production deployment failed"
    fi

    success "Production deployed to: $PRODUCTION_URL"

    # Configure custom domain if not already set
    log "Configuring custom domain..."
    vercel domains add "$DOMAIN" || warning "Domain may already be configured"
    vercel alias "$PRODUCTION_URL" "$DOMAIN" || warning "Alias may already be set"

    # Run production health checks
    log "Running production health checks..."
    sleep 30  # Wait for deployment to be ready

    # Health check endpoints
    HEALTH_ENDPOINTS=(
        "https://$DOMAIN"
        "https://$DOMAIN/api/health"
        "https://$DOMAIN/sitemap.xml"
        "https://$DOMAIN/robots.txt"
    )

    for endpoint in "${HEALTH_ENDPOINTS[@]}"; do
        if curl -f "$endpoint" &> /dev/null; then
            success "Health check passed: $endpoint"
        else
            warning "Health check failed: $endpoint"
        fi
    done

    # Security headers check
    log "Checking security headers..."
    SECURITY_HEADERS=(
        "strict-transport-security"
        "x-frame-options"
        "x-content-type-options"
        "content-security-policy"
    )

    for header in "${SECURITY_HEADERS[@]}"; do
        if curl -I "https://$DOMAIN" 2>/dev/null | grep -qi "$header"; then
            success "Security header present: $header"
        else
            warning "Security header missing: $header"
        fi
    done

    success "Production deployment completed successfully!"
    echo -e "${GREEN}🎉 Your site is live at: https://$DOMAIN${NC}"
}

# Configure monitoring
setup_monitoring() {
    log "Setting up monitoring..."

    # Vercel Analytics
    log "Vercel Analytics should be enabled in your dashboard"

    # Performance monitoring
    log "Consider setting up:"
    echo "  - Vercel Analytics (https://vercel.com/analytics)"
    echo "  - Sentry for error tracking"
    echo "  - LogRocket for session replay"
    echo "  - Google Analytics for user analytics"

    success "Monitoring setup guidance provided"
}

# Main deployment function
main() {
    echo -e "${BLUE}"
    echo "============================================================================="
    echo "                    FYNSOR CONSULTING - VERCEL DEPLOYMENT"
    echo "============================================================================="
    echo -e "${NC}"

    check_prerequisites
    setup_environment
    install_dependencies
    run_security_checks
    build_and_test
    login_vercel
    init_vercel_project
    configure_env_vars

    # Deployment options
    echo
    echo "Deployment Options:"
    echo "1. Deploy to staging only"
    echo "2. Deploy to staging and production"
    echo "3. Deploy to production only"
    echo
    read -p "Choose deployment option (1-3): " -n 1 -r
    echo

    case $REPLY in
        1)
            deploy_staging
            ;;
        2)
            deploy_staging
            deploy_production
            ;;
        3)
            deploy_production
            ;;
        *)
            error "Invalid option selected"
            ;;
    esac

    setup_monitoring

    echo
    echo -e "${GREEN}"
    echo "============================================================================="
    echo "                          DEPLOYMENT COMPLETED!"
    echo "============================================================================="
    echo -e "${NC}"
    echo "Production URL: https://$DOMAIN"
    echo "Vercel Dashboard: https://vercel.com/dashboard"
    echo
    echo "Next steps:"
    echo "  1. Verify all functionality on the live site"
    echo "  2. Set up monitoring and analytics"
    echo "  3. Configure custom domain DNS (if not already done)"
    echo "  4. Review security headers and SSL configuration"
    echo "  5. Set up automated backups"
    echo
}

# Run main function
main "$@"