#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Database Migrations Script - identity-service
# ==============================================================================
# Runs database migrations for identity-service
# Used by ArgoCD PreSync hooks and CI workflows
# ==============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

main() {
    log_info "Starting database migrations for identity-service..."
    
    # Validate required environment variables
    if [[ -z "${DATABASE_URL:-}" ]]; then
        log_error "Required environment variable not set: DATABASE_URL"
        return 1
    fi
    
    log_info "Database connection configured via DATABASE_URL"
    
    # Set migration directory
    MIGRATION_DIR="${MIGRATION_DIR:-/app/migrations}"
    
    if [[ ! -d "$MIGRATION_DIR" ]]; then
        log_error "Migration directory not found: $MIGRATION_DIR"
        return 1
    fi
    
    log_info "Running migrations from: $MIGRATION_DIR"
    
    # Run Node.js migration script
    log_info "Executing TypeScript migration runner..."
    npm run migrate
    
    log_success "Database migrations completed for identity-service"
}

main "$@"