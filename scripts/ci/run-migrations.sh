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
    
    # Check if DATABASE_URL is set
    if [[ -z "${DATABASE_URL:-}" ]]; then
        log_error "Required environment variable not set: DATABASE_URL"
        return 1
    fi
    
    log_info "Using DATABASE_URL for connection"
    
    # Set migration directory
    MIGRATION_DIR="${MIGRATION_DIR:-./migrations}"
    
    if [[ ! -d "$MIGRATION_DIR" ]]; then
        log_error "Migration directory not found: $MIGRATION_DIR"
        return 1
    fi
    
    log_info "Running migrations from: $MIGRATION_DIR"
    
    # Run each migration file in order (001, 002, 003, 004, 005)
    migration_count=0
    for migration in "$MIGRATION_DIR"/*.sql; do
        if [[ -f "$migration" ]]; then
            log_info "Running migration: $(basename "$migration")"
            psql "$DATABASE_URL" -f "$migration"
            migration_count=$((migration_count + 1))
        fi
    done
    
    if [[ $migration_count -eq 0 ]]; then
        log_info "No migration files found in $MIGRATION_DIR"
    else
        log_success "Applied $migration_count migrations successfully"
    fi
    
    log_success "Database migrations completed for identity-service"
}

main "$@"