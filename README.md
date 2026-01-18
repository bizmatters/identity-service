# Identity Service

Platform Dashboard Authentication Service for ZeroTouch platform.

## Overview

The Identity Service implements a Trust Broker architecture providing secure, vendor-agnostic authentication using AWS Cognito as an OIDC provider.

## Technology Stack

- **Runtime:** Node.js 20 LTS
- **Framework:** Fastify 4.x
- **Database:** Kysely (type-safe SQL) + pg driver
- **Cache:** ioredis (Dragonfly/Redis)
- **OIDC:** openid-client
- **JWT:** jsonwebtoken
- **Validation:** @sinclair/typebox

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Build
npm run build

# Run tests
npm test

# Run integration tests
npm run test:integration

# Lint
npm run lint

# Format
npm run format
```

## Configuration

All configuration is provided via environment variables. See `ci/config.yaml` for required variables.

## Architecture

See design document at: `bizmatters/.kiro/specs/platform/in-progress/manus-scale/phase0-authentication/00-platform-login/design.md`
