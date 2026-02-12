# Scoollink Multi-Tenant Auth Foundation

This gateway now enforces:

- Signed access token authentication
- School-level tenant isolation via `school_id`
- Role-based route guards
- Refresh token flow (implemented in `backend-services/auth-service.js`)
- Password hashing and verification using Node crypto (scrypt)

## Environment variables

- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `ACCESS_TOKEN_TTL_MS` (default `900000`)
- `REFRESH_TOKEN_TTL_MS` (default `604800000`)

## Quick preview (no external services required)

```bash
npm run preview:gateway
```

The preview script demonstrates:

1. Valid SchoolAdmin token passes auth + tenant + role checks.
2. Cross-school header mismatch is blocked by tenant middleware.
3. Student token is blocked by SchoolAdmin-only role guard.

## HTTP preview (real endpoint calls)

```bash
npm run preview:http
```

This starts a local HTTP server with protected routes and calls them via `fetch` to show:

1. Allowed admin request on tenant-matching school context.
2. Blocked tenant mismatch request (`403`).
3. Blocked Student role on SchoolAdmin-only route (`403`).

## Run auth service

```bash
node backend-services/auth-service.js
```

## Run API gateway

```bash
node api-gateway/gateway.js
```

## Run tests

```bash
npm run test:gateway
```
