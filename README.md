# 🦆 duck-auth

A production-grade **OAuth 2.0 + OIDC Server** with a self-contained demo client, built on Next.js 16.

## Features

- **Authorization Code Flow + PKCE (S256)** — RFC 6749 / RFC 7636
- **OIDC Core** — Discovery, JWKS, ID Token, UserInfo
- **Token lifecycle** — Refresh token rotation, revocation (RFC 7009)
- **Dynamic Client Registration** — RFC 7591
- **CAS-protected token redemption** — No TOCTOU races
- **Rate limiting** — Token bucket per IP + client_id
- **94 tests** — Unit (vitest) + E2E (tsx) + Browser (Playwright)

## Stack

- Next.js 16 (App Router, Turbopack)
- Prisma 7 + SQLite (libsql adapter)
- jose (JWT RS256)
- Tailwind v4 + shadcn/ui (Nova preset)
- vitest + Playwright

## Quick Start

```bash
# Install
npm install

# Database
npm run db:migrate
npm run db:seed

# Generate RSA signing keys (persisted to .oauth-keys.json)
npm run db:keys:init

# Dev server
npm run dev

# Production
npm run build && npm start
```

### Demo Credentials

| Item | Value |
|---|---|
| User | `alice@example.com` / `alice-password` |
| Client ID | `demo-client` |
| Client Secret | `demo-secret-change-me` |
| Redirect URI | `http://localhost:3000/api/auth/callback` |

### Environment Variables

```env
DATABASE_URL=file:./dev.db
OAUTH_ISSUER=http://localhost:3000
OAUTH_SESSION_SECRET=<openssl rand -base64 48>
DEMO_CLIENT_ID=demo-client
DEMO_CLIENT_SECRET=demo-secret-change-me
DEMO_REDIRECT_URI=http://localhost:3000/api/auth/callback
```

## Testing

```bash
# Start server first
npm start &

# Unit tests (no server needed)
npm run test:unit

# E2E protocol tests
npm run test:e2e

# Browser tests (real UI clicks)
npm run e2e:playwright

# Everything
npm test && npm run e2e:playwright
```

## Project Structure

```
app/
  oauth/          # OAuth server endpoints (authorize, token, userinfo, jwks, revoke, register)
  api/auth/       # Demo client (login, callback, logout, me)
  api/consent/    # Consent approval/denial route handler
  login/          # Login page
  consent/        # Consent page
  .well-known/    # OIDC discovery
lib/
  oauth/          # Core logic (crypto, jwt, errors, discovery, consent, client-auth, rate-limit, cookies)
  generated/      # Prisma client
e2e/              # Test suites
playwright.config.ts
vitest.config.ts
```

## Production Deployment

1. Set `OAUTH_ISSUER` to your HTTPS URL
2. Set `OAUTH_SESSION_SECRET` to a random 48+ byte string
3. Run `npm run db:keys:init` to generate persistent RSA keys
4. Set up cron: `npm run db:cleanup` daily to purge expired tokens
5. Block `/api/test/rate-reset` at the reverse proxy
6. **Reverse proxy REQUIRED** — The rate limiter identifies clients via the
   `X-Forwarded-For` header. In a direct deployment (no proxy), attackers can
   forge this header to bypass all rate limits. Always deploy behind a trusted
   reverse proxy (nginx, Caddy, Cloudflare, etc.) and ensure it **overwrites**
   (not appends to) the `X-Forwarded-For` header from downstream clients.

   **nginx example:**
   ```nginx
   proxy_set_header X-Forwarded-For $remote_addr;
   ```

   **Caddy example:**
   ```caddyfile
   reverse_proxy localhost:3000 {
     header_up X-Forwarded-For {remote_host}
   }
   ```

## License

MIT 🦆