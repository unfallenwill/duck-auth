# OAuth 2.0 + OIDC Server

Standard OAuth 2.0 Authorization Code Flow + PKCE + OpenID Connect, implemented
inside this Next.js app via App Router route handlers and Prisma + SQLite.

## What's implemented

| Endpoint | Spec | Notes |
|---|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery | All metadata |
| `GET /oauth/jwks` | RFC 7517 | Public JWKS for token verification |
| `POST /oauth/register` | RFC 7591 | Dynamic client registration; secret shown ONCE |
| `GET /oauth/authorize` | RFC 6749 §4.1.1 + RFC 7636 | Auth code + PKCE S256 |
| `POST /oauth/token` | RFC 6749 §4.1.3 + §6 | `authorization_code` + `refresh_token` grants |
| `GET /oauth/userinfo` | OIDC Core §5.3 | Returns claims per scope |
| `POST /oauth/revoke` | RFC 7009 | Revoke access + refresh tokens |

## Security properties

- **PKCE (S256 only)** — required; `plain` not accepted (deprecated).
- **state parameter** — required; client must echo back to /callback.
- **One-time auth codes** — DB-marked `usedAt`, TTL 10 min.
- **Refresh token rotation** — old token revoked when new one issued.
- **Access token revocation** — DB-tracked by `jti`, checked on every /userinfo.
- **Client secret** — hashed (scrypt) at rest; never returned after registration.
- **Session cookie** — HMAC-signed (HS256), httpOnly, SameSite=Lax, Secure in prod.
- **Redirect URI** — exact-match against registered list.
- **Scope** — validated against client's allowed scopes; unknown scopes rejected.

## Demo Client (self-test)

The same app also implements a demo OAuth client at `/api/auth/*`:

- `GET /api/auth/login` — generates state + PKCE pair, redirects to /oauth/authorize
- `GET /api/auth/callback` — exchanges code for tokens, stores in httpOnly cookies
- `GET /api/auth/me` — fetches userinfo server-side using stored access_token
- `POST /api/auth/logout` — revokes tokens, clears cookies

Visit `/` to use the demo flow:
1. Click "Use OAuth Server to log in"
2. Log in with seeded credentials (`alice@example.com` / `alice-password`)
3. Approve the consent page
4. See your userinfo displayed on the home page

## Scripts

```bash
npm run db:migrate    # run Prisma migrations
npm run db:seed       # seed demo user + client
npm run dev           # dev server
npm run build         # production build
npm start             # serve production build (default port 3000)
npm run e2e           # end-to-end OAuth flow test
npm run lint          # ESLint
```

## Schema

- `User` — id, email, passwordHash (scrypt), name
- `Client` — id, name, secretHash, redirectUris (JSON), allowedScopes (space-sep)
- `Consent` — (userId, clientId) unique; scopes; for skipping future prompts
- `AuthorizationCode` — code, clientId, userId, redirectUri, scopes, codeChallenge, expiresAt, usedAt
- `AccessToken` — jti, clientId, userId, scopes, expiresAt, revokedAt
- `RefreshToken` — token, clientId, userId, scopes, expiresAt, revokedAt

## Production caveats

- **Keys**: RS256 keypair is generated fresh on every process start. Persist
  them to disk or KMS in production or all tokens become unverifiable on
  restart.
- **Session secret**: change `OAUTH_SESSION_SECRET` in `.env` to a random 32+ byte string.
- **HTTPS**: `Secure` cookie flag is enabled when `NODE_ENV=production`.
- **Demo flow**: this single app is BOTH the OAuth server and the demo client.
  In a real deployment they would be separate origins.