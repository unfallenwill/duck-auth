/**
 * Simple in-memory token-bucket rate limiter.
 *
 * ⚠️  SECURITY WARNING — X-Forwarded-For trust model
 *     This limiter relies on the `X-Forwarded-For` / `X-Real-IP` headers
 *     for client identification. In a **direct** deployment (no reverse
 *     proxy) an attacker can trivially forge these headers and bypass every
 *     rate limit.
 *
 *     This module MUST be deployed behind a trusted reverse proxy (nginx,
 *     Caddy, Cloudflare, etc.) that **overwrites** the XFF header from
 *     upstream clients. See README → "Production Deployment" for details.
 *
 * Per RFC 6749 §5.1 + RFC 7009 §5, the authorization server MUST protect
 * its endpoints from abuse. This is a basic implementation suitable for a
 * single-process deployment. For multi-instance / serverless, replace with
 * a Redis-backed limiter (e.g. @upstash/ratelimit).
 *
 * Default buckets:
 *   - /oauth/token: 20 req/minute per (IP, client_id)
 *   - /oauth/revoke: 30 req/minute per IP
 *   - /api/auth/login-post: 5 req/minute per IP
 *   - /oauth/authorize: 30 req/minute per IP
 */

interface Bucket {
  tokens: number;
  lastRefill: number; // epoch ms
}

interface LimiterConfig {
  capacity: number;     // max tokens
  refillPerMs: number;  // tokens added per ms (capacity / windowMs)
}

// Shared buckets store — pinned to globalThis so it survives Next.js
// module re-evaluation / route-level code splitting.
const globalForBuckets = globalThis as unknown as {
  __oauthRateLimitBuckets?: Map<string, Bucket>;
};
const buckets =
  globalForBuckets.__oauthRateLimitBuckets ?? new Map<string, Bucket>();
if (process.env["NODE_ENV"] !== "production") {
  globalForBuckets.__oauthRateLimitBuckets = buckets;
}

function take(key: string, cfg: LimiterConfig): boolean {
  const now = Date.now();
  const elapsed = now - (buckets.get(key)?.lastRefill ?? now);
  const refill = elapsed * cfg.refillPerMs;
  const current: Bucket = buckets.get(key) ?? {
    tokens: cfg.capacity,
    lastRefill: now,
  };
  current.tokens = Math.min(cfg.capacity, current.tokens + refill);
  current.lastRefill = now;
  if (current.tokens < 1) {
    buckets.set(key, current);
    return false;
  }
  current.tokens -= 1;
  buckets.set(key, current);
  return true;
}

function clientKey(req: Request, form: URLSearchParams | null): string {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown";
  const clientId = form?.get("client_id") ?? "anon";
  return `${ip}::${clientId}`;
}

function ipKey(req: Request): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

/** Token endpoint: 20 req/minute per (IP, client_id). */
export function tokenRateLimit(req: Request, form: URLSearchParams): boolean {
  const cfg: LimiterConfig = {
    capacity: 20,
    refillPerMs: 20 / 60_000,
  };
  return take(`token::${clientKey(req, form)}`, cfg);
}

/** Revoke endpoint: 30 req/minute per IP. */
export function revokeRateLimit(req: Request): boolean {
  const cfg: LimiterConfig = {
    capacity: 30,
    refillPerMs: 30 / 60_000,
  };
  return take(`revoke::${ipKey(req)}`, cfg);
}

/** Register endpoint: 5 req/minute per IP. */
export function registerRateLimit(req: Request): boolean {
  const cfg: LimiterConfig = {
    capacity: 5,
    refillPerMs: 5 / 60_000,
  };
  return take(`register::${ipKey(req)}`, cfg);
}

/** Login endpoint: 5 req/minute per IP. */
export function loginRateLimit(req: Request): boolean {
  const cfg: LimiterConfig = {
    capacity: 5,
    refillPerMs: 5 / 60_000,
  };
  return take(`login::${ipKey(req)}`, cfg);
}

/** Authorize endpoint: 30 req/minute per IP. */
export function authorizeRateLimit(req: Request): boolean {
  const cfg: LimiterConfig = {
    capacity: 30,
    refillPerMs: 30 / 60_000,
  };
  return take(`authorize::${ipKey(req)}`, cfg);
}

/** Reset all buckets (for tests). */
export function _resetRateLimit(): void {
  buckets.clear();
}