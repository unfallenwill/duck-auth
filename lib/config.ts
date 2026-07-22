/**
 * Centralized configuration — single source of truth for all env vars.
 *
 * In production, missing required vars cause a fail-fast at startup.
 * In development, sensible defaults are provided for local dev.
 *
 * All modules should import from here instead of reading process.env directly.
 */
import { z } from "zod";

/**
 * Dev-only fallback for the session-cookie HMAC secret. MUST NOT be used
 * in production — loadConfig() throws if OAUTH_SESSION_SECRET is missing
 * and NODE_ENV=production.
 */
export const SESSION_COOKIE_DEV_FALLBACK =
  "dev-only-change-me-32-bytes-please-please";

const ConfigSchema = z.object({
  issuer: z.string().url().default("http://localhost:3000"),

  sessionSecret: z
    .string()
    .min(32, "OAUTH_SESSION_SECRET must be at least 32 characters"),

  keysPath: z.string().default("./.oauth-keys.json"),

  databaseUrl: z.string().default("file:./dev.db"),

  demoClientId: z.string().default("demo-client"),
  demoClientSecret: z.string().default("demo-secret-change-me"),
  demoRedirectUri: z
    .string()
    .default("http://localhost:3000/api/auth/callback"),

  /**
   * Opt-in legacy JWT session cookie fallback for the Phase 1 → Phase 5
   * production migration window. See issue #37.
   *
   * When `true`, `verifySessionCookie` accepts JWTs signed with
   * `OAUTH_SESSION_SECRET` that lack a `jti` claim (the pre-Phase-1 cookie
   * format). The fallback is signature-only — no DB lookup, no revocation
   * possible for these cookies — but they naturally expire within their
   * own 2h TTL (jose enforces `exp` inside `jwtVerify`).
   *
   * Operators set `OAUTH_SESSION_LEGACY_GRACE=true` during the migration
   * window (so existing users aren't logged out), then unset it after all
   * legacy cookies have expired. Eventually the fallback code itself
   * should be deleted (Phase 6 / cleanup).
   *
   * Must default to `false` — the legacy code path should be opt-in, not
   * accidentally enabled by a missing env var.
   */
  sessionLegacyGracePeriod: z.boolean().default(false),
});

export type Config = z.infer<typeof ConfigSchema>;

function loadConfig(): Config {
  const raw = {
    issuer: process.env["OAUTH_ISSUER"],
    sessionSecret: process.env["OAUTH_SESSION_SECRET"],
    keysPath: process.env["OAUTH_KEYS_PATH"],
    databaseUrl: process.env["DATABASE_URL"],
    demoClientId: process.env["DEMO_CLIENT_ID"],
    demoClientSecret: process.env["DEMO_CLIENT_SECRET"],
    demoRedirectUri: process.env["DEMO_REDIRECT_URI"],
    sessionLegacyGracePeriod:
      process.env["OAUTH_SESSION_LEGACY_GRACE"] === "true",
  };

  const isProd = process.env["NODE_ENV"] === "production";

  // In production, session secret is required.
  if (!raw.sessionSecret) {
    if (isProd) {
      throw new Error(
        "OAUTH_SESSION_SECRET is required in production. " +
          "Generate one with: openssl rand -base64 48",
      );
    }
    console.warn(
      "[config] OAUTH_SESSION_SECRET not set — using insecure dev fallback. " +
        "DO NOT deploy without setting it.",
    );
    raw.sessionSecret = SESSION_COOKIE_DEV_FALLBACK;
  }

  // Warn if DCR_INITIAL_TOKEN is not set in production (Issue #15).
  // Without it, the register endpoint is open to anyone — fine for demos,
  // but a security risk in production.
  if (isProd && !process.env["DCR_INITIAL_TOKEN"]) {
    console.warn(
      "[config] DCR_INITIAL_TOKEN is not set — dynamic client registration " +
        "is unprotected (fail-open). Set DCR_INITIAL_TOKEN to require an " +
        "Initial Access Token for /oauth/register.",
    );
  }

  return ConfigSchema.parse(raw);
}

/** Singleton config — loaded once at first access. */
let _config: Config | null = null;

export function getConfig(): Config {
  if (!_config) {
    _config = loadConfig();
  }
  return _config;
}

// Convenience exports (evaluated lazily via getters).
export const config = new Proxy({} as Config, {
  get(_target, prop: string) {
    return getConfig()[prop as keyof Config];
  },
});