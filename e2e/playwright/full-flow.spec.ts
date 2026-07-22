/**
 * Full browser-level regression test for the OAuth + OIDC flow.
 *
 * Unlike the other e2e suites that bypass the consent UI by calling
 * `recordConsent()` directly, this test:
 *   - Goes through the REAL /login form
 *   - Clicks the REAL "允许" button on /consent (triggers server action)
 *   - Verifies the entire cookie chain lands on / with userinfo rendered
 *
 * DB access via raw @libsql/client because Prisma's generated client
 * uses `import.meta` which conflicts with Playwright's CommonJS loader.
 */
import { test, expect } from "@playwright/test";
import { createClient } from "@libsql/client";

const ALICE_EMAIL = "alice@example.com";
const ALICE_PASSWORD = "alice-password";
const CLIENT_ID = "demo-client";

const dbUrl = process.env["DATABASE_URL"] ?? "file:./dev.db";
const db = createClient({ url: dbUrl });

async function deleteConsent(): Promise<void> {
  await db.execute({
    sql: `DELETE FROM Consent WHERE clientId = ? AND userId IN (SELECT id FROM User WHERE email = ?)`,
    args: [CLIENT_ID, ALICE_EMAIL],
  });
}

async function getConsentRow(): Promise<{ scopes: string } | null> {
  const r = await db.execute({
    sql: `SELECT c.scopes as scopes FROM Consent c JOIN User u ON u.id = c.userId WHERE u.email = ? AND c.clientId = ?`,
    args: [ALICE_EMAIL, CLIENT_ID],
  });
  if (r.rows.length === 0) return null;
  return { scopes: String(r.rows[0]!.scopes) };
}

async function userExists(): Promise<boolean> {
  const r = await db.execute({
    sql: `SELECT id FROM User WHERE email = ?`,
    args: [ALICE_EMAIL],
  });
  return r.rows.length > 0;
}

test.beforeAll(async () => {
  if (!(await userExists())) {
    throw new Error("Seed missing — run `npm run db:seed` first.");
  }
});

test.beforeEach(async ({ page }) => {
  await deleteConsent();
  // Reset rate-limit buckets so each test gets a fresh quota.
  // Endpoint requires ADMIN_TOKEN (issue #32) — read from env set in
  // playwright.config.ts (webServer.env).
  const adminToken = process.env["ADMIN_TOKEN"];
  await page.request.post("http://localhost:3000/api/test/rate-reset", {
    headers: adminToken ? { "X-Admin-Token": adminToken } : {},
  });
});

test.afterAll(async () => {
  db.close();
});

test.describe("Full browser OAuth flow", () => {
  test("home → login → authorize → consent → callback → home with userinfo", async ({
    page,
  }) => {
    await page.goto("/");
    await page.getByTestId("oauth-login").click();

    await expect(page).toHaveURL(/\/login\?next=/);
    await page.fill('input[name="email"]', ALICE_EMAIL);
    await page.fill('input[name="password"]', ALICE_PASSWORD);
    await page.getByTestId("login-submit").click();

    // Wait for /consent (real user-visible page) using polling — waitForURL
    // can miss intermediate redirects in some Next.js + Playwright combos.
    await expect.poll(() => page.url(), {
      message: "should land on /consent after login",
      timeout: 15_000,
      intervals: [100, 200, 500],
    }).toMatch(/\/consent/);

    await page.getByTestId("consent-approve").click();

    // Give the server a moment to do its work, then check URL.
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});

    await expect.poll(() => page.url(), {
      message: "should land on / after callback",
      timeout: 15_000,
    }).toMatch(/\/$/);
    await expect(page.getByText(ALICE_EMAIL)).toBeVisible();
    await expect(page.getByTestId("oauth-logout")).toBeVisible();
  });

  test("consent row was persisted to the database", async ({ page }) => {
    await page.goto("/");
    await page.getByTestId("oauth-login").click();
    await page.fill('input[name="email"]', ALICE_EMAIL);
    await page.fill('input[name="password"]', ALICE_PASSWORD);
    await page.getByTestId("login-submit").click();
    await expect.poll(() => page.url(), { timeout: 15_000 }).toMatch(/\/consent/);
    await page.getByTestId("consent-approve").click();
    await expect.poll(() => page.url(), { timeout: 15_000 }).toMatch(/\/$/);

    // DB-side proof: approveConsent actually wrote the row.
    const consent = await getConsentRow();
    expect(consent).not.toBeNull();
    expect(consent!.scopes).toContain("openid");
    expect(consent!.scopes).toContain("email");
  });

  test("second visit skips consent (existing row covers scopes)", async ({
    page,
    context,
  }) => {
    // First visit — creates the consent row.
    await page.goto("/");
    await page.getByTestId("oauth-login").click();
    await page.fill('input[name="email"]', ALICE_EMAIL);
    await page.fill('input[name="password"]', ALICE_PASSWORD);
    await page.getByTestId("login-submit").click();
    await expect.poll(() => page.url(), { timeout: 15_000 }).toMatch(/\/consent/);
    await page.getByTestId("consent-approve").click();
    await expect.poll(() => page.url(), { timeout: 15_000 }).toMatch(/\/$/);

    // Second visit in a fresh page within the SAME context (so cookies
    // are preserved). /api/auth/login is the OAuth entry — it doesn't
    // depend on the home page being visible.
    const page2 = await context.newPage();
    await page2.goto("/api/auth/login");
    await expect.poll(() => page2.url(), { timeout: 15_000 }).toMatch(/\/$/);
    await expect(page2.getByText(ALICE_EMAIL)).toBeVisible();
  });

  test("login with wrong password shows error and stays on /login", async ({
    page,
  }) => {
    await page.goto("/login");
    await page.fill('input[name="email"]', ALICE_EMAIL);
    await page.fill('input[name="password"]', "wrong-password");
    await page.getByTestId("login-submit").click();

    await expect(page).toHaveURL(/\/login\?error=invalid/);
    await expect(page.getByText("邮箱或密码错误")).toBeVisible();
  });
});