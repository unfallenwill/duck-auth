import { cookies } from "next/headers";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import { ISSUER } from "@/lib/oauth/discovery";

async function fetchUserInfo(accessToken: string) {
  const res = await fetch(`${ISSUER}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    cache: "no-store",
  });
  if (!res.ok) return null;
  return (await res.json()) as Record<string, unknown>;
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ oauth_error?: string; detail?: string }>;
}) {
  const sp = await searchParams;
  const cookieStore = await cookies();
  const accessToken = cookieStore.get("oauth_access_token")?.value;
  const userinfo = accessToken ? await fetchUserInfo(accessToken) : null;

  return (
    <main className="flex min-h-svh items-center justify-center p-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>OAuth Demo Client</CardTitle>
          <CardDescription>
            Next.js 16 · shadcn/ui · OAuth 2.0 + OIDC Server
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {sp.oauth_error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <p className="font-medium">OAuth 错误: {sp.oauth_error}</p>
              {sp.detail && (
                <pre className="mt-1 overflow-x-auto text-xs">
                  {sp.detail}
                </pre>
              )}
            </div>
          )}

          {userinfo ? (
            <>
              <div className="rounded-md border border-border bg-muted/30 p-4">
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  已登录 · Userinfo
                </p>
                <dl className="space-y-1 text-sm">
                  {Object.entries(userinfo).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <dt className="font-mono text-xs text-muted-foreground">
                        {k}
                      </dt>
                      <dd className="font-mono text-xs">{String(v)}</dd>
                    </div>
                  ))}
                </dl>
              </div>
              <form action="/api/auth/logout" method="post">
                <Button type="submit" variant="outline" className="w-full" data-testid="oauth-logout">
                  登出
                </Button>
              </form>
            </>
          ) : (
            <>
              <p className="text-sm text-muted-foreground">
                您未登录。点击下方按钮，使用 OAuth Server 完成授权码 + PKCE 流程。
              </p>
              <a
                href="/api/auth/login"
                data-testid="oauth-login"
                className={buttonVariants({ className: "w-full" })}
              >
                使用 OAuth Server 登录
              </a>
            </>
          )}
        </CardContent>
      </Card>
    </main>
  );
}