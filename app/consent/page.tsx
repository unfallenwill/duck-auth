import { prisma } from "@/lib/generated/prisma-client";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { parseScopes } from "@/lib/oauth/discovery";

const SCOPE_LABELS: Record<string, string> = {
  openid: "验证您的身份 (sub)",
  profile: "读取您的资料 (name)",
  email: "读取您的邮箱 (email)",
};

export default async function ConsentPage({
  searchParams,
}: {
  searchParams: Promise<{
    client_id?: string;
    redirect_uri?: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
  }>;
}) {
  const sp = await searchParams;

  const clientId = sp.client_id ?? "";
  const redirectUri = sp.redirect_uri ?? "";
  const state = sp.state ?? "";
  const scope = sp.scope ?? "";
  const codeChallenge = sp.code_challenge ?? "";
  const codeChallengeMethod = sp.code_challenge_method ?? "";

  const client = clientId
    ? await prisma.client.findUnique({ where: { id: clientId } })
    : null;

  const scopes = parseScopes(scope);

  if (!client) {
    return (
      <main className="flex min-h-svh items-center justify-center p-8">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>未知客户端</CardTitle>
          </CardHeader>
        </Card>
      </main>
    );
  }

  return (
    <main className="flex min-h-svh items-center justify-center p-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>
            <span className="font-semibold">{client.name}</span> 申请访问
          </CardTitle>
          <CardDescription>
            将以您的身份访问以下信息：
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <ul className="flex flex-col gap-2">
            {scopes.map((s) => (
              <li
                key={s}
                className="flex items-center gap-2 rounded-md border border-border bg-muted/30 px-3 py-2 text-sm"
              >
                <span className="size-2 rounded-full bg-primary" />
                <span className="font-mono text-xs text-muted-foreground">
                  {s}
                </span>
                <span>{SCOPE_LABELS[s] ?? s}</span>
              </li>
            ))}
          </ul>

          <div className="flex gap-2">
            <form action="/api/consent" method="post" className="flex-1">
              <input type="hidden" name="action" value="approve" />
              <input type="hidden" name="client_id" value={clientId} />
              <input type="hidden" name="redirect_uri" value={redirectUri} />
              <input type="hidden" name="state" value={state} />
              <input type="hidden" name="scope" value={scope} />
              <input
                type="hidden"
                name="code_challenge"
                value={codeChallenge}
              />
              <input
                type="hidden"
                name="code_challenge_method"
                value={codeChallengeMethod}
              />
              <Button type="submit" className="w-full" data-testid="consent-approve">
                允许
              </Button>
            </form>
            <form action="/api/consent" method="post" className="flex-1">
              <input type="hidden" name="action" value="deny" />
              <input type="hidden" name="client_id" value={clientId} />
              <input type="hidden" name="redirect_uri" value={redirectUri} />
              <input type="hidden" name="state" value={state} />
              <Button
                type="submit"
                variant="outline"
                className="w-full"
                data-testid="consent-deny"
              >
                拒绝
              </Button>
            </form>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}