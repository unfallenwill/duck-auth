import { getJwks } from "@/lib/oauth/jwt";

export async function GET() {
  const jwks = await getJwks();
  return Response.json(jwks, {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Content-Type": "application/json",
    },
  });
}