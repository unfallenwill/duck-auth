import { discoveryDocument } from "@/lib/oauth/discovery";

export async function GET() {
  return Response.json(discoveryDocument(), {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Content-Type": "application/json",
    },
  });
}