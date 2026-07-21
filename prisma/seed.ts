import "dotenv/config";
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import {
  hashPassword,
  hashClientSecret,
} from "../lib/oauth/crypto";

const url = process.env["DATABASE_URL"] ?? "file:./dev.db";
const adapter = new PrismaLibSql({ url });
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log("🌱 Seeding...");

  // Demo user
  const demoEmail = "alice@example.com";
  const demoPassword = "alice-password";
  const existingUser = await prisma.user.findUnique({ where: { email: demoEmail } });
  if (existingUser) {
    await prisma.user.delete({ where: { id: existingUser.id } });
  }
  const user = await prisma.user.create({
    data: {
      email: demoEmail,
      name: "Alice",
      passwordHash: hashPassword(demoPassword),
    },
  });
  console.log(`  ✓ user: ${user.email} (id=${user.id})`);

  // Demo client (matches DEMO_CLIENT_ID in .env)
  const demoClientId = process.env["DEMO_CLIENT_ID"] ?? "demo-client";
  const demoClientSecret = process.env["DEMO_CLIENT_SECRET"] ?? "demo-secret-change-me";
  const demoRedirectUri =
    process.env["DEMO_REDIRECT_URI"] ?? "http://localhost:3000/api/auth/callback";

  await prisma.client.deleteMany({ where: { id: demoClientId } });
  const client = await prisma.client.create({
    data: {
      id: demoClientId,
      name: "Next.js Hello Demo Client",
      secretHash: hashClientSecret(demoClientSecret),
      redirectUris: JSON.stringify([demoRedirectUri]),
      allowedScopes: "openid profile email",
    },
  });
  console.log(`  ✓ client: ${client.id} (secret: ${demoClientSecret})`);

  console.log("\n✅ Done. Try logging in with:");
  console.log(`     email:    ${demoEmail}`);
  console.log(`     password: ${demoPassword}`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());