import "dotenv/config";
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import {
  hashPassword,
  hashClientSecret,
} from "../lib/oauth/crypto";
import { config } from "../lib/config";

const adapter = new PrismaLibSql({ url: config.databaseUrl });
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
  const demoClientId = config.demoClientId;
  const demoClientSecret = config.demoClientSecret;
  const demoRedirectUri = config.demoRedirectUri;

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