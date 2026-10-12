import { Pool } from "pg";
import { createApp } from "./app";
import { createLetsEncrypt } from "./certificate-authority";
import { createLocalKms } from "./kms";
import { ConsoleMailer } from "./mailer";
import { runMigrations } from "./migrate";
import { bootstrapPlatformOperator } from "./operator";

const databaseUrl = process.env.DATABASE_URL;
const secret = process.env.AUTH_SECRET;
const localKmsKey = process.env.LOCAL_KMS_KEY;
if (!databaseUrl || !secret || !localKmsKey) throw new Error("DATABASE_URL, AUTH_SECRET and LOCAL_KMS_KEY are required");

const pool = new Pool({ connectionString: databaseUrl });
const { app, auth, db, issuances, renewals } = createApp({
  pool,
  mailer: new ConsoleMailer(),
  clock: () => new Date(),
  baseURL: process.env.BASE_URL ?? "http://localhost:3000",
  webURL: process.env.WEB_URL,
  trustedOrigins: process.env.TRUSTED_ORIGINS?.split(",").map((o) => o.trim()).filter(Boolean),
  secret,
  kms: createLocalKms(localKmsKey),
  certificateAuthority: createLetsEncrypt(),
  agentGateway: {
    ...(process.env.AGENT_LATEST_VERSION && { latestVersion: process.env.AGENT_LATEST_VERSION }),
    ...(process.env.AGENT_GATEWAY_SECRET && { terminatorSecret: process.env.AGENT_GATEWAY_SECRET }),
  },
});
await runMigrations(pool);
await issuances.failInterrupted();

// Renewals that have come due are started once a minute; each pass waits for the one before it.
const RENEWAL_PASS_MS = 60_000;
(async function renewDue() {
  await renewals.tick().catch((err) => console.error("renewal pass failed", err));
  setTimeout(renewDue, RENEWAL_PASS_MS);
})();

if (process.env.OPERATOR_EMAIL && process.env.OPERATOR_PASSWORD) {
  await bootstrapPlatformOperator(auth, db, {
    email: process.env.OPERATOR_EMAIL,
    password: process.env.OPERATOR_PASSWORD,
    name: "Platform Operator",
  });
}

export default { port: Number(process.env.PORT ?? 3000), fetch: app.fetch };
