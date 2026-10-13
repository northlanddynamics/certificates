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
    // An Agent's poll waits for work this long, so that relayed DNS operations reach it at once (see AgentGatewayConfig).
    longPollSeconds: Number(process.env.AGENT_LONG_POLL_SECONDS ?? 20),
    ...(process.env.AGENT_LATEST_VERSION && { latestVersion: process.env.AGENT_LATEST_VERSION }),
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

// The platform serves TLS itself when given a certificate and key (PEM files), which Agents require outside development (ADR 0006);
// without them it serves plain HTTP, for development or behind a TLS terminator that is not the platform's concern.
const tlsCertFile = process.env.TLS_CERT_FILE;
const tlsKeyFile = process.env.TLS_KEY_FILE;
if (!!tlsCertFile !== !!tlsKeyFile) throw new Error("TLS_CERT_FILE and TLS_KEY_FILE must be set together");

// An idle connection is closed after `idleTimeout` seconds, which must outlast a long poll (Bun allows at most 255).
export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
  idleTimeout: 60,
  ...(tlsCertFile && tlsKeyFile && { tls: { cert: Bun.file(tlsCertFile), key: Bun.file(tlsKeyFile) } }),
};
