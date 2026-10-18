import { Pool } from "pg";
import { createApp } from "./app";
import { createLetsEncrypt } from "./issuance/acme/certificate-authority";
import { createLocalKms } from "./platform/crypto/kms";
import { ConsoleMailer } from "./platform/mailer";
import { runMigrations } from "./platform/migrate";
import { bootstrapPlatformOperator } from "./tenancy/operator";

const databaseUrl = process.env.DATABASE_URL;
const secret = process.env.AUTH_SECRET;
const localKmsKey = process.env.LOCAL_KMS_KEY;
if (!databaseUrl || !secret || !localKmsKey) throw new Error("DATABASE_URL, AUTH_SECRET and LOCAL_KMS_KEY are required");

const pool = new Pool({ connectionString: databaseUrl });
const { app, auth, db, issuances, renewals, notifications, auditForwarding, crls, enrollmentValidators, deviceCertificatePruning, sharedChallenges } = createApp({
  pool,
  mailer: new ConsoleMailer(),
  clock: () => new Date(),
  baseURL: process.env.BASE_URL ?? "http://localhost:3000",
  webURL: process.env.WEB_URL,
  // Where relying parties fetch Private CAs' CRLs and CA certificates; a plain-HTTP URL (see the README's Private CAs).
  pkiBaseURL: process.env.PKI_BASE_URL,
  trustedOrigins: process.env.TRUSTED_ORIGINS?.split(",").map((o) => o.trim()).filter(Boolean),
  secret,
  kms: createLocalKms(localKmsKey),
  certificateAuthority: createLetsEncrypt(),
  agentGateway: {
    // An Agent's poll waits for work this long, so that relayed DNS operations reach it at once (see AgentGatewayConfig).
    longPollSeconds: Number(process.env.AGENT_LONG_POLL_SECONDS ?? 20),
    ...(process.env.AGENT_LATEST_VERSION && { latestVersion: process.env.AGENT_LATEST_VERSION }),
  },
  // SCEP's rate limit counts the address in X-Forwarded-For only behind a TLS terminator that sets it (see ScepConfig).
  scep: { trustForwardedFor: process.env.TRUST_FORWARDED_FOR === "true" },
});
await runMigrations(pool);
await issuances.failInterrupted();

// Renewals that have come due are started once a minute; each pass waits for the one before it.
const RENEWAL_PASS_MS = 60_000;
(async function renewDue() {
  await renewals.tick().catch((err) => console.error("renewal pass failed", err));
  setTimeout(renewDue, RENEWAL_PASS_MS);
})();

// Notices are sent, and silent Agents and Certificates nearing their end noticed, once a minute; each pass waits for the one before it.
const NOTIFICATION_PASS_MS = 60_000;
(async function notify() {
  await notifications.tick().catch((err) => console.error("notification pass failed", err));
  setTimeout(notify, NOTIFICATION_PASS_MS);
})();

// Audit Events are forwarded to the Organizations' SIEMs every half a minute; each pass waits for the one before it.
const AUDIT_FORWARDING_PASS_MS = 30_000;
(async function forwardAudit() {
  await auditForwarding.tick().catch((err) => console.error("audit forwarding pass failed", err));
  setTimeout(forwardAudit, AUDIT_FORWARDING_PASS_MS);
})();

// Private CAs' CRLs that are due (3 days before their nextUpdate) are reissued once a minute; each pass waits for the one before it.
const CRL_PASS_MS = 60_000;
(async function reissueCrls() {
  await crls.tick().catch((err) => console.error("CRL pass failed", err));
  setTimeout(reissueCrls, CRL_PASS_MS);
})();

// Enrollment Validators are told what became of requests and Revocations every half a minute, and their revocation feeds
// are pulled once a minute (each no more often than its kind allows); each pass waits for the one before it.
const ENROLLMENT_VALIDATOR_DELIVERY_PASS_MS = 30_000;
(async function tellEnrollmentValidators() {
  await enrollmentValidators.deliver().catch((err) => console.error("Enrollment Validator delivery pass failed", err));
  setTimeout(tellEnrollmentValidators, ENROLLMENT_VALIDATOR_DELIVERY_PASS_MS);
})();
const REVOCATION_FEED_PASS_MS = 60_000;
(async function pullRevocationFeeds() {
  await enrollmentValidators.pollFeeds().catch((err) => console.error("revocation feed pass failed", err));
  setTimeout(pullRevocationFeeds, REVOCATION_FEED_PASS_MS);
})();

// Device Certificates past their Enrollment Profile's retention period are pruned once an hour; each pass waits for the one before it.
const PRUNING_PASS_MS = 3_600_000;
(async function pruneDeviceCertificates() {
  await deviceCertificatePruning.prune().catch((err) => console.error("Device Certificate pruning pass failed", err));
  setTimeout(pruneDeviceCertificates, PRUNING_PASS_MS);
})();

// Previous Shared Challenges past their expiry are cleared, and their expiry audited, once a minute; each pass waits for
// the one before it. A device presenting one is refused from its expiry on regardless.
const SHARED_CHALLENGE_EXPIRY_PASS_MS = 60_000;
(async function expireSharedChallenges() {
  await sharedChallenges.expire().catch((err) => console.error("Shared Challenge expiry pass failed", err));
  setTimeout(expireSharedChallenges, SHARED_CHALLENGE_EXPIRY_PASS_MS);
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

// When the platform serves TLS itself, it also serves what Private CAs publish (/pki) over plain HTTP on PKI_HTTP_PORT,
// answering nothing else there and never redirecting: relying parties fetch CRLs over plain HTTP. Without TLS the one
// listener below is plain HTTP already.
const pkiHttpPort = process.env.PKI_HTTP_PORT;
if (pkiHttpPort && tlsCertFile) {
  Bun.serve({
    port: Number(pkiHttpPort),
    fetch: (request) => (new URL(request.url).pathname.startsWith("/pki/") ? app.fetch(request) : new Response("not found", { status: 404 })),
  });
}

// An idle connection is closed after `idleTimeout` seconds, which must outlast a long poll (Bun allows at most 255).
export default {
  port: Number(process.env.PORT ?? 3000),
  fetch: app.fetch,
  idleTimeout: 60,
  ...(tlsCertFile && tlsKeyFile && { tls: { cert: Bun.file(tlsCertFile), key: Bun.file(tlsKeyFile) } }),
};
