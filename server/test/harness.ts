// Seam A harness: the Hono app called in-process against a real Postgres,
// with Better Auth running for real. Only the outside world is replaced
// (email is captured, the clock is injectable). Later tickets' API tests live here.
import { Pool } from "pg";
import { readFileSync } from "node:fs";
import { createApp, type AppDeps } from "../src/app";
import { CertificateAuthorityError, createLetsEncrypt, type AcmeEnvironment, type RevocationReason } from "../src/certificate-authority";
import { createTxtResolver, type TxtResolver } from "../src/dcv";
import type { Db } from "../src/db/client";
import type { Issuances } from "../src/issuance";
import { createLocalKms } from "../src/kms";
import { CapturingMailer } from "../src/mailer";
import type { MemberRemovalHook } from "../src/member-removal";
import { CapturingWebhooks } from "../src/notifications";
import { runMigrations } from "../src/migrate";
import { bootstrapPlatformOperator } from "../src/operator";
import type { UnitOfWork } from "../src/unit-of-work";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5433/certs_test";

export const PASSWORD = "correct-horse-battery-staple";

const BASE = "http://localhost";

/** Pebble, Let's Encrypt's ACME test server (`docker compose up -d pebble`), and the root its certificate is signed by. */
export const PEBBLE_DIRECTORY = process.env.PEBBLE_DIRECTORY ?? "https://localhost:14000/dir";
const PEBBLE_CA = readFileSync(new URL("./pebble/minica.pem", import.meta.url), "utf8");
/** Where Pebble serves the root its chains end in; it makes a new one each time it starts. */
export const PEBBLE_MANAGEMENT = process.env.PEBBLE_MANAGEMENT ?? "https://localhost:15000";
const pebbleRoots = async () => [await (await fetch(`${PEBBLE_MANAGEMENT}/roots/0`, { tls: { ca: PEBBLE_CA } })).text()];

/** BIND (`docker compose up -d bind`): rfc2136.test takes dynamic updates signed with this key; readonly.test takes none. */
export const BIND = {
  server: process.env.BIND_HOST ?? "127.0.0.1",
  port: Number(process.env.BIND_PORT ?? 5354),
  zone: "rfc2136.test",
  readonlyZone: "readonly.test",
  keyName: "certs-test",
  keySecret: "dGVzdC10c2lnLWtleS1mb3ItdGhlLXJmYzIxMzYtdGVzdHM=",
  /**
   * Keys of the other TSIG algorithms, named <value>-key, each allowed to update only <value>.rfc2136.test (and refused
   * everywhere else); they share one secret.
   */
  otherKeys: { "hmac-sha1": "sha1", "hmac-sha384": "sha384", "hmac-sha512": "sha512", "hmac-md5": "md5" } as Record<string, string>,
  otherKeySecret: "b3RoZXItc2VjcmV0LWZvci10aGUtb3RoZXItYWxnb3JpdGhtcw==",
};

export interface OrgAdmin {
  orgId: string;
  cookie: string;
  invitationId: string;
}

export interface Harness {
  app: ReturnType<typeof createApp>["app"];
  pool: Pool;
  db: Db;
  /** The platform's own unit of work and Issuances, for tests of the Issuances interface itself. */
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  mailer: CapturingMailer;
  /** What webhook notification channels were sent, instead of sending it; `failing` makes every post fail. */
  webhooks: CapturingWebhooks;
  /** One pass of notifications at the harness's clock: notices Agents gone silent and Certificates nearing their end, then sends what is queued. Returns how many were sent. */
  deliverNotices(): Promise<number>;
  /** Where the CA's environments are served; every one is Pebble unless a test points one elsewhere. */
  caDirectories: Record<AcmeEnvironment, string>;
  /** Reads TXT records straight from BIND, as the CA's DNS checks do: what is really published. */
  bindTxt: TxtResolver;
  /** What DCV uses to see that a challenge record is published: BIND, unless a test sets `current` to something else. */
  dcvResolver: { current: TxtResolver };
  /** Resolves once every Issuance that was started has ended; read outcomes through the API, this only waits. */
  settleIssuances(): Promise<void>;
  /** One pass of the Renewal scheduler at the harness's clock: starts the Renewals that are due and returns how many. Settle the Issuances to see their outcome. */
  runRenewalScheduler(): Promise<number>;
  /**
   * The CA as the platform sees it, for the ARI tests: `enabled` is whether it answers ARI (off by default, so that
   * Pebble's own window, two thirds into a Certificate's life, does not decide the other tests' Renewals), `asked` the
   * Certificates (PEM) it was asked about, `replaces` what each order was placed to replace, and `failing` makes asking fail, and `replacing` names another Certificate (PEM) for orders to replace.
   */
  ari: { enabled: boolean; asked: string[]; replaces: (string | undefined)[]; failing: boolean; replacing?: string };
  /** What the CA was told to revoke, in order: the Certificate (PEM) and the reason. Nothing but a revocation by a person may ever add to it. */
  revocations: { certificate: string; reason: RevocationReason }[];
  /** Has Pebble answer ARI for the Certificate (PEM, or its chain) with this window instead of its own; the CA's `Retry-After` is Pebble's six hours. */
  setPebbleWindow(certificate: string, window: { start: Date; end: Date }): Promise<void>;
  /** What the platform does when it starts: ends the Issuances an earlier run left running. */
  failInterruptedIssuances(): Promise<void>;
  /** The roots the CA's chains end in, as an export that includes the root finds them: Pebble's, unless a test sets `current` to something else. */
  caRoots: { current: () => Promise<string[]> };
  /** The private keys of the ACME accounts the platform created at the CA, as PEM; for tests to check they never leak. */
  createdAccountKeys: string[];
  /** The hooks the app runs when a member is removed; empty unless a test adds one (and takes it out again). */
  memberRemovalHooks: MemberRemovalHook[];
  setNow(d: Date): void;
  /** Sign up (Better Auth) and return the session cookie. */
  signUp(email: string, password: string, name?: string): Promise<string>;
  signIn(email: string, password: string): Promise<string>;
  createOperator(email: string, password: string): Promise<string>;
  api(
    path: string,
    opts?: { method?: string; body?: unknown; cookie?: string; headers?: Record<string, string> },
  ): Promise<{ status: number; body: any; cookie: string }>;
  /** Operator creates an Organization; its first administrator accepts the invitation and signs in. */
  createOrgWithAdmin(operatorCookie: string, slug: string, adminEmail: string): Promise<OrgAdmin>;
  /** Empty every table and reset captured mail and the clock. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

/** The cookies a browser would hold after `res`: a later Set-Cookie of a name replaces an earlier one, and an empty value clears it. */
function cookieFrom(res: Response): string {
  const jar = new Map<string, string>();
  for (const setCookie of res.headers.getSetCookie()) {
    const [pair = ""] = setCookie.split(";");
    const at = pair.indexOf("=");
    const name = pair.slice(0, at);
    const value = pair.slice(at + 1);
    if (value) jar.set(name, value);
    else jar.delete(name);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

export async function createHarness(overrides: Partial<AppDeps> = {}): Promise<Harness> {
  const pool = new Pool({ connectionString: TEST_DATABASE_URL });
  const mailer = new CapturingMailer();
  const webhooks = new CapturingWebhooks();
  const memberRemovalHooks: MemberRemovalHook[] = [];
  let now = new Date("2026-01-01T00:00:00Z");
  const caDirectories: Record<AcmeEnvironment, string> = { staging: PEBBLE_DIRECTORY, production: PEBBLE_DIRECTORY };
  const createdAccountKeys: string[] = [];
  const caRoots = { current: pebbleRoots };
  const ari: Harness["ari"] = { enabled: false, asked: [], replaces: [], failing: false };
  const revocations: Harness["revocations"] = [];
  // The real ACME client against Pebble; it only notes the keys it generated.
  const letsEncrypt = createLetsEncrypt({
    directoryUrls: caDirectories,
    trustedCa: PEBBLE_CA,
    roots: { staging: () => caRoots.current(), production: () => caRoots.current() },
    pollMs: { min: 200, max: 1000 },
  });
  const bindTxt = createTxtResolver([`${BIND.server}:${BIND.port}`]);
  const dcvResolver = { current: bindTxt };
  const deps: AppDeps = {
    pool,
    mailer,
    webhooks,
    memberRemovalHooks,
    kms: createLocalKms(Buffer.alloc(32, 1).toString("base64")),
    certificateAuthority: {
      ...letsEncrypt,
      async createAccount(environment, input) {
        const account = await letsEncrypt.createAccount(environment, input);
        createdAccountKeys.push(account.accountKey);
        return account;
      },
      async issue(environment, account, request) {
        const replaces = ari.replacing ?? request.replaces;
        ari.replaces.push(replaces);
        return letsEncrypt.issue(environment, account, { ...request, replaces });
      },
      async revoke(environment, account, request) {
        await letsEncrypt.revoke(environment, account, request);
        revocations.push(request);
      },
      async renewalInfo(environment, certificate) {
        ari.asked.push(certificate);
        if (ari.failing) throw new CertificateAuthorityError("unreachable", "could not reach the CA for its renewal information");
        return ari.enabled ? letsEncrypt.renewalInfo(environment, certificate) : null;
      },
    },
    dcv: { resolver: { lookupTxt: (name) => dcvResolver.current.lookupTxt(name), lookupCname: (name) => dcvResolver.current.lookupCname(name) }, visibilityTimeoutMs: 1500, pollIntervalMs: 50 },
    clock: () => now,
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-1234",
    ...overrides,
  };
  const { app, auth, db, unitOfWork, issuances, renewals, notifications } = createApp(deps);
  await runMigrations(pool);
  const reset = async () => {
    await issuances.idle();
    dcvResolver.current = bindTxt;
    caRoots.current = pebbleRoots;
    Object.assign(ari, { enabled: false, failing: false, replacing: undefined });
    ari.asked.length = ari.replaces.length = revocations.length = 0;
    // Cascades through every table that references an Organization or a user.
    await pool.query(`truncate organization, "user", apikey cascade`);
    mailer.sent.length = 0;
    webhooks.sent.length = 0;
    webhooks.failing = false;
    memberRemovalHooks.length = 0;
    createdAccountKeys.length = 0;
    caDirectories.staging = caDirectories.production = PEBBLE_DIRECTORY;
    now = new Date("2026-01-01T00:00:00Z");
  };
  await reset();

  const post = (path: string, body: unknown) =>
    app.request(`${BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify(body),
    });

  const harness: Harness = {
    app,
    pool,
    db,
    unitOfWork,
    issuances,
    mailer,
    webhooks,
    deliverNotices: () => notifications.tick(),
    caDirectories,
    bindTxt,
    dcvResolver,
    settleIssuances: () => issuances.idle(),
    runRenewalScheduler: () => renewals.tick(),
    ari,
    revocations,
    async setPebbleWindow(certificate, window) {
      const leaf = certificate.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)![0];
      const res = await fetch(`${PEBBLE_MANAGEMENT}/set-renewal-info/`, {
        method: "POST",
        body: JSON.stringify({ Certificate: leaf, ARIResponse: JSON.stringify({ suggestedWindow: { start: window.start.toISOString(), end: window.end.toISOString() } }) }),
        tls: { ca: PEBBLE_CA },
      });
      if (!res.ok) throw new Error(`Pebble would not set the renewal information: ${res.status} ${await res.text()}`);
    },
    failInterruptedIssuances: () => issuances.failInterrupted(),
    caRoots,
    createdAccountKeys,
    memberRemovalHooks,
    setNow: (d) => {
      now = d;
    },
    async signUp(email, password, name = email) {
      const res = await post("/api/auth/sign-up/email", { email, password, name });
      if (res.status !== 200) throw new Error(`sign-up failed: ${res.status} ${await res.text()}`);
      return cookieFrom(res);
    },
    async signIn(email, password) {
      const res = await post("/api/auth/sign-in/email", { email, password });
      if (res.status !== 200) throw new Error(`sign-in failed: ${res.status} ${await res.text()}`);
      return cookieFrom(res);
    },
    async createOperator(email, password) {
      await bootstrapPlatformOperator(auth, db, { email, password, name: "Operator" });
      const res = await post("/api/auth/sign-in/email", { email, password });
      return cookieFrom(res);
    },
    async api(path, opts = {}) {
      const res = await app.request(`${BASE}${path}`, {
        method: opts.method ?? (opts.body ? "POST" : "GET"),
        headers: {
          "content-type": "application/json",
          origin: BASE,
          ...(opts.cookie ? { cookie: opts.cookie } : {}),
          ...opts.headers,
        },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null, cookie: cookieFrom(res) };
    },
    async createOrgWithAdmin(operatorCookie, slug, adminEmail) {
      const created = await harness.api("/api/platform/organizations", {
        cookie: operatorCookie,
        body: { name: `Org ${slug}`, slug, adminEmail },
      });
      if (created.status !== 201) throw new Error(`create organization failed: ${created.status}`);
      const adminCookie = await harness.signUp(adminEmail, PASSWORD);
      const accepted = await harness.api("/api/auth/organization/accept-invitation", {
        cookie: adminCookie,
        body: { invitationId: created.body.invitationId },
      });
      if (accepted.status !== 200) throw new Error(`accept failed: ${accepted.status}`);
      return { orgId: created.body.id, cookie: await harness.signIn(adminEmail, PASSWORD), invitationId: created.body.invitationId };
    },
    reset,
    close: () => pool.end(),
  };
  return harness;
}
