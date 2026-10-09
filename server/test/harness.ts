// Seam A harness: the Hono app called in-process against a real Postgres,
// with Better Auth running for real. Only the outside world is replaced
// (email is captured, the clock is injectable). Later tickets' API tests live here.
import { Pool } from "pg";
import { readFileSync } from "node:fs";
import { createApp, type AppDeps } from "../src/app";
import { createLetsEncrypt, type AcmeEnvironment } from "../src/certificate-authority";
import type { Db } from "../src/db/client";
import { createLocalKms } from "../src/kms";
import { CapturingMailer } from "../src/mailer";
import type { MemberRemovalHook } from "../src/member-removal";
import { runMigrations } from "../src/migrate";
import { bootstrapPlatformOperator } from "../src/operator";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5433/certs_test";

export const PASSWORD = "correct-horse-battery-staple";

const BASE = "http://localhost";

/** Pebble, Let's Encrypt's ACME test server (`docker compose up -d pebble`), and the root its certificate is signed by. */
export const PEBBLE_DIRECTORY = process.env.PEBBLE_DIRECTORY ?? "https://localhost:14000/dir";
const PEBBLE_CA = readFileSync(new URL("./pebble/minica.pem", import.meta.url), "utf8");

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
  mailer: CapturingMailer;
  /** Where the CA's environments are served; every one is Pebble unless a test points one elsewhere. */
  caDirectories: Record<AcmeEnvironment, string>;
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
    opts?: { method?: string; body?: unknown; cookie?: string },
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

export async function createHarness(): Promise<Harness> {
  const pool = new Pool({ connectionString: TEST_DATABASE_URL });
  const mailer = new CapturingMailer();
  const memberRemovalHooks: MemberRemovalHook[] = [];
  let now = new Date("2026-01-01T00:00:00Z");
  const caDirectories: Record<AcmeEnvironment, string> = { staging: PEBBLE_DIRECTORY, production: PEBBLE_DIRECTORY };
  const createdAccountKeys: string[] = [];
  // The real ACME client against Pebble; it only notes the keys it generated.
  const letsEncrypt = createLetsEncrypt({ directoryUrls: caDirectories, trustedCa: PEBBLE_CA });
  const deps: AppDeps = {
    pool,
    mailer,
    memberRemovalHooks,
    kms: createLocalKms(Buffer.alloc(32, 1).toString("base64")),
    certificateAuthority: {
      ...letsEncrypt,
      async createAccount(environment, input) {
        const account = await letsEncrypt.createAccount(environment, input);
        createdAccountKeys.push(account.accountKey);
        return account;
      },
    },
    clock: () => now,
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-1234",
  };
  const { app, auth, db } = createApp(deps);
  await runMigrations(pool);
  const reset = async () => {
    // Cascades through every table that references an Organization or a user.
    await pool.query(`truncate organization, "user" cascade`);
    mailer.sent.length = 0;
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
    mailer,
    caDirectories,
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
