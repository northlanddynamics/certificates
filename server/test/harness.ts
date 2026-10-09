// Seam A harness: the Hono app called in-process against a real Postgres,
// with Better Auth running for real. Only the outside world is replaced
// (email is captured, the clock is injectable). Later tickets' API tests live here.
import { Pool } from "pg";
import { createApp, type AppDeps } from "../src/app";
import type { Db } from "../src/db/client";
import { CapturingMailer } from "../src/mailer";
import { runMigrations } from "../src/migrate";
import { bootstrapPlatformOperator } from "../src/operator";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5433/certs_test";

export const PASSWORD = "correct-horse-battery-staple";

const BASE = "http://localhost";

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
  setNow(d: Date): void;
  /** Sign up (Better Auth) and return the session cookie. */
  signUp(email: string, password: string, name?: string): Promise<string>;
  signIn(email: string, password: string): Promise<string>;
  createOperator(email: string, password: string): Promise<string>;
  api(
    path: string,
    opts?: { method?: string; body?: unknown; cookie?: string },
  ): Promise<{ status: number; body: any }>;
  /** Operator creates an Organization; its first administrator accepts the invitation and signs in. */
  createOrgWithAdmin(operatorCookie: string, slug: string, adminEmail: string): Promise<OrgAdmin>;
  /** Empty every table and reset captured mail and the clock. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

function cookieFrom(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((c) => c.split(";")[0])
    .join("; ");
}

export async function createHarness(): Promise<Harness> {
  const pool = new Pool({ connectionString: TEST_DATABASE_URL });
  const mailer = new CapturingMailer();
  let now = new Date("2026-01-01T00:00:00Z");
  const deps: AppDeps = {
    pool,
    mailer,
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
      return { status: res.status, body: text ? JSON.parse(text) : null };
    },
    async createOrgWithAdmin(operatorCookie, slug, adminEmail) {
      const created = await harness.api("/api/platform/organizations", {
        cookie: operatorCookie,
        body: { name: `Org ${slug}`, slug, adminEmail },
      });
      if (created.status !== 201) throw new Error(`create organization failed: ${created.status}`);
      const adminCookie = await harness.signUp(adminEmail, PASSWORD);
      const accepted = await harness.api(`/api/invitations/${created.body.invitationId}/accept`, {
        cookie: adminCookie,
        method: "POST",
      });
      if (accepted.status !== 200) throw new Error(`accept failed: ${accepted.status}`);
      return { orgId: created.body.id, cookie: await harness.signIn(adminEmail, PASSWORD), invitationId: created.body.invitationId };
    },
    reset,
    close: () => pool.end(),
  };
  return harness;
}
