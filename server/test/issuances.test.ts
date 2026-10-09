// The Issuances interface called directly, on the platform's own unit of work and a real Postgres: whether an Issuance
// of a Managed Certificate may start, and under which intent, is decided by `begin` from the Managed Certificate's state
// under a lock on it. The routes, the scheduler and Approval all start Issuances through it; their own tests cover how
// they present a refusal. The Issuances that are allowed to start run in the background against an Organization with no
// ACME account, so they end at once as failed (no_acme_account): what these tests look at is whether and how one began.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { eq } from "drizzle-orm";
import { listAudit } from "../src/audit";
import { acmeAccount, certificate, issuance, managedCertificate, secret } from "../src/db/schema";
import { refusalMessage, renewsAutomatically, type IssuanceIntent, type Refusal } from "../src/issuance";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
let orgId: string;
const actor = { id: "user-1", email: "admin@acme.test" };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  orgId = (await h.createOrgWithAdmin(operator, "acme", "admin@acme.test")).orgId;
});
afterAll(async () => {
  await h.close();
});

/** A Managed Certificate as an Organization Administrator creates one, in the state given. */
async function managedCertificateIn(state: Partial<typeof managedCertificate.$inferInsert> = {}) {
  const [row] = await h.db
    .insert(managedCertificate)
    .values({ organizationId: orgId, names: ["a.example.test"], keyAlgorithm: "ecdsa-p256", keyCustody: "owner", environment: "staging", csr: "not-a-csr", ...state })
    .returning();
  return row!;
}

/**
 * A Certificate the Managed Certificate already has. Its ACME account is for the other environment, so an Issuance that
 * begins still ends at once for want of one in the Managed Certificate's own.
 */
async function certificateOf(managedCertificateId: string) {
  let [account] = await h.db.select().from(acmeAccount).where(eq(acmeAccount.organizationId, orgId));
  if (!account) {
    const [secretRow] = await h.db.insert(secret).values({ organizationId: orgId, ciphertext: Buffer.from("not-a-secret") }).returning();
    [account] = await h.db
      .insert(acmeAccount)
      .values({ organizationId: orgId, environment: "production", accountUrl: "https://acme.test/acct/1", secretId: secretRow!.id })
      .returning();
  }
  await h.db.insert(certificate).values({
    organizationId: orgId,
    managedCertificateId,
    fingerprint: randomBytes(32).toString("hex"),
    serial: "01",
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2026-04-01T00:00:00Z"),
    names: ["a.example.test"],
    chainPem: "not-a-chain",
    ca: "pebble",
    environment: "staging",
    acmeAccountId: account!.id,
    issuedAt: new Date("2026-01-01T00:00:00Z"),
  });
}

const begin = (id: string, intent: IssuanceIntent) =>
  h.unitOfWork.run(actor, (tx, change) => h.issuances.begin(tx, change, actor, { id, organizationId: orgId }, intent));

const issuancesOf = (id: string) => h.db.select().from(issuance).where(eq(issuance.managedCertificateId, id));
const startedEvents = async () => (await listAudit(h.db, orgId)).filter((e) => e.action === "issuance.started");

describe("beginning an Issuance for the intent to issue", () => {
  test("starts one for a Managed Certificate that is not awaiting Approval, is not rejected and is not archived, and it runs", async () => {
    const mc = await managedCertificateIn();

    const begun = await begin(mc.id, "issue");

    expect(begun).toEqual({ issuanceId: expect.any(String) });
    await h.settleIssuances();
    expect(await issuancesOf(mc.id)).toMatchObject([{ id: (begun as { issuanceId: string }).issuanceId, status: "failed", failureCode: "no_acme_account" }]);
    expect((await startedEvents()).map((e) => e.detail)).toEqual([{ issuanceId: (begun as { issuanceId: string }).issuanceId }]);
  });

  test.each<[string, Partial<typeof managedCertificate.$inferInsert>, Refusal]>([
    ["is archived", { archivedAt: new Date("2026-01-01T00:00:00Z") }, "archived"],
    ["awaits Approval", { approvalStatus: "pending" }, "awaiting_approval"],
    ["was rejected", { approvalStatus: "rejected" }, "rejected"],
  ])("refuses a Managed Certificate that %s, and records nothing", async (_, state, refused) => {
    const mc = await managedCertificateIn(state);

    expect(await begin(mc.id, "issue")).toEqual({ refused });

    await h.settleIssuances();
    expect(await issuancesOf(mc.id)).toEqual([]);
    expect(await startedEvents()).toEqual([]);
  });
});

describe("an Issuance of a Managed Certificate that has a Certificate is its Renewal, whatever the intent", () => {
  test("is audited as requested when a person asks for it, whether to issue or to renew now", async () => {
    const mc = await managedCertificateIn();
    await certificateOf(mc.id);

    const issued = await begin(mc.id, "issue");
    await h.settleIssuances();
    const renewed = await begin(mc.id, "renewNow");
    await h.settleIssuances();

    expect(issued).toEqual({ issuanceId: expect.any(String) });
    expect(renewed).toEqual({ issuanceId: expect.any(String) });
    expect((await startedEvents()).map((e) => e.detail.renewal)).toEqual(["requested", "requested"]);
  });

  test("is audited as scheduled when the scheduler starts it", async () => {
    const mc = await managedCertificateIn();
    await certificateOf(mc.id);

    expect(await begin(mc.id, "scheduled")).toEqual({ issuanceId: expect.any(String) });

    await h.settleIssuances();
    expect((await startedEvents()).map((e) => e.detail.renewal)).toEqual(["scheduled"]);
  });
});

describe("what each intent needs besides being approved and live", () => {
  test.each(["renewNow", "scheduled"] as const)("%s needs a Certificate to renew", async (intent) => {
    const mc = await managedCertificateIn();

    expect(await begin(mc.id, intent)).toEqual({ refused: "no_certificate" });
    expect(await issuancesOf(mc.id)).toEqual([]);
  });

  test("scheduled needs an automatic Renewal Policy, and a person's Renewal does not", async () => {
    const mc = await managedCertificateIn({ renewalMode: "manual" });
    await certificateOf(mc.id);

    expect(await begin(mc.id, "scheduled")).toEqual({ refused: "not_automatic" });
    expect(await begin(mc.id, "renewNow")).toEqual({ issuanceId: expect.any(String) });
  });

  test.each(["issue", "renewNow", "scheduled"] as const)("%s is refused while another Issuance of it runs, and nothing more is recorded", async (intent) => {
    const mc = await managedCertificateIn();
    await certificateOf(mc.id);
    await h.db.insert(issuance).values({ organizationId: orgId, managedCertificateId: mc.id, status: "running", startedAt: new Date() });

    expect(await begin(mc.id, intent)).toEqual({ refused: "already_running" });

    expect(await issuancesOf(mc.id)).toHaveLength(1);
    expect(await startedEvents()).toEqual([]);
  });

  test.each(["issue", "renewNow", "scheduled"] as const)("%s is refused for an archived Managed Certificate that has a Certificate", async (intent) => {
    const mc = await managedCertificateIn({ archivedAt: new Date("2026-01-02T00:00:00Z") });
    await certificateOf(mc.id);

    expect(await begin(mc.id, intent)).toEqual({ refused: "archived" });
  });
});

describe("the reasons it is refused, as told to whoever asked", () => {
  test("say what was asked for, and what to do instead where there is something", () => {
    expect(refusalMessage("awaiting_approval", "issue")).toBe("the Managed Certificate is awaiting Approval, so it cannot be issued");
    expect(refusalMessage("awaiting_approval", "renewNow")).toBe("the Managed Certificate is awaiting Approval, so it cannot be renewed");
    expect(refusalMessage("archived", "issue")).toBe("the Managed Certificate is archived, so it cannot be issued");
    expect(refusalMessage("already_running", "issue")).toContain("already running");
    expect(refusalMessage("no_certificate", "renewNow")).toContain("try issuing it again instead");
  });
});

describe("deciding under a lock on the Managed Certificate", () => {
  test("a change made at the same time, such as an archive, is not overridden by asking: the decision waits for it and sees it", async () => {
    const mc = await managedCertificateIn();
    await certificateOf(mc.id);
    let locked!: () => void;
    const hasLock = new Promise<void>((resolve) => (locked = resolve));
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    const archiving = h.unitOfWork.run(actor, async (tx) => {
      await tx.update(managedCertificate).set({ archivedAt: new Date("2026-01-02T00:00:00Z") }).where(eq(managedCertificate.id, mc.id));
      locked();
      await released;
    });
    await hasLock;

    let decided: unknown = "not yet";
    const asking = begin(mc.id, "scheduled").then((result) => (decided = result));
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(decided).toBe("not yet");

    release();
    await archiving;
    await asking;
    expect(decided).toEqual({ refused: "archived" });
    expect(await issuancesOf(mc.id)).toEqual([]);
  });

  test("a change that rolls back after beginning leaves no Issuance, no Audit Event and nothing running", async () => {
    const mc = await managedCertificateIn();

    await expect(
      h.unitOfWork.run(actor, async (tx, change) => {
        expect(await h.issuances.begin(tx, change, actor, { id: mc.id, organizationId: orgId }, "issue")).toEqual({ issuanceId: expect.any(String) });
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");

    await h.settleIssuances();
    expect(await issuancesOf(mc.id)).toEqual([]);
    expect(await startedEvents()).toEqual([]);
  });
});

describe("which Managed Certificates the scheduler may renew", () => {
  test("the condition the scheduler and the CA's renewal windows select by is the one a scheduled Issuance begins by", async () => {
    const ids: string[] = [];
    for (const renewalMode of ["automatic", "manual"] as const) {
      for (const archivedAt of [null, new Date("2026-01-02T00:00:00Z")]) {
        for (const approvalStatus of ["not_required", "approved", "pending", "rejected"] as const) {
          const mc = await managedCertificateIn({ renewalMode, archivedAt, approvalStatus });
          await certificateOf(mc.id);
          ids.push(mc.id);
        }
      }
    }

    const selected = (await h.db.select({ id: managedCertificate.id }).from(managedCertificate).where(renewsAutomatically)).map((r) => r.id);
    const begun: string[] = [];
    for (const id of ids) if ("issuanceId" in (await begin(id, "scheduled"))) begun.push(id);

    expect(begun).toHaveLength(2);
    expect(selected.sort()).toEqual(begun.sort());
  });
});
