// The unit of work called directly with a change of the platform's own (not one of Better Auth's endpoints):
// the change and its Audit Event commit or roll back together, and mail goes out only after the commit.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { eq } from "drizzle-orm";
import { listAudit } from "../src/audit";
import { team } from "../src/db/schema";
import type { Mailer } from "../src/mailer";
import { createUnitOfWork } from "../src/unit-of-work";
import { PASSWORD, createHarness, type Harness } from "./harness";

let h: Harness;
let orgId: string;
const actor = { id: "user-1", email: "admin@acme.test" };
const NOW = new Date("2026-02-03T04:05:06Z");

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

const teamNames = async () => (await h.db.select().from(team).where(eq(team.organizationId, orgId))).map((t) => t.name);
const auditActions = async () => (await listAudit(h.db, orgId)).map((e) => e.action);
const unitOfWork = (mailer: Mailer = h.mailer) => createUnitOfWork({ db: h.db, mailer, clock: () => NOW });

describe("unit of work", () => {
  test("a change and its Audit Event commit together, stamped with the actor and the clock", async () => {
    const created = await unitOfWork().run(actor, async (tx, change) => {
      await tx.insert(team).values({ id: "t1", name: "Platform", organizationId: orgId, createdAt: NOW });
      await change.audit({ organizationId: orgId, action: "team.created", target: { type: "team", id: "t1" }, detail: { name: "Platform" } });
      return "t1";
    });

    expect(created).toBe("t1");
    expect(await teamNames()).toEqual(["Platform"]);
    const events = (await listAudit(h.db, orgId)).filter((e) => e.action === "team.created");
    expect(events).toEqual([
      {
        id: expect.any(String),
        occurredAt: NOW.toISOString(),
        actor,
        action: "team.created",
        target: { type: "team", id: "t1" },
        detail: { name: "Platform" },
      },
    ]);
  });

  test("a change that throws leaves no write, no Audit Event and no mail", async () => {
    const mailBefore = h.mailer.sent.length;
    const auditBefore = (await auditActions()).length;

    await expect(
      unitOfWork().run(actor, async (tx, change) => {
        await tx.insert(team).values({ id: "t1", name: "Platform", organizationId: orgId, createdAt: NOW });
        await change.audit({ organizationId: orgId, action: "team.created", target: { type: "team", id: "t1" } });
        change.mail({ to: "x@acme.test", subject: "s", text: "t" });
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");

    expect(await teamNames()).toEqual([]);
    expect(await auditActions()).toHaveLength(auditBefore);
    expect(h.mailer.sent).toHaveLength(mailBefore);
  });

  test("queued mail is sent only after the commit", async () => {
    const mailBefore = h.mailer.sent.length;
    const mail = { to: "x@acme.test", subject: "Hello", text: "Body" };

    await unitOfWork().run(actor, async (_tx, change) => {
      change.mail(mail);
      expect(h.mailer.sent).toHaveLength(mailBefore);
    });

    expect(h.mailer.sent.slice(mailBefore)).toEqual([mail]);
  });

  test("a mail failure after the commit is logged and does not hide the commit", async () => {
    const failing: Mailer = {
      send: async () => {
        throw new Error("smtp down");
      },
    };
    const log = console.error;
    const logged: unknown[][] = [];
    console.error = (...args) => void logged.push(args);
    try {
      const result = await unitOfWork(failing).run(actor, async (tx, change) => {
        await tx.insert(team).values({ id: "t1", name: "Platform", organizationId: orgId, createdAt: NOW });
        change.mail({ to: "x@acme.test", subject: "s", text: "t" });
        return "committed";
      });
      expect(result).toBe("committed");
    } finally {
      console.error = log;
    }
    expect(await teamNames()).toEqual(["Platform"]);
    expect(logged).toHaveLength(1);
  });
});
