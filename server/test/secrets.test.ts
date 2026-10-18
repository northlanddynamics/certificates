// Secrets: envelope encryption with a data key per Organization, wrapped by a pluggable KMS. Tested through the
// module's own interface (create, replace, open) against the real database; only the KMS is swapped for ones the
// tests can watch.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { eq } from "drizzle-orm";
import { createLocalKms, type Kms } from "../src/platform/crypto/kms";
import { secret } from "../src/platform/db/schema";
import { createSecrets } from "../src/platform/crypto/secrets";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let operator: string;
let acme: { orgId: string };
let globex: { orgId: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acme = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const MASTER_KEY = Buffer.alloc(32, 7).toString("base64");

/** A local KMS that remembers what it was asked to wrap, and for whom. */
function watchedKms(inner: Kms = createLocalKms(MASTER_KEY)) {
  const wrapped: { context: string; wrapped: Uint8Array }[] = [];
  const kms: Kms = {
    ...inner,
    async wrap(dataKey, context) {
      const out = await inner.wrap(dataKey, context);
      wrapped.push({ context, wrapped: out });
      return out;
    },
    unwrap: (w, context) => inner.unwrap(w, context),
  };
  return { kms, wrapped };
}

const store = (kms: Kms) => {
  const secrets = createSecrets(kms);
  return {
    create: (orgId: string, value: string) => h.db.transaction((tx) => secrets.create(tx, orgId, value)),
    replace: (orgId: string, id: string, value: string) => h.db.transaction((tx) => secrets.replace(tx, orgId, id, value)),
    open: (orgId: string, id: string) => secrets.open(h.db, orgId, id),
  };
};

describe("secrets", () => {
  test("a secret is stored encrypted and opens to what was written", async () => {
    const secrets = store(createLocalKms(MASTER_KEY));
    const id = await secrets.create(acme.orgId, "super-secret-value");
    expect(await secrets.open(acme.orgId, id)).toBe("super-secret-value");

    const [row] = await h.db.select().from(secret).where(eq(secret.id, id));
    expect(row!.ciphertext.includes("super-secret-value")).toBe(false);
  });

  test("each Organization's secrets are encrypted under its own data key, wrapped by the KMS once", async () => {
    const { kms, wrapped } = watchedKms();
    const secrets = store(kms);
    const a1 = await secrets.create(acme.orgId, "same value");
    const a2 = await secrets.create(acme.orgId, "another value");
    const g1 = await secrets.create(globex.orgId, "same value");

    expect(wrapped.map((w) => w.context).sort()).toEqual([acme.orgId, globex.orgId].sort());
    expect(Buffer.from(wrapped[0]!.wrapped).equals(Buffer.from(wrapped[1]!.wrapped))).toBe(false);

    // The same plaintext encrypts differently, and a ciphertext moved to another Organization's secret is refused.
    const [rowA] = await h.db.select().from(secret).where(eq(secret.id, a1));
    const [rowG] = await h.db.select().from(secret).where(eq(secret.id, g1));
    expect(rowA!.ciphertext.equals(rowG!.ciphertext)).toBe(false);
    await h.db.update(secret).set({ ciphertext: rowA!.ciphertext }).where(eq(secret.id, g1));
    await expect(secrets.open(globex.orgId, g1)).rejects.toThrow();
    expect(await secrets.open(acme.orgId, a2)).toBe("another value");
  });

  test("a secret cannot be opened through another Organization", async () => {
    const secrets = store(createLocalKms(MASTER_KEY));
    const id = await secrets.create(acme.orgId, "acme only");
    await expect(secrets.open(globex.orgId, id)).rejects.toThrow();
  });

  test("replacing a secret changes what it opens to, and only for that secret", async () => {
    const secrets = store(createLocalKms(MASTER_KEY));
    const id = await secrets.create(acme.orgId, "old");
    const other = await secrets.create(acme.orgId, "untouched");
    await secrets.replace(acme.orgId, id, "new");
    expect(await secrets.open(acme.orgId, id)).toBe("new");
    expect(await secrets.open(acme.orgId, other)).toBe("untouched");
    await expect(secrets.replace(globex.orgId, id, "hijacked")).rejects.toThrow();
    expect(await secrets.open(acme.orgId, id)).toBe("new");
  });

  test("a secret written in a rolled-back transaction is not left behind", async () => {
    const secrets = createSecrets(createLocalKms(MASTER_KEY));
    await expect(
      h.db.transaction(async (tx) => {
        await secrets.create(tx, acme.orgId, "never committed");
        throw new Error("rolled back");
      }),
    ).rejects.toThrow("rolled back");
    expect(await h.db.select().from(secret)).toEqual([]);
  });

  test("the KMS is pluggable: the data key opens only through the KMS that wrapped it", async () => {
    const secrets = store(createLocalKms(MASTER_KEY));
    const id = await secrets.create(acme.orgId, "value");
    const elsewhere = store(createLocalKms(Buffer.alloc(32, 9).toString("base64")));
    await expect(elsewhere.open(acme.orgId, id)).rejects.toThrow();
  });
});

describe("local KMS", () => {
  test("unwraps what it wrapped, for the same context only", async () => {
    const kms = createLocalKms(MASTER_KEY);
    const key = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await kms.wrap(key, "org-1");
    expect(Buffer.from(await kms.unwrap(wrapped, "org-1")).equals(Buffer.from(key))).toBe(true);
    await expect(kms.unwrap(wrapped, "org-2")).rejects.toThrow();
  });

  test("refuses a master key that is not 32 bytes", () => {
    expect(() => createLocalKms(Buffer.alloc(16).toString("base64"))).toThrow();
  });
});
