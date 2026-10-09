// Write-only values the platform must hold (ACME account keys now, DNS Provider credentials later; ADR 0002).
// Envelope encryption: each Organization has one data key, wrapped by the KMS and stored wrapped; each secret is
// encrypted under its Organization's data key. `open` is for the platform's own modules to use a secret and is
// never behind a route: nothing returns a secret's value.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { Db, Tx } from "./db/client";
import { organizationDataKey, secret } from "./db/schema";
import type { Kms } from "./kms";

export interface Secrets {
  /** Stores `value` encrypted under the Organization's data key (created on first use) and returns the secret's id. */
  create(tx: Tx, organizationId: string, value: string): Promise<string>;
  /** Throws when the Organization has no such secret. */
  replace(tx: Tx, organizationId: string, secretId: string, value: string): Promise<void>;
  /** Throws when the Organization has no such secret, or when the stored bytes were tampered with or moved. */
  open(db: Db | Tx, organizationId: string, secretId: string): Promise<string>;
}

const IV_BYTES = 12;
const TAG_BYTES = 16;

// Binding a ciphertext to its Organization and id means it opens nowhere else.
const aad = (organizationId: string, secretId: string) => Buffer.from(`secret:${organizationId}:${secretId}`);

function encrypt(dataKey: Buffer, value: string, associated: Buffer) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", dataKey, iv).setAAD(associated);
  const body = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return Buffer.concat([iv, body, cipher.getAuthTag()]);
}

function decrypt(dataKey: Buffer, ciphertext: Buffer, associated: Buffer) {
  const iv = ciphertext.subarray(0, IV_BYTES);
  const tag = ciphertext.subarray(ciphertext.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", dataKey, iv).setAAD(associated).setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext.subarray(IV_BYTES, ciphertext.length - TAG_BYTES)), decipher.final()]).toString("utf8");
}

export function createSecrets(kms: Kms): Secrets {
  async function dataKeyOf(db: Db | Tx, organizationId: string) {
    const [row] = await db.select().from(organizationDataKey).where(eq(organizationDataKey.organizationId, organizationId));
    if (!row) throw new Error("the Organization has no data key");
    return Buffer.from(await kms.unwrap(row.wrappedKey, organizationId));
  }

  async function dataKeyForWriting(tx: Tx, organizationId: string) {
    const [existing] = await tx.select().from(organizationDataKey).where(eq(organizationDataKey.organizationId, organizationId));
    if (existing) return Buffer.from(await kms.unwrap(existing.wrappedKey, organizationId));
    const fresh = randomBytes(32);
    // Two first writes at once: the second waits for the first to commit, then finds its key and uses that one.
    await tx
      .insert(organizationDataKey)
      .values({ organizationId, wrappedKey: Buffer.from(await kms.wrap(fresh, organizationId)) })
      .onConflictDoNothing();
    return dataKeyOf(tx, organizationId);
  }

  return {
    async create(tx, organizationId, value) {
      const dataKey = await dataKeyForWriting(tx, organizationId);
      const id = crypto.randomUUID();
      await tx.insert(secret).values({ id, organizationId, ciphertext: encrypt(dataKey, value, aad(organizationId, id)) });
      return id;
    },
    async replace(tx, organizationId, secretId, value) {
      const dataKey = await dataKeyForWriting(tx, organizationId);
      const replaced = await tx
        .update(secret)
        .set({ ciphertext: encrypt(dataKey, value, aad(organizationId, secretId)) })
        .where(and(eq(secret.id, secretId), eq(secret.organizationId, organizationId)))
        .returning({ id: secret.id });
      if (replaced.length === 0) throw new Error("no such secret");
    },
    async open(db, organizationId, secretId) {
      const [row] = await db
        .select({ ciphertext: secret.ciphertext })
        .from(secret)
        .where(and(eq(secret.id, secretId), eq(secret.organizationId, organizationId)));
      if (!row) throw new Error("no such secret");
      return decrypt(await dataKeyOf(db, organizationId), row.ciphertext, aad(organizationId, secretId));
    },
  };
}
