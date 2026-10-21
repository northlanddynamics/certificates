// The ACME CAs an Organization can issue from: a directory URL and what is shown of it. Let's Encrypt Staging and Let's
// Encrypt Production are built in, the same for every Organization, and never change; they are defined here, by stable
// ids, and not stored. An Organization may add custom ones of its own (`acme_ca`, by a UUID), each created together with
// its ACME Account (acme-accounts.ts), with the External Account Binding a CA may require for that. An ACME Account and a Managed Certificate's issuer (issuer.ts) refer to an ACME
// CA by its id. Its environment tag is a label of intent and changes nothing about how it issues.
import { z } from "@hono/zod-openapi";
import { and, asc, eq } from "drizzle-orm";
import type { Db } from "../../platform/db/client";
import { acmeCa } from "../../platform/db/schema";

export const ACME_CA_TAGS = ["staging", "production"] as const;
export type AcmeCaTag = (typeof ACME_CA_TAGS)[number];

export interface AcmeCa {
  id: string;
  name: string;
  /** Where its ACME directory is served. */
  directoryUrl: string;
  /** What it is for, as a label; none for an untagged one. */
  tag: AcmeCaTag | null;
  /** The key id of the External Account Binding its account was registered with, for a CA that requires one; its HMAC key is a secret, kept apart. */
  externalAccountKeyId: string | null;
  /** Built into the platform, shared by every Organization and read-only. */
  builtIn: boolean;
}

export const BUILT_IN_ACME_CAS = [
  { id: "letsencrypt-staging", name: "Let's Encrypt Staging", directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory", tag: "staging", externalAccountKeyId: null, builtIn: true },
  { id: "letsencrypt-production", name: "Let's Encrypt Production", directoryUrl: "https://acme-v02.api.letsencrypt.org/directory", tag: "production", externalAccountKeyId: null, builtIn: true },
] as const satisfies readonly AcmeCa[];
export type BuiltInAcmeCaId = (typeof BUILT_IN_ACME_CAS)[number]["id"];

/** The ACME CA a Managed Certificate or an ACME Account is for when none is named: staging, to try an Issuance there first. */
export const DEFAULT_ACME_CA_ID: BuiltInAcmeCaId = "letsencrypt-staging";

/** An ACME CA's id, in a request; whether it is one the Organization can use is the route's to check. */
export const AcmeCaId = z.string().min(1).openapi({ description: "An ACME CA's id: `letsencrypt-staging` or `letsencrypt-production` for the built-in ones, a UUID for a custom one." });

export interface AcmeCas {
  /** Every ACME CA the Organization can use, the built-in ones first, staging before production, then its custom ones in the order they were added. */
  list(organizationId: string): Promise<AcmeCa[]>;
  /** The ACME CA by its id, when the Organization can use it; none otherwise. */
  find(organizationId: string, id: string): Promise<AcmeCa | null>;
  /** The ACME CA something of the Organization's refers to; one it cannot use is gone, which a stored reference never is but for a bug. */
  get(organizationId: string, id: string): Promise<AcmeCa>;
}

/** A custom ACME CA as the ACME CA it is. */
export const customAcmeCa = ({ id, name, directoryUrl, tag, externalAccountKeyId }: typeof acmeCa.$inferSelect): AcmeCa => ({ id, name, directoryUrl, tag, externalAccountKeyId, builtIn: false });

/** The ACME CAs, with the built-in ones' directories at `directoryUrls` where given (read each time, so tests may repoint them at Pebble). */
export function createAcmeCas({ db, directoryUrls = {} }: { db: Db; directoryUrls?: Partial<Record<BuiltInAcmeCaId, string>> }): AcmeCas {
  const builtIn = (): AcmeCa[] => BUILT_IN_ACME_CAS.map((ca) => ({ ...ca, directoryUrl: directoryUrls[ca.id] ?? ca.directoryUrl }));
  const find = async (organizationId: string, id: string) => {
    const ca = builtIn().find((ca) => ca.id === id);
    if (ca) return ca;
    // Not a UUID can't be a custom one; asking Postgres would only raise a type error.
    if (!z.uuid().safeParse(id).success) return null;
    const [row] = await db.select().from(acmeCa).where(and(eq(acmeCa.organizationId, organizationId), eq(acmeCa.id, id)));
    return row ? customAcmeCa(row) : null;
  };
  return {
    async list(organizationId) {
      const custom = await db.select().from(acmeCa).where(eq(acmeCa.organizationId, organizationId)).orderBy(asc(acmeCa.createdAt), asc(acmeCa.id));
      return [...builtIn(), ...custom.map(customAcmeCa)];
    },
    find,
    async get(organizationId, id) {
      const ca = await find(organizationId, id);
      if (!ca) throw new Error(`the ACME CA ${id} is gone`);
      return ca;
    },
  };
}
