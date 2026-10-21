// The ACME CAs an Organization can issue from: a directory URL and what is shown of it. Let's Encrypt Staging and Let's
// Encrypt Production are built in, the same for every Organization, and never change; they are defined here, by stable
// ids, and not stored. An ACME Account (acme-accounts.ts) and a Managed Certificate's issuer (issuer.ts) refer to an ACME
// CA by its id. Its environment tag is a label of intent and changes nothing about how it issues.
import { z } from "@hono/zod-openapi";

export const ACME_CA_TAGS = ["staging", "production"] as const;
export type AcmeCaTag = (typeof ACME_CA_TAGS)[number];

export interface AcmeCa {
  id: string;
  name: string;
  /** Where its ACME directory is served. */
  directoryUrl: string;
  /** What it is for, as a label; none for an untagged one. */
  tag: AcmeCaTag | null;
  /** Built into the platform, shared by every Organization and read-only. */
  builtIn: boolean;
}

export const BUILT_IN_ACME_CAS = [
  { id: "letsencrypt-staging", name: "Let's Encrypt Staging", directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory", tag: "staging", builtIn: true },
  { id: "letsencrypt-production", name: "Let's Encrypt Production", directoryUrl: "https://acme-v02.api.letsencrypt.org/directory", tag: "production", builtIn: true },
] as const satisfies readonly AcmeCa[];
export type BuiltInAcmeCaId = (typeof BUILT_IN_ACME_CAS)[number]["id"];

/** The ACME CA a Managed Certificate or an ACME Account is for when none is named: staging, to try an Issuance there first. */
export const DEFAULT_ACME_CA_ID: BuiltInAcmeCaId = "letsencrypt-staging";

/** An ACME CA's id, in a request; whether it is one the Organization can use is the route's to check. */
export const AcmeCaId = z.string().min(1).openapi({ description: "An ACME CA's id: `letsencrypt-staging` or `letsencrypt-production` for the built-in ones." });

export interface AcmeCas {
  /** Every ACME CA the Organization can use, the built-in ones first, staging before production. */
  list(organizationId: string): Promise<AcmeCa[]>;
  /** The ACME CA by its id, when the Organization can use it; none otherwise. */
  find(organizationId: string, id: string): Promise<AcmeCa | null>;
  /** The ACME CA something of the Organization's refers to; one it cannot use is gone, which a stored reference never is but for a bug. */
  get(organizationId: string, id: string): Promise<AcmeCa>;
}

/** The ACME CAs, with the built-in ones' directories at `directoryUrls` where given (read each time, so tests may repoint them at Pebble). */
export function createAcmeCas({ directoryUrls = {} }: { directoryUrls?: Partial<Record<BuiltInAcmeCaId, string>> } = {}): AcmeCas {
  const builtIn = (): AcmeCa[] => BUILT_IN_ACME_CAS.map((ca) => ({ ...ca, directoryUrl: directoryUrls[ca.id] ?? ca.directoryUrl }));
  const find = async (_organizationId: string, id: string) => builtIn().find((ca) => ca.id === id) ?? null;
  return {
    list: async () => builtIn(),
    find,
    async get(organizationId, id) {
      const ca = await find(organizationId, id);
      if (!ca) throw new Error(`the ACME CA ${id} is gone`);
      return ca;
    },
  };
}
