// What the platform records of a Certificate's revocation: the shape the API gives it and how it is read. A Certificate
// is immutable, so that it was revoked is a record of its own. The route that revokes is in revocation-routes.ts.
import { z } from "@hono/zod-openapi";
import { inArray } from "drizzle-orm";
import { REVOCATION_REASONS } from "../pki/revocation-reasons";
import type { Db, Tx } from "../platform/db/client";
import { certificateRevocation } from "../platform/db/schema";

export const RevocationReasonName = z.enum(Object.keys(REVOCATION_REASONS) as [keyof typeof REVOCATION_REASONS, ...(keyof typeof REVOCATION_REASONS)[]]);

export const Revocation = z.object({
  reason: RevocationReasonName.openapi({ description: "The RFC 5280 reason the CA was given." }),
  revokedAt: z.string(),
  revokedBy: z.object({ id: z.string(), email: z.string() }),
});

export type RevocationRow = typeof certificateRevocation.$inferSelect;

export const toRevocation = (row: RevocationRow) => ({
  reason: row.reason,
  revokedAt: row.revokedAt.toISOString(),
  revokedBy: { id: row.revokedById, email: row.revokedByEmail },
});

/** The revocation of each of the Certificates, for those that were revoked. */
export async function revocationsOf(db: Db | Tx, certificateIds: string[]): Promise<Map<string, RevocationRow>> {
  if (certificateIds.length === 0) return new Map();
  const rows = await db.select().from(certificateRevocation).where(inArray(certificateRevocation.certificateId, certificateIds));
  return new Map(rows.map((row) => [row.certificateId, row]));
}
