// Renewal: when a Managed Certificate is due for one, and what a failed one costs. A Renewal Policy says whether the
// scheduler renews a Managed Certificate (automatic) or only a person does (manual), and how many days before its
// current Certificate ends it is due. A failed Renewal is tried again after a delay that doubles each time up to a
// ceiling; how many have failed is read from the Issuances since the last that succeeded, so there is no counter to
// get out of step. An automatic Renewal is due at the earlier of the policy's days and a time within the window the CA's
// ACME Renewal Information (ARI) suggests. The scheduler (renewal-scheduler.ts) and the API's view of a Managed
// Certificate share this.
import { and, asc, desc, eq, inArray, sql } from "drizzle-orm";
import type { Db } from "./db/client";
import { certificate, issuance } from "./db/schema";
import type { IssuanceFailureCode } from "./issuance-failure";

export const RENEWAL_MODES = ["automatic", "manual"] as const;
export type RenewalMode = (typeof RENEWAL_MODES)[number];

export const MAX_RENEWAL_DAYS = 365;

export interface RenewalPolicy {
  mode: RenewalMode;
  daysBeforeExpiry: number;
}

/** The first failed Renewal is tried again after this long; each failure after it doubles the wait. */
const FIRST_RETRY_MS = 10 * 60_000;
/** The wait never grows past this, so a lasting failure is still looked at every few hours. */
const LONGEST_RETRY_MS = 6 * 3_600_000;
/** A Certificate is never due in the first tenth of its life, so a Renewal Policy of more days than it lives cannot make it renew again as soon as it is issued. */
const EARLIEST_DUE_FRACTION = 0.1;

/** How long to wait before trying again after `failures` Renewals in a row have failed. */
export const retryDelayMs = (failures: number) => Math.min(FIRST_RETRY_MS * 2 ** Math.max(0, failures - 1), LONGEST_RETRY_MS);

/** When a Certificate is due for Renewal under the policy: its days before it ends, but not before a tenth of its life has passed. */
export function dueAt(certificate: { notBefore: Date; notAfter: Date }, daysBeforeExpiry: number): Date {
  const lived = certificate.notAfter.getTime() - certificate.notBefore.getTime();
  const byPolicy = certificate.notAfter.getTime() - daysBeforeExpiry * 86_400_000;
  return new Date(Math.max(byPolicy, certificate.notBefore.getTime() + lived * EARLIEST_DUE_FRACTION));
}

/** The window of time the CA suggests renewing a Certificate in. */
export interface RenewalWindow {
  start: Date;
  end: Date;
}

/** What makes a Certificate due: the Renewal Policy's days, or the time chosen within the CA's window. */
export type DueBecause = "policy" | "ari";

/**
 * A time within the CA's window for the Certificate: a point in it that its fingerprint decides, so that it is the same
 * on every pass and differs between Certificates, which spreads the Renewals the CA suggests for a whole window.
 */
export function timeWithin(window: RenewalWindow, fingerprint: string): Date {
  const fraction = parseInt(fingerprint.slice(0, 8), 16) / 0x1_0000_0000;
  return new Date(window.start.getTime() + Math.floor(fraction * (window.end.getTime() - window.start.getTime())));
}

/**
 * When an automatic Renewal is due, and why: the policy's days (not before a tenth of the Certificate's life) or the
 * time chosen within the CA's window, whichever comes first. The CA's window is not held to the tenth: a CA that asks
 * for a Renewal early has a reason, such as a revocation to come.
 */
export function renewalDue(
  current: { notBefore: Date; notAfter: Date; fingerprint: string },
  daysBeforeExpiry: number,
  window: RenewalWindow | null,
): { at: Date; because: DueBecause } {
  const byPolicy = dueAt(current, daysBeforeExpiry);
  if (!window) return { at: byPolicy, because: "policy" };
  const byWindow = timeWithin(window, current.fingerprint);
  return byWindow < byPolicy ? { at: byWindow, because: "ari" } : { at: byPolicy, because: "policy" };
}

/** The Renewals that have failed since a Managed Certificate's last Certificate was issued. */
export interface RenewalFailures {
  failures: number;
  last: { code: IssuanceFailureCode; message: string; at: Date };
}

/** For each of the Managed Certificates that has had any, its failed Issuances since the last that succeeded. */
export async function failuresOf(db: Db, managedCertificateIds: string[]): Promise<Map<string, RenewalFailures>> {
  const out = new Map<string, RenewalFailures>();
  if (managedCertificateIds.length === 0) return out;
  const rows = await db
    .select()
    .from(issuance)
    .where(
      and(
        inArray(issuance.managedCertificateId, managedCertificateIds),
        eq(issuance.status, "failed"),
        sql`${issuance.createdAt} > coalesce((select max(s.created_at) from ${issuance} as s where s.managed_certificate_id = ${issuance.managedCertificateId} and s.status = 'succeeded'), '-infinity'::timestamptz)`,
      ),
    )
    .orderBy(asc(issuance.createdAt), asc(issuance.id));
  for (const row of rows) {
    const soFar = out.get(row.managedCertificateId);
    out.set(row.managedCertificateId, {
      failures: (soFar?.failures ?? 0) + 1,
      last: { code: row.failureCode ?? "internal", message: row.failureMessage ?? "", at: row.finishedAt ?? row.startedAt },
    });
  }
  return out;
}

/** The earliest the scheduler will try to renew: when it is due, and when the backoff after its last failure has passed. None for a manual Managed Certificate, which only a person renews. */
export function nextAttemptAt(
  policy: RenewalPolicy,
  current: { notBefore: Date; notAfter: Date; fingerprint: string } | null,
  failed: RenewalFailures | undefined,
  window: RenewalWindow | null,
): Date | null {
  if (policy.mode !== "automatic" || !current) return null;
  const { at: due } = renewalDue(current, policy.daysBeforeExpiry, window);
  if (!failed) return due;
  return new Date(Math.max(due.getTime(), failed.last.at.getTime() + retryDelayMs(failed.failures)));
}

/** Each Managed Certificate's most recent Certificate, as a subquery to join. */
export const currentCertificates = (db: Db) =>
  db
    .selectDistinctOn([certificate.managedCertificateId], {
      id: certificate.id,
      organizationId: certificate.organizationId,
      managedCertificateId: certificate.managedCertificateId,
      fingerprint: certificate.fingerprint,
      notBefore: certificate.notBefore,
      notAfter: certificate.notAfter,
      issuerKind: certificate.issuerKind,
      environment: certificate.environment,
      acmeAccountId: certificate.acmeAccountId,
      privateCaId: certificate.privateCaId,
      chainPem: certificate.chainPem,
    })
    .from(certificate)
    .orderBy(certificate.managedCertificateId, desc(certificate.createdAt), desc(certificate.id))
    .as("current");
