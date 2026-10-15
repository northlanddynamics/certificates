// The CA's ACME Renewal Information (ARI) for current Certificates, kept for the Renewal scheduler. A CA's window for
// a Certificate can move (earlier, ahead of a revocation, say), so each is asked about again when the CA's Retry-After
// says to, and what was last said is stored (renewal_info) for the scheduler and the API to read. Like the scheduler
// it keeps no state of its own: what is due to be asked is read from the table.
import { and, eq, inArray, isNull, lte, or, sql } from "drizzle-orm";
import { certificateIssuerOf, type Issuers } from "./issuer";
import type { Db } from "./db/client";
import { managedCertificate, renewalInfo } from "./db/schema";
import { renewsAutomatically } from "./issuance";
import { currentCertificates, type RenewalWindow } from "./renewal";

/** Asked again after this when the CA gave no Retry-After, or offered no ARI (it may come to), or did not know the Certificate. */
const DEFAULT_RECHECK_MS = 6 * 3_600_000;
/** Whatever the CA asks, it is asked again within a day: its windows are meant to be followed, not forgotten. */
const LONGEST_RECHECK_MS = 24 * 3_600_000;
/** Not asked again sooner than this, whatever the CA says, so a Retry-After of zero is no invitation to ask on every pass. */
const SHORTEST_RECHECK_MS = 60_000;
/** Asked again after this when it could not be reached or answered badly. */
const FAILED_RECHECK_MS = 15 * 60_000;
/** One pass asks about this many Certificates at most, this many at a time, so a first pass over many does not hold up the rest. */
const PER_PASS = 100;
const AT_ONCE = 10;

/** What the CA last said about a Certificate: its window (none if it offered none) and when it was, and will next be, asked. */
export interface RenewalInformation {
  window: RenewalWindow | null;
  checkedAt: Date | null;
  nextCheckAt: Date;
}

/** What the CA last said about each of these Certificates, by Certificate; nothing for one never asked about. */
export async function informationOf(db: Db, certificateIds: string[]): Promise<Map<string, RenewalInformation>> {
  const out = new Map<string, RenewalInformation>();
  if (certificateIds.length === 0) return out;
  for (const row of await db.select().from(renewalInfo).where(inArray(renewalInfo.certificateId, certificateIds))) {
    out.set(row.certificateId, {
      window: row.windowStart && row.windowEnd ? { start: row.windowStart, end: row.windowEnd } : null,
      checkedAt: row.checkedAt,
      nextCheckAt: row.nextCheckAt,
    });
  }
  return out;
}

/**
 * Asks the CA about the current Certificate of every automatic, live, approved Managed Certificate that is due to be
 * asked, and stores what it says at `now`. It never throws for one Certificate's trouble.
 */
export async function refreshRenewalInfo({ db, issuers, now }: { db: Db; issuers: Issuers; now: Date }): Promise<void> {
  const current = currentCertificates(db);
  const due = await db
    .select({ id: current.id, organizationId: current.organizationId, issuerKind: current.issuerKind, environment: current.environment, acmeAccountId: current.acmeAccountId, issuingCaId: current.issuingCaId, chainPem: current.chainPem })
    .from(managedCertificate)
    .innerJoin(current, eq(current.managedCertificateId, managedCertificate.id))
    .leftJoin(renewalInfo, eq(renewalInfo.certificateId, current.id))
    .where(
      and(
        renewsAutomatically,
        // One that has ended is past a window.
        sql`${current.notAfter} > ${now}`,
        or(isNull(renewalInfo.certificateId), lte(renewalInfo.nextCheckAt, now)),
      ),
    )
    .orderBy(sql`${renewalInfo.nextCheckAt} nulls first`)
    .limit(PER_PASS);

  const after = (ms: number) => new Date(now.getTime() + ms);
  async function ask(row: (typeof due)[number]) {
    try {
      const info = await issuers.renewalInfo(certificateIssuerOf(row), row.chainPem);
      const retry = info?.retryAfterMs == null ? DEFAULT_RECHECK_MS : Math.min(Math.max(info.retryAfterMs, SHORTEST_RECHECK_MS), LONGEST_RECHECK_MS);
      const values = { windowStart: info?.window.start ?? null, windowEnd: info?.window.end ?? null, checkedAt: now, nextCheckAt: after(retry) };
      await db
        .insert(renewalInfo)
        .values({ certificateId: row.id, organizationId: row.organizationId, ...values })
        .onConflictDoUpdate({ target: renewalInfo.certificateId, set: values });
    } catch (err) {
      console.error("could not ask the CA about the renewal of", row.id, err);
      // What the CA last said stands; it is only asked again later.
      await db
        .insert(renewalInfo)
        .values({ certificateId: row.id, organizationId: row.organizationId, nextCheckAt: after(FAILED_RECHECK_MS) })
        .onConflictDoUpdate({ target: renewalInfo.certificateId, set: { nextCheckAt: after(FAILED_RECHECK_MS) } })
        .catch((e) => console.error("could not record that", e));
    }
  }
  for (let i = 0; i < due.length; i += AT_ONCE) await Promise.all(due.slice(i, i + AT_ONCE).map(ask));
}
