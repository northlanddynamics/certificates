// A test-only issuer kind that answers "pending", as a CA reached through an Agent does: while `holding`, every Issuance
// it is asked for is held, under a handle of its own and with a deadline 7 days from the clock, and the test then
// has it report the result as such a kind would, through Issuances.report. What it reports issued is what the
// platform's own issuer (a Private CA's, in the tests) issues for the request it held. Otherwise it is the platform's own.
// Likewise, while `holdingRevocations`, every revocation it is asked for is held, for a CA that confirms later, and the
// test has it confirm or refuse through Revocations.report. What it confirms is recorded, but no CRL is reissued for it,
// as no CA of the platform's own revoked it.
import type { Db, Tx } from "../../src/platform/db/client";
import type { Issuances } from "../../src/issuance/issuance";
import type { IssueRequest, Issued, Issuer, Issuers } from "../../src/issuance/issuer";
import type { Revocations } from "../../src/issuance/revocations";
import type { RevocationReason } from "../../src/pki/revocation-reasons";

type Held = { db: Db | Tx; organizationId: string; issuer: Issuer; request: IssueRequest };

/** A revocation it holds: the Revocation Request's id, the Certificate (PEM) and the reason, in the order asked. */
export type HeldRevocation = { requestId: string; handle: string; certificate: string; reason: RevocationReason };

const DEADLINE_MS = 7 * 86_400_000;

export class HeldIssuer {
  /** Whether Issuances are held; off unless a test turns it on. */
  holding = false;
  /** Whether revocations are held; off unless a test turns it on. */
  holdingRevocations = false;
  /** The revocations it was asked for and holds, in the order asked. */
  readonly revocations: HeldRevocation[] = [];
  /** What it was asked for and holds, by Issuance. */
  private readonly held = new Map<string, Held>();
  private platform: Issuers | undefined;
  private issuances: Issuances | undefined;
  private revocationsTo: Revocations | undefined;
  private count = 0;

  constructor(private readonly clock: () => Date) {}

  /** The platform's issuers, with this kind in front of them. */
  wrap(platform: Issuers): Issuers {
    this.platform = platform;
    return {
      ...platform,
      issue: async (db, organizationId, issuer, request) => {
        if (!this.holding) return platform.issue(db, organizationId, issuer, request);
        const handle = `held-${++this.count}`;
        this.held.set(request.issuanceId, { db, organizationId, issuer, request });
        return { pending: { handle, deadline: new Date(this.clock().getTime() + DEADLINE_MS) } };
      },
      revoke: async (tx, change, organizationId, issuedBy, requests) => {
        if (!this.holdingRevocations) return platform.revoke(tx, change, organizationId, issuedBy, requests);
        return requests.map(({ requestId, certificate, reason }) => {
          const handle = `held-revocation-${++this.count}`;
          this.revocations.push({ requestId, handle, certificate, reason });
          return { pending: { handle, deadline: new Date(this.clock().getTime() + DEADLINE_MS) } };
        });
      },
    };
  }

  /** Where it reports results. */
  reportTo(issuances: Issuances, revocations: Revocations) {
    this.issuances = issuances;
    this.revocationsTo = revocations;
  }

  /** Reports that the CA revoked the held revocation's Certificate; what Revocations.report answers. */
  confirmRevocation(requestId: string) {
    this.heldRevocation(requestId);
    return this.revocationsTo!.report(requestId, "revoked");
  }

  /** Reports that the CA did not revoke it, as `revoke` would throw it. */
  refuseRevocation(requestId: string, error: unknown) {
    this.heldRevocation(requestId);
    return this.revocationsTo!.report(requestId, { failed: error });
  }

  /** What the platform's own issuer issues for the held request. */
  async issue(issuanceId: string): Promise<Issued> {
    const held = this.heldFor(issuanceId);
    const issued = await this.platform!.issue(held.db, held.organizationId, held.issuer, held.request);
    if ("pending" in issued) throw new Error("the platform's own issuer answered pending");
    return issued;
  }

  /** Reports the Certificate the platform's own issuer issues for the held request; what Issuances.report answers. */
  async release(issuanceId: string) {
    return this.issuances!.report(issuanceId, await this.issue(issuanceId));
  }

  /** Reports that the CA failed, as `issue` would throw it. */
  fail(issuanceId: string, error: unknown) {
    this.heldFor(issuanceId);
    return this.issuances!.report(issuanceId, { failed: error });
  }

  /** Reports that the request is pending still, under a new handle and deadline. */
  stillPending(issuanceId: string, handle: string, deadline: Date) {
    this.heldFor(issuanceId);
    return this.issuances!.report(issuanceId, { pending: { handle, deadline } });
  }

  reset() {
    this.holding = false;
    this.held.clear();
    this.holdingRevocations = false;
    this.revocations.length = 0;
    this.count = 0;
  }

  private heldRevocation(requestId: string) {
    const held = this.revocations.find((r) => r.requestId === requestId);
    if (!held) throw new Error(`no revocation ${requestId} is held`);
    return held;
  }

  private heldFor(issuanceId: string) {
    const held = this.held.get(issuanceId);
    if (!held) throw new Error(`no Issuance ${issuanceId} is held`);
    return held;
  }
}
