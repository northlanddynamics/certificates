// A test-only issuer kind that answers "pending", as a CA reached through an Agent does: while `holding`, every Issuance
// it is asked for is held, under a handle of its own and with a deadline 7 days from the clock, and the test then
// has it report the result as such a kind would, through Issuances.report. What it reports issued is what the
// platform's own issuer (a Private CA's, in the tests) issues for the request it held. Otherwise it is the platform's own.
import type { Db, Tx } from "../../src/platform/db/client";
import type { Issuances } from "../../src/issuance/issuance";
import type { IssueRequest, Issued, Issuer, Issuers } from "../../src/issuance/issuer";

type Held = { db: Db | Tx; organizationId: string; issuer: Issuer; request: IssueRequest };

const DEADLINE_MS = 7 * 86_400_000;

export class HeldIssuer {
  /** Whether Issuances are held; off unless a test turns it on. */
  holding = false;
  /** What it was asked for and holds, by Issuance. */
  private readonly held = new Map<string, Held>();
  private platform: Issuers | undefined;
  private issuances: Issuances | undefined;
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
    };
  }

  /** Where it reports results. */
  reportTo(issuances: Issuances) {
    this.issuances = issuances;
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
    this.count = 0;
  }

  private heldFor(issuanceId: string) {
    const held = this.held.get(issuanceId);
    if (!held) throw new Error(`no Issuance ${issuanceId} is held`);
    return held;
  }
}
