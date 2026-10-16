// A test-only Enrollment Validator service and the kind that talks to it (`test_double` in the harness), standing in for
// a device management platform such as Intune: it records what it was asked and told, can be told to refuse or to be
// unreachable, takes only its own credential, and keeps a queue of Revocations to feed. The seam's contract
// (enrollment-validator-contract.ts) runs against it, and the platform's scenario tests drive it through the harness.
import { z } from "@hono/zod-openapi";
import type { DecidedRequest, EnrollmentRequest, EnrollmentValidatorKind, IssuedDeviceCertificate, RevocationOutcome, RevocationRequest } from "../src/enrollment-validator";
import type { RevocationReason } from "../src/revocation-reasons";

/** The credential the service takes; anything else is refused as unauthorized. */
export const DOUBLE_SECRET = "double-app-secret";

export class ValidatorDouble {
  /** What it was asked to validate, and told of, in order, with the tenant each came for. */
  readonly validations: (EnrollmentRequest & { tenant: string })[] = [];
  readonly issued: { tenant: string; request: DecidedRequest; certificate: IssuedDeviceCertificate }[] = [];
  readonly failed: { tenant: string; request: DecidedRequest; reason: string }[] = [];
  readonly reports: { tenant: string; outcomes: RevocationOutcome[] }[] = [];
  /** The tenant of each pull of its feed, in order. */
  readonly pulls: string[] = [];
  /** How many connection tests reached it. */
  tests = 0;
  /** When set, it refuses every request with this code. */
  refusing: string | null = null;
  /** When set, no call reaches it. */
  unreachable = false;
  private queue: (RevocationRequest & { tenant: string })[] = [];
  private refs = 0;

  /** Queues a Revocation for the tenant's feed, as the service would when a device is retired. */
  queueRevocation(tenant: string, serial: string, issuer?: string, reason: RevocationReason = "cessationOfOperation") {
    this.queue.push({ tenant, ref: `request-${++this.refs}`, serial, issuer, reason });
  }

  reset() {
    this.validations.length = this.issued.length = this.failed.length = this.reports.length = this.pulls.length = 0;
    this.tests = 0;
    this.refusing = null;
    this.unreachable = false;
    this.queue = [];
  }

  /** The call reaches the service with this credential, or throws as a client of it would. */
  private reach(secret: string) {
    if (this.unreachable) throw new Error("the validator service did not answer");
    if (secret !== DOUBLE_SECRET) throw new Error("the validator service answered 401: unauthorized");
  }

  /** The kind, as a platform registers it; `vouchesForNames` as given. */
  kind({ vouchesForNames = true }: { vouchesForNames?: boolean } = {}): EnrollmentValidatorKind<{ tenant: string }> {
    const double = this;
    return {
      settings: z.object({ tenant: z.string().min(1) }).strict(),
      secret: z.string().min(1),
      vouchesForNames,
      revocationFeed: { intervalMs: 3_600_000, sourceOf: ({ tenant }) => tenant },
      create({ tenant }, secret) {
        return {
          async validate(request) {
            double.reach(secret);
            double.validations.push({ ...request, tenant });
            return double.refusing ? { allowed: false, reason: double.refusing } : { allowed: true };
          },
          async issued(request, certificate) {
            double.reach(secret);
            double.issued.push({ tenant, request, certificate });
          },
          async failed(request, reason) {
            double.reach(secret);
            double.failed.push({ tenant, request, reason });
          },
          async test() {
            double.reach(secret);
            double.tests++;
          },
          revocations: {
            async pull() {
              double.reach(secret);
              double.pulls.push(tenant);
              const pulled = double.queue.filter((r) => r.tenant === tenant);
              double.queue = double.queue.filter((r) => r.tenant !== tenant);
              return pulled.map(({ tenant: _, ...request }) => request);
            },
            async report(outcomes) {
              double.reach(secret);
              double.reports.push({ tenant, outcomes });
            },
          },
        };
      },
    };
  }
}
