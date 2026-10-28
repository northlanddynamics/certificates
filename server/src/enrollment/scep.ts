// The SCEP server (RFC 8894): public, unauthenticated routes at each Enrollment Profile's opaque public id, where devices
// enroll. ts-scep handles the protocol, running as the profile's RA: it opens each request's envelope with the RA key and
// verifies its signer, and signs the CertRep with the RA key, encrypted to the device. What is issued is decided by
// device enrollment (device-enrollment.ts); this is its SCEP adapter, which rate limits the routes and answers a device
// SUCCESS with its certificate or FAILURE with a failInfo, or, on an ADCS CA, PENDING until ADCS has answered, which the
// device asks after with GetCertInitial. A profile with no RA certificate yet (on an ADCS CA, until ADCS first issues
// one) serves no SCEP.
import type { OpenAPIHono } from "@hono/zod-openapi";
import { eq } from "drizzle-orm";
import type { Context } from "hono";
import { getConnInfo } from "hono/bun";
import { FailInfo, ScepServer, type ScepResult } from "ts-scep";
import type { Db } from "../platform/db/client";
import { enrollmentProfile } from "../platform/db/schema";
import type { DeviceEnrollment, DeviceEnrollmentAnswer } from "./device-enrollment";
import { enrollmentIssuerOf, type EnrollmentIssuers } from "./enrollment-issuer";
import { kindOf, type EnrollmentValidators } from "./enrollment-validator";
import type { Secrets } from "../platform/crypto/secrets";

/**
 * How the SCEP routes are rate limited, so that a flood of requests cannot exhaust the platform or a validator's service:
 * at most `perAddress` requests from one source address and `perProfile` to one Enrollment Profile in each window of
 * `windowMs`, every SCEP operation counting. Beyond that a request is answered 429 before it is looked at. The counts are
 * the process's own: each server behind a load balancer counts what reaches it.
 */
export interface ScepConfig {
  windowMs: number;
  perAddress: number;
  perProfile: number;
  /**
   * Whether the source address is the last in X-Forwarded-For, as the TLS terminator in front of the platform adds it,
   * rather than the connection's; set only when there is one, or devices could choose the address they are counted by.
   */
  trustForwardedFor: boolean;
}

/** A device enrolls with three requests or so (GetCACaps, GetCACert, PKIOperation), and many may share a NAT address. */
export const SCEP_DEFAULTS: ScepConfig = { windowMs: 60_000, perAddress: 120, perProfile: 3000, trustForwardedFor: false };

/** Counts requests per key in fixed windows of the clock; `take` answers how many seconds until the key may go on, when it may not now. */
function createRateLimiter(clock: () => Date) {
  let windowStart = 0;
  let counts = new Map<string, number>();
  return {
    take(key: string, limit: number, windowMs: number): number | undefined {
      const now = clock().getTime();
      if (now >= windowStart + windowMs || now < windowStart) {
        windowStart = now - (now % windowMs);
        counts = new Map();
      }
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);
      return count > limit ? Math.ceil((windowStart + windowMs - now) / 1000) : undefined;
    },
    reset() {
      counts = new Map();
    },
  };
}

/**
 * What GetCACaps advertises (RFC 8894, 3.5.2), with Renewal where the profile's validator allows it. What is accepted is
 * wider, for the clients in the field: SHA-1 signatures and 3DES or single DES content encryption (micromdm's scepclient
 * uses DES whatever it is offered), and RSA-OAEP key transport besides PKCS#1 v1.5 (Windows), which RFC 8894 has no
 * keyword for. CertRep answers with the key transport the request used.
 */
const CAPABILITIES = ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard"];

/** A device's answer, as SCEP sends it. */
function resultOf(answer: DeviceEnrollmentAnswer): ScepResult {
  if ("issued" in answer) return { status: "success", certificates: [answer.issued.certificatePem, ...answer.issued.chainPem] };
  if ("refused" in answer) return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: answer.refused };
  if ("pending" in answer) return { status: "pending" };
  return { status: "failure", failInfo: FailInfo.badRequest, failInfoText: "the transaction is still being decided; send it again later" };
}

export function registerScep(ctx: {
  app: OpenAPIHono;
  db: Db;
  secrets: Secrets;
  issuers: EnrollmentIssuers;
  enrollment: DeviceEnrollment;
  kinds: EnrollmentValidators;
  clock: () => Date;
  /** Read on each request, so that it may be changed while the app runs. */
  config?: Partial<ScepConfig>;
}) {
  const { app, db, secrets, issuers, enrollment, kinds, clock } = ctx;
  const config = () => ({ ...SCEP_DEFAULTS, ...ctx.config });
  const limiter = createRateLimiter(clock);

  /**
   * The SCEP server of the profile with this public id, whatever its Organization: the id, unguessable, is all a device
   * has. None when there is no such profile, and "no RA" while it has no RA certificate.
   */
  async function serverOf(publicId: string) {
    const [profile] = await db.select().from(enrollmentProfile).where(eq(enrollmentProfile.publicId, publicId));
    if (!profile) return undefined;
    if (profile.raCertificatePem === null) return "no RA" as const;
    const [issuing, ...above] = await issuers.chainOf(db, profile.organizationId, enrollmentIssuerOf(profile));
    return new ScepServer({
      ca: { certificate: issuing!, chain: above },
      ra: { certificate: profile.raCertificatePem, privateKey: await secrets.open(db, profile.organizationId, profile.raKeySecretId) },
      capabilities: kindOf(kinds, profile.validatorKind)?.allowsRenewal ? [...CAPABILITIES, "Renewal"] : CAPABILITIES,
      handler: {
        // ts-scep has already checked that a RenewalReq's signer was issued by the CA certificate GetCACert serves.
        enroll: async (request) =>
          resultOf(
            await enrollment.enroll(profile, {
              csr: request.csr.der,
              challengePassword: request.csr.challengePassword,
              transactionId: request.transactionId,
              ...(request.renewal && { renewalSignedWith: request.signerCertificate.raw }),
            }),
          ),
        // GetCertInitial: a client answered PENDING asks after its request, and any may ask after one it sent.
        async poll(request) {
          const answer = await enrollment.answerOf(profile, request.transactionId);
          return answer ? resultOf(answer) : { status: "failure", failInfo: FailInfo.badCertId, failInfoText: "no such transaction" };
        },
      },
    });
  }

  /** Where the request came from, as the rate limit counts it. */
  function sourceAddressOf(c: Context): string {
    if (config().trustForwardedFor) {
      const hops = c.req.header("x-forwarded-for")?.split(",") ?? [];
      const last = hops.at(-1)?.trim();
      if (last) return last;
    }
    try {
      return getConnInfo(c).remote.address ?? "unknown";
    } catch {
      return "unknown";
    }
  }

  // Windows' SCEP client appends /pkiclient.exe to the URL it is given; others use it as it is.
  app.on(["GET", "POST"], ["/scep/:publicId", "/scep/:publicId/pkiclient.exe"], async (c) => {
    const { windowMs, perAddress, perProfile } = config();
    const limited = (retryAfter: number) => c.text("too many requests", 429, { "retry-after": String(retryAfter) });
    const addressWait = limiter.take(`address:${sourceAddressOf(c)}`, perAddress, windowMs);
    if (addressWait !== undefined) return limited(addressWait);
    // Counted before the profile is looked up and its RA key opened, which a flood would otherwise cost each time.
    const publicId = c.req.param("publicId");
    const profileWait = limiter.take(`profile:${publicId}`, perProfile, windowMs);
    if (profileWait !== undefined) return limited(profileWait);
    const server = await serverOf(publicId);
    if (!server) return c.text("not found", 404);
    if (server === "no RA") return c.text("the Enrollment Profile has no RA certificate yet: it serves SCEP once ADCS issues one", 503, { "retry-after": "300" });
    return server.fetchHandler(c.req.raw);
  });

  return {
    /** Forgets every count, as if a new window began. */
    resetRateLimits: () => limiter.reset(),
  };
}
