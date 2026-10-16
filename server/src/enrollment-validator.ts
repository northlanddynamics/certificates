// The Enrollment Validator seam: the pluggable integration an Enrollment Profile names, which decides whether a device's
// enrollment request may be issued, is told the outcome, and may feed Revocations. A kind is described by plain data (its
// non-secret settings and its write-only secret), like a DNS Provider kind, and `create` makes a running validator from
// them; the secret is opened only then (enrollment-validators.ts), never shown or logged. The kinds the platform runs are
// ENROLLMENT_VALIDATOR_KINDS (enrollment-validator-kinds.ts) unless the app is given others (`AppDeps.enrollmentValidators`).
// Every kind keeps the contract in server/test/enrollment-validator-contract.ts.
import type { z } from "@hono/zod-openapi";
import type { RevocationReason } from "./revocation-reasons";

/** One enrollment request, as a validator is asked about it: after the SCEP envelope is opened and its signer verified. */
export interface EnrollmentRequest {
  /** The PKCS #10 request, DER. */
  csr: Uint8Array;
  /** The CSR's PKCS #9 challengePassword, if it has one. */
  challengePassword?: string;
  /** The SCEP transaction ID. */
  transactionId: string;
}

/** A request as a validator is told of its outcome: the challenge, used up by then, is not kept to tell it. */
export type DecidedRequest = Omit<EnrollmentRequest, "challengePassword">;

export type EnrollmentDecision = { allowed: true } | { allowed: false; reason: string };

/** The Device Certificate a request was issued. */
export interface IssuedDeviceCertificate {
  /** PEM. */
  pem: string;
  /** Upper-case hex, as Revocation requests name it. */
  serial: string;
  notAfter: Date;
  /** The Issuing CA's subject (RFC 4514). */
  issuer: string;
}

/** A Device Certificate a validator's feed asks to have revoked, by serial and issuer, and why. */
export interface RevocationRequest {
  /** What the kind needs to tell this request's outcome apart from the others'; given back with it. */
  ref: string;
  /** Hex, of any case. */
  serial: string;
  /** The Issuing CA's subject (RFC 4514); any Issuing CA when none. */
  issuer?: string;
  reason: RevocationReason;
}

/**
 * What became of a RevocationRequest: `revoked` now, `already_revoked` before, `not_found` among the Device Certificates of
 * the profiles the feed is for, or `failed` (such as the CRL not being signed), which may be asked again.
 */
export interface RevocationOutcome {
  ref: string;
  outcome: "revoked" | "already_revoked" | "not_found" | "failed";
  message?: string;
}

/**
 * What a validator throws when its service cannot be reached, refuses its credentials or answers what it should not. Its
 * message is shown to administrators and kept, so it must say what went wrong without ever holding the secret or a token.
 * Anything else a validator throws is taken for a bug in it, and its message is neither shown nor kept nor logged.
 */
export class EnrollmentValidatorError extends Error {}

/** What may be shown, kept and logged of an error a validator threw. */
export const describeValidatorError = (err: unknown) =>
  err instanceof EnrollmentValidatorError ? err.message.replace(/\u0000/g, "").slice(0, 1000) : `the Enrollment Validator failed unexpectedly (${err instanceof Error ? err.name : typeof err})`;

/** A validator, running with its settings and secret. Every call throws an EnrollmentValidatorError when its service cannot be reached. */
export interface EnrollmentValidator {
  /** Whether the request may be issued. Throws when the validator cannot be asked, which refuses it too. */
  validate(request: EnrollmentRequest): Promise<EnrollmentDecision>;
  /** Tells it the request was issued. Throws when it could not be told: it is told again later, so at least once. */
  issued(request: DecidedRequest, certificate: IssuedDeviceCertificate): Promise<void>;
  /** Tells it a request it was asked about was refused after all (by it, or after it allowed it). At least once, like `issued`. */
  failed(request: DecidedRequest, reason: string): Promise<void>;
  /**
   * Resolves when the service can be reached with these settings and secret, without validating or revoking anything;
   * with a note for the administrator when the test could not prove everything (shown, so it must hold no secret).
   */
  test(): Promise<void | { note?: string }>;
  /** Its revocation feed, when its kind has one. */
  revocations?: {
    /** The Revocations it asks for now. What is pulled is not asked for again, so each is answered by `report`. */
    pull(): Promise<RevocationRequest[]>;
    /** Tells it what became of each, once the Revocations have committed. At least once, like `issued`. */
    report(outcomes: RevocationOutcome[]): Promise<void>;
  };
}

/** One kind of Enrollment Validator: what it is configured with, and how to run one from that. */
export interface EnrollmentValidatorKind<Settings = any> {
  /** The non-secret configuration, which the API shows. */
  settings: z.ZodType<Settings>;
  /** The write-only credential, as the string the Organization supplies; none for a kind that needs none. */
  secret?: z.ZodType<string>;
  /**
   * Whether it checks the subject and SANs a device asks for, as Intune does. A profile whose validator does not must
   * carry name rules (name-rules.ts), which the platform checks instead.
   */
  vouchesForNames: boolean;
  /**
   * That it feeds Revocations: profiles whose settings give the same `sourceOf` share one feed, which is pulled once,
   * at most once every `intervalMs`, for all of them.
   */
  revocationFeed?: { intervalMs: number; sourceOf(settings: Settings): string };
  /**
   * The device a request came from as the kind knows it, from the subject alternative names the device asked for (such as
   * Intune's device ID, in an `IntuneDeviceId://` URI); none when they do not say. Device Certificates can be found by it.
   */
  deviceIdOf?(subjectAltNames: { type: string; value: string }[]): string | undefined;
  /** A validator that runs with the settings and the secret (an empty string for a kind without one). */
  create(settings: Settings, secret: string): EnrollmentValidator;
}

/** The validator kinds the platform runs, by the name a profile gives. */
export type EnrollmentValidators = Record<string, EnrollmentValidatorKind>;
