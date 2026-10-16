// The Enrollment Validator: the pluggable integration an Enrollment Profile names, which decides whether a device's
// enrollment request may be issued. The kinds the platform runs are given to the app (`AppDeps.enrollmentValidators`),
// by kind name; a profile names one of them. This is the tracer's cut of the seam: deciding only. Telling the kind the
// outcome, its connection test, its credentials (Secrets), its revocation feed and whether it vouches for names come
// with the seam itself (`.scratch/device-enrollment/issues/03-enrollment-validator-seam.md`).

/** One enrollment request, as a validator is asked about it: after the SCEP envelope is opened and its signer verified. */
export interface EnrollmentRequest {
  /** The PKCS #10 request, DER. */
  csr: Uint8Array;
  /** The CSR's PKCS #9 challengePassword, if it has one. */
  challengePassword?: string;
  /** The SCEP transaction ID. */
  transactionId: string;
}

export type EnrollmentDecision = { allowed: true } | { allowed: false; reason: string };

export interface EnrollmentValidatorKind {
  /** Whether the request may be issued. Throws when the validator cannot be asked, which refuses it too. */
  validate(request: EnrollmentRequest): Promise<EnrollmentDecision>;
}

/** The validator kinds the platform runs, by the name a profile gives. None are built in yet. */
export type EnrollmentValidators = Record<string, EnrollmentValidatorKind>;
