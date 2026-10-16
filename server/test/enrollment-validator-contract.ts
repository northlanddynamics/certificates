// The contract every Enrollment Validator kind keeps (enrollment-validator.ts), whatever service it talks to: it takes the
// settings and secret it is configured with, allows or refuses a request as its service says, throws rather than allows
// when its service cannot be reached, tells its service of each outcome and throws when it could not (so that the
// platform tells it again), tests its connection without validating anything, and, when it has a revocation feed, hands
// over the Revocations its service asks for and reports their outcomes. Each kind runs it against a double of its
// service: the test kind in enrollment-validator-seam.test.ts, Intune against the Intune double.
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createCsr, generateRsaKeyPair } from "ts-scep";
import type { DecidedRequest, EnrollmentRequest, EnrollmentValidatorKind, IssuedDeviceCertificate, RevocationOutcome } from "../src/enrollment-validator";

/** What the contract needs of a kind's service double. */
export interface ValidatorServiceDouble {
  /** Has the service allow every request from now on. */
  allow(): void;
  /** Has the service refuse every request from now on. */
  refuse(): void;
  /** Has no call reach the service, or every call reach it again. */
  setUnreachable(unreachable: boolean): void;
  /** The transaction IDs of the requests the service was asked to validate, in order. */
  validated(): string[];
  /** The transaction IDs and serials the service was told were issued, in order. */
  issued(): { transactionId: string; serial: string }[];
  /** The transaction IDs the service was told failed, in order. */
  failed(): string[];
  /** Queues a Revocation of the serial and issuer for the service's feed to hand over (kinds with a feed only). */
  queueRevocation?(serial: string, issuer: string): void;
  /** The outcomes the service was told of, in order (kinds with a feed only). */
  revocationOutcomes?(): RevocationOutcome["outcome"][];
}

export interface ValidatorUnderContract<Settings> {
  kind: EnrollmentValidatorKind<Settings>;
  /** Settings and a secret the service takes. */
  settings: Settings;
  secret: string;
  /** A secret the service refuses (kinds that take one only). */
  wrongSecret?: string;
  service: ValidatorServiceDouble;
}

/** A request as a device would send it, with a fresh key, and a certificate as the platform would issue it for it. */
async function aRequest(transactionId: string): Promise<{ request: EnrollmentRequest; decided: DecidedRequest; certificate: IssuedDeviceCertificate }> {
  const { privateKey } = generateRsaKeyPair(2048);
  const csr = createCsr({ subject: "CN=contract-device", privateKey, challengePassword: "contract-challenge" });
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const issued = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "5b0e7a",
    name: "CN=Contract Issuing CA",
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2027-01-01T00:00:00Z"),
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
  });
  const der = new Uint8Array(csr);
  return {
    request: { csr: der, challengePassword: "contract-challenge", transactionId },
    decided: { csr: der, transactionId },
    certificate: { pem: issued.toString("pem"), serial: "5B0E7A", notAfter: issued.notAfter, issuer: issued.issuer },
  };
}

export function enrollmentValidatorContract<Settings>(name: string, setup: () => ValidatorUnderContract<Settings> | Promise<ValidatorUnderContract<Settings>>) {
  describe(`${name}: the Enrollment Validator contract`, () => {
    const open = async () => {
      const under = await setup();
      under.service.allow();
      under.service.setUnreachable(false);
      return { ...under, validator: under.kind.create(under.kind.settings.parse(under.settings), under.secret) };
    };

    test("its configuration is what its kind declares: the settings parse, and the secret too when it takes one", async () => {
      const { kind, settings, secret } = await setup();
      expect(kind.settings.safeParse(settings).success).toBe(true);
      if (kind.secret) expect(kind.secret.safeParse(secret).success).toBe(true);
      expect(typeof kind.vouchesForNames).toBe("boolean");
    });

    test("allows a request its service allows, and refuses with a reason one its service refuses", async () => {
      const { validator, service } = await open();
      const allowed = await aRequest("contract-allowed");
      expect(await validator.validate(allowed.request)).toEqual({ allowed: true });

      service.refuse();
      const refused = await aRequest("contract-refused");
      const decision = await validator.validate(refused.request);
      expect(decision.allowed).toBe(false);
      expect(decision.allowed ? "" : decision.reason).not.toBe("");
      expect(service.validated()).toEqual(["contract-allowed", "contract-refused"]);
    });

    test("throws, rather than allowing, when its service cannot be reached", async () => {
      const { validator, service } = await open();
      service.setUnreachable(true);
      await expect(validator.validate((await aRequest("contract-unreachable")).request)).rejects.toThrow();
    });

    test("tells its service of an issued request and of a failed one, and throws when it could not, so that it is told again", async () => {
      const { validator, service } = await open();
      const issued = await aRequest("contract-issued");
      await validator.issued(issued.decided, issued.certificate);
      const failed = await aRequest("contract-failed");
      await validator.failed(failed.decided, "the Enrollment Profile does not allow a rsa-1024 key");
      expect(service.issued()).toEqual([{ transactionId: "contract-issued", serial: "5B0E7A" }]);
      expect(service.failed()).toEqual(["contract-failed"]);

      service.setUnreachable(true);
      await expect(validator.issued(issued.decided, issued.certificate)).rejects.toThrow();
      await expect(validator.failed(failed.decided, "refused")).rejects.toThrow();
    });

    test("tests its connection without validating anything, and fails the test when its service cannot be reached or refuses its secret", async () => {
      const under = await open();
      await under.validator.test();
      expect(under.service.validated()).toEqual([]);

      if (under.wrongSecret !== undefined) {
        await expect(under.kind.create(under.kind.settings.parse(under.settings), under.wrongSecret).test()).rejects.toThrow();
      }
      under.service.setUnreachable(true);
      await expect(under.validator.test()).rejects.toThrow();
    });

    test("when it has a revocation feed, hands over what its service asks to revoke, once, and reports the outcomes", async () => {
      const { kind, validator, service } = await open();
      if (!kind.revocationFeed) {
        expect(validator.revocations).toBeUndefined();
        return;
      }
      expect(validator.revocations).toBeDefined();
      expect(kind.revocationFeed.intervalMs).toBeGreaterThan(0);
      service.queueRevocation!("5B0E7A", "CN=Contract Issuing CA");

      const pulled = await validator.revocations!.pull();
      expect(pulled.map((r) => [r.serial.toUpperCase(), r.issuer])).toEqual([["5B0E7A", "CN=Contract Issuing CA"]]);
      expect(pulled[0]!.ref).not.toBe("");
      expect(await validator.revocations!.pull()).toEqual([]);

      await validator.revocations!.report([{ ref: pulled[0]!.ref, outcome: "revoked" }]);
      expect(service.revocationOutcomes!()).toEqual(["revoked"]);
      service.setUnreachable(true);
      await expect(validator.revocations!.report([{ ref: pulled[0]!.ref, outcome: "revoked" }])).rejects.toThrow();
    });
  });
}
