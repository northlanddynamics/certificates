// The Intune Enrollment Validator against the Intune double: the seam's contract, and what Intune's API is sent
// (docs/research/intune-scep-api.md), which the contract leaves to each kind.
import { beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createHash } from "node:crypto";
import { createCsr, generateRsaKeyPair } from "ts-scep";
import { createIntuneKind, INTUNE_CALLER_INFO } from "../src/intune";
import { enrollmentValidatorContract } from "./enrollment-validator-contract";
import { INTUNE, IntuneDouble } from "./intune-double";

const double = new IntuneDouble();
const kind = createIntuneKind({ fetch: double.fetch });
const SETTINGS = { tenantId: INTUNE.tenantId, appId: INTUNE.appId };

enrollmentValidatorContract("Intune", () => {
  double.reset();
  return {
    kind,
    settings: SETTINGS,
    secret: INTUNE.secret,
    wrongSecret: "not-the-entra-secret",
    service: {
      allow: () => void (double.refusing = null),
      refuse: () => void (double.refusing = "ChallengeExpired"),
      setUnreachable: (unreachable) => void (double.unreachable = unreachable),
      validated: () => double.validations.map((v) => v.transactionId),
      issued: () => double.successes.map((s) => ({ transactionId: s.transactionId, serial: s.certificateSerialNumber })),
      failed: () => double.failures.map((f) => f.transactionId),
    },
  };
});

describe("the Intune Enrollment Validator", () => {
  beforeEach(() => double.reset());
  const validator = () => kind.create(kind.settings.parse(SETTINGS), INTUNE.secret);
  const csr = () => new Uint8Array(createCsr({ subject: "CN=device", privateKey: generateRsaKeyPair(2048).privateKey, challengePassword: "intune-challenge" }));

  test("is configured with the Entra tenant and app IDs, and the app secret, and vouches for names", () => {
    expect(kind.vouchesForNames).toBe(true);
    expect(kind.secret!.safeParse("").success).toBe(false);
    expect(kind.settings.safeParse(SETTINGS).success).toBe(true);
    expect(kind.settings.safeParse({ tenantId: "contoso.onmicrosoft.com", appId: INTUNE.appId }).success).toBe(true);
    expect(kind.settings.safeParse({ tenantId: "../evil", appId: INTUNE.appId }).success).toBe(false);
    expect(kind.settings.safeParse({ tenantId: INTUNE.tenantId, appId: "not-a-guid" }).success).toBe(false);
    expect(kind.settings.safeParse({ ...SETTINGS, secret: INTUNE.secret }).success).toBe(false);
  });

  test("sends Intune the whole CSR, with its challenge in it, and the SCEP transaction ID, as the platform", async () => {
    const der = csr();
    expect(await validator().validate({ csr: der, challengePassword: "intune-challenge", transactionId: "tx-1" })).toEqual({ allowed: true });
    expect(double.validations).toEqual([{ transactionId: "tx-1", certificateRequest: Buffer.from(der).toString("base64"), callerInfo: INTUNE_CALLER_INFO }]);
    const call = double.requests.find((r) => r.url.endsWith("/ScepActions/validateRequest"))!;
    expect(call.headers["api-version"]).toBe("2018-02-20");
    expect(call.headers["client-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("refuses with Intune's code as the reason", async () => {
    double.refusing = "ScepProfileNoLongerTargetedToTheClient";
    const decision = await validator().validate({ csr: csr(), challengePassword: "c", transactionId: "tx-2" });
    expect(decision.allowed).toBe(false);
    expect(decision.allowed ? "" : decision.reason).toStartWith("ScepProfileNoLongerTargetedToTheClient");
  });

  test("fails rather than allows when Intune answers with an error", async () => {
    double.failing = true;
    await expect(validator().validate({ csr: csr(), transactionId: "tx-3" })).rejects.toThrow(/503/);
  });

  test("tells Intune of success with the certificate's SHA-1 thumbprint, hex serial, expiry and issuer, and of failure with E_FAIL", async () => {
    const der = csr();
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "0a5b0e7a",
      name: "CN=Acme Issuing CA 1, O=Acme",
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T09:30:00Z"),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    await validator().issued({ csr: der, transactionId: "tx-4" }, { pem: cert.toString("pem"), serial: "0A5B0E7A", notAfter: cert.notAfter, issuer: cert.issuer });
    expect(double.successes).toEqual([
      {
        transactionId: "tx-4",
        certificateRequest: Buffer.from(der).toString("base64"),
        certificateThumbprint: createHash("sha1").update(new Uint8Array(cert.rawData)).digest("hex").toUpperCase(),
        certificateSerialNumber: "0A5B0E7A",
        certificateExpirationDateUtc: "2027-01-01T09:30:00.000Z",
        issuingCertificateAuthority: "CN=Acme Issuing CA 1, O=Acme",
        callerInfo: INTUNE_CALLER_INFO,
        caConfiguration: null,
        certificateAuthority: null,
      } as never,
    ]);

    await validator().failed({ csr: der, transactionId: "tx-5" }, "x".repeat(300));
    expect(double.failures).toEqual([{ transactionId: "tx-5", certificateRequest: Buffer.from(der).toString("base64"), hResult: 0x80004005, errorDescription: "x".repeat(255), callerInfo: INTUNE_CALLER_INFO }]);
  });

  test("tests its connection by getting both tokens and discovering both services, never calling Intune itself", async () => {
    const result = await validator().test();
    expect(double.intuneCalls()).toEqual([]);
    expect(double.requests.map((r) => new URL(r.url).host)).toEqual(["login.microsoftonline.com", "graph.microsoft.com", "login.microsoftonline.com"]);
    expect(result && result.note).toContain("scep_challenge_provider");
  });

  test("fails the connection test, saying why, when Graph's Application.Read.All is not consented", async () => {
    double.graphConsented = false;
    await expect(validator().test()).rejects.toThrow(/Application\.Read\.All/);
  });

  test("knows a device by the Intune device ID in an IntuneDeviceId:// URI", () => {
    expect(kind.deviceIdOf!([{ type: "dns", value: "a.example" }, { type: "url", value: "IntuneDeviceId://5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11" }])).toBe("5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11");
    expect(kind.deviceIdOf!([{ type: "url", value: "intunedeviceid://5B1E4F0E-8B2C-4A57-9A1D-0C6F3E2A7B11" }])).toBe("5B1E4F0E-8B2C-4A57-9A1D-0C6F3E2A7B11");
    expect(kind.deviceIdOf!([{ type: "url", value: "https://example.com/" }])).toBeUndefined();
    expect(kind.deviceIdOf!([{ type: "url", value: "IntuneDeviceId://" }])).toBeUndefined();
  });
});
