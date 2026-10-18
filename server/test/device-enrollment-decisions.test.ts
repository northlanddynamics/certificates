// Device enrollment's own interface (device-enrollment.ts), beneath any protocol: what an Enrollment Profile answers a
// request, in which order its checks refuse, which refusals are kept as the transaction's answer, and when its
// Enrollment Validator is asked. The SCEP routes that adapt it are covered by device-enrollment.test.ts and the others.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { eq } from "drizzle-orm";
import { createCsr, generateRsaKeyPair } from "ts-scep";
import { enrollmentProfile } from "../src/platform/db/schema";
import type { DeviceEnrollmentRequest } from "../src/enrollment/device-enrollment";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

/** A new Enrollment Profile of the validator kind on a new Private CA's Issuing CA, as it is stored, with what its create response shows. */
async function createProfile(kind: string, extra: Record<string, unknown> = {}) {
  const ca = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(ca.status).toBe(201);
  const res = await h.api(`/api/organizations/${org.orgId}/enrollment-profiles`, { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId: ca.body.issuingCas[0].id, validator: { kind }, ...extra } });
  expect(res.status).toBe(201);
  return { created: res.body as { id: string; sharedChallenge?: { challenge: string } }, row: await rowOf(res.body.id) };
}

const rowOf = async (id: string) => (await h.db.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, id)))[0]!;

let transactions = 0;
/** A first enrollment's request for a device with a new key. */
function requestOf({ keyBits = 2048, challengePassword, dns = [], transactionId = `tx-${++transactions}` }: { keyBits?: number; challengePassword?: string; dns?: string[]; transactionId?: string } = {}): DeviceEnrollmentRequest {
  const { privateKey } = generateRsaKeyPair(keyBits);
  const csr = createCsr({ subject: "CN=device-01, O=Acme", privateKey, challengePassword, subjectAltNames: { dns } });
  return { csr, challengePassword, transactionId };
}

const refusalsOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items.filter((e: { action: string }) => e.action === "enrollment.refused");

describe("device enrollment", () => {
  test("issues a Device Certificate with the chain above it, and answers its transaction the same again", async () => {
    const { row } = await createProfile("test_allow");
    const request = requestOf();
    const answer = await h.deviceEnrollment.enroll(row, request);
    if (!("issued" in answer)) throw new Error(`refused: ${JSON.stringify(answer)}`);
    const certificate = new x509.X509Certificate(answer.issued.certificatePem);
    expect(certificate.subject).toBe("O=Acme, CN=device-01");
    // The Issuing CA's certificate, then the root.
    expect(answer.issued.chainPem).toHaveLength(2);
    expect(certificate.issuer).toBe(new x509.X509Certificate(answer.issued.chainPem[0]!).subject);

    // Asked again, even with another key, the transaction keeps its answer, and the validator is not asked again.
    expect(await h.deviceEnrollment.enroll(row, { ...requestOf(), transactionId: request.transactionId })).toEqual(answer);
    expect(await h.deviceEnrollment.answerOf(row, request.transactionId)).toEqual(answer);
    expect(h.enrollmentValidations).toHaveLength(1);
  });

  test("knows no transaction it was never asked", async () => {
    const { row } = await createProfile("test_allow");
    expect(await h.deviceEnrollment.answerOf(row, "never-asked")).toBeUndefined();
  });

  test("refuses a key the profile does not allow before its validator is asked, and keeps the refusal as the transaction's answer", async () => {
    const { row } = await createProfile("test_allow");
    const request = requestOf({ keyBits: 1024 });
    const answer = await h.deviceEnrollment.enroll(row, request);
    expect(answer).toEqual({ refused: "the Enrollment Profile does not allow a 1024-bit RSA key (rsa-1024); it allows rsa-2048, rsa-3072, rsa-4096" });
    expect(h.enrollmentValidations).toHaveLength(0);
    // A good key under the same transaction is still refused.
    expect(await h.deviceEnrollment.enroll(row, { ...requestOf(), transactionId: request.transactionId })).toEqual(answer);
    const refusals = await refusalsOf();
    expect(refusals).toHaveLength(1);
    expect(refusals[0].detail.reason).toBe((answer as { refused: string }).refused);
  });

  test("refuses a name outside the Issuing CA's Permitted Name Rules before its validator is asked", async () => {
    const { row } = await createProfile("test_allow");
    const answer = await h.deviceEnrollment.enroll(row, requestOf({ dns: ["laptop.elsewhere.test"] }));
    expect("refused" in answer && answer.refused).toContain("laptop.elsewhere.test");
    expect(h.enrollmentValidations).toHaveLength(0);
  });

  test("refuses a renewal under a kind that does not allow one", async () => {
    const { row } = await createProfile("test_allow");
    const first = await h.deviceEnrollment.enroll(row, requestOf());
    if (!("issued" in first)) throw new Error("refused");
    const signedWith = new Uint8Array(new x509.X509Certificate(first.issued.certificatePem).rawData);
    expect(await h.deviceEnrollment.enroll(row, { ...requestOf(), renewalSignedWith: signedWith })).toEqual({ refused: "RenewalReq is not supported: enroll again with PKCSReq" });
  });

  test("refuses everything of a profile whose validator kind the platform no longer runs, without keeping the refusal", async () => {
    const { row } = await createProfile("test_allow");
    const gone = { ...row, validatorKind: "no_longer_run" };
    const request = requestOf();
    expect(await h.deviceEnrollment.enroll(gone, request)).toEqual({ refused: "the Enrollment Validator no_longer_run is not available" });
    // Not the transaction's answer: under a kind it runs, the same transaction is decided afresh.
    expect(await h.deviceEnrollment.answerOf(gone, request.transactionId)).toBeUndefined();
    expect("issued" in (await h.deviceEnrollment.enroll(row, request))).toBe(true);
  });
});

describe("device enrollment under a Shared Challenge profile", () => {
  test("refuses a request without the Shared Challenge before anything else, without keeping the refusal, then issues the transaction with it", async () => {
    const { row, created } = await createProfile("shared_challenge");
    // A key the profile would refuse too: the Shared Challenge is checked first, so the device learns nothing of the profile.
    const without = requestOf({ keyBits: 1024, challengePassword: "not-the-challenge" });
    const answer = await h.deviceEnrollment.enroll(row, without);
    expect("refused" in answer && answer.refused).not.toContain("key");
    expect(await h.deviceEnrollment.answerOf(row, without.transactionId)).toBeUndefined();

    const withIt = requestOf({ challengePassword: created.sharedChallenge!.challenge, transactionId: without.transactionId });
    expect("issued" in (await h.deviceEnrollment.enroll(row, withIt))).toBe(true);
  });

  test("renews a Device Certificate signed with, and supersedes it", async () => {
    const { row, created } = await createProfile("shared_challenge");
    const first = await h.deviceEnrollment.enroll(row, requestOf({ challengePassword: created.sharedChallenge!.challenge }));
    if (!("issued" in first)) throw new Error("refused");
    const current = new x509.X509Certificate(first.issued.certificatePem);
    // A renewal needs no Shared Challenge: it is signed with the Device Certificate it replaces.
    const renewed = await h.deviceEnrollment.enroll(row, { ...requestOf(), renewalSignedWith: new Uint8Array(current.rawData) });
    expect("issued" in renewed).toBe(true);
    const again = await h.deviceEnrollment.enroll(row, { ...requestOf(), renewalSignedWith: new Uint8Array(current.rawData) });
    expect(again).toEqual({ refused: `the Device Certificate the RenewalReq is signed with (${current.serialNumber.toUpperCase()}) is revoked` });
  });
});
