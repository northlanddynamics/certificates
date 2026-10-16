// Device enrollment validated by Intune: an Organization Administrator connects an Enrollment Profile to their Intune
// tenant through an Entra app, tests the connection, and from then on only the requests Intune vouches for are issued,
// and Intune is told each outcome. The platform runs its own Intune kind against the Intune double, and every check is
// of what a device, an administrator and Intune see: SCEP answers, the API, Audit Events and Intune's recorded calls.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { createHash } from "node:crypto";
import { FailInfo, ScepFailureError } from "ts-scep";
import { PASSWORD, createHarness, type Harness } from "./harness";
import { INTUNE } from "./intune-double";
import { scepDevice, type DeviceRequest } from "./scep-device";

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const DEVICE_ID = "5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11";
const INTUNE_VALIDATOR = { kind: "intune", settings: { tenantId: INTUNE.tenantId, appId: INTUNE.appId }, secret: INTUNE.secret };
const profiles = () => `/api/organizations/${org.orgId}/enrollment-profiles`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; detail: any }[];
const enroll = (scepUrl: string, request: DeviceRequest) => scepDevice(h, scepUrl).enroll(request).catch((err: unknown) => err);

let cas = 0;
/** A new Enrollment Profile on a new Issuing CA, connected to Intune unless another validator is given; the API's answer. */
async function createIntuneProfile(validator: Record<string, unknown> = INTUNE_VALIDATOR, extra: Record<string, unknown> = {}) {
  const ca = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
    cookie: org.cookie,
    body: { name: `Devices ${++cas}`, subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(ca.status).toBe(201);
  const issuing = ca.body.issuingCas[0] as { id: string; subject: string };
  return h.api(profiles(), { cookie: org.cookie, body: { name: `Wi-Fi ${cas}`, issuingCaId: issuing.id, validator, ...extra } });
}

describe("an Enrollment Profile connected to Intune", () => {
  test("is configured with the Entra tenant ID, app ID and app secret, which is never shown or audited", async () => {
    const res = await createIntuneProfile();
    expect(res.status).toBe(201);
    expect(res.body.validator).toEqual({ kind: "intune", settings: { tenantId: INTUNE.tenantId, appId: INTUNE.appId }, hasSecret: true });
    expect(res.body.nameRules).toBeNull();
    const kinds = await h.api(`/api/organizations/${org.orgId}/enrollment-validator-kinds`, { cookie: org.cookie });
    expect(kinds.body.items).toContainEqual({ kind: "intune", vouchesForNames: true, takesSecret: true, allowsRenewal: false });

    const shown = JSON.stringify([(await h.api(`${profiles()}/${res.body.id}`, { cookie: org.cookie })).body, await auditOf()]);
    expect(shown).not.toContain(INTUNE.secret);
  });

  test("is refused without a secret, with bad IDs, or with name rules, since Intune vouches for names", async () => {
    expect((await createIntuneProfile({ ...INTUNE_VALIDATOR, secret: undefined })).status).toBe(400);
    const badTenant = await createIntuneProfile({ ...INTUNE_VALIDATOR, settings: { tenantId: "contoso/../x", appId: INTUNE.appId } });
    expect(badTenant.status).toBe(400);
    expect(JSON.stringify(badTenant.body)).not.toContain(INTUNE.secret);
    expect((await createIntuneProfile({ ...INTUNE_VALIDATOR, settings: { tenantId: INTUNE.tenantId } })).status).toBe(400);
    const nameRules = { requiredSubjectAttributes: [], subjectPatterns: {}, allowedSanTypes: ["dns"], sanPatterns: {} };
    expect((await createIntuneProfile(INTUNE_VALIDATOR, { nameRules })).status).toBe(422);
  });

  test("tests its connection: both tokens and Intune's services, never a validation, and audited", async () => {
    const profile = (await createIntuneProfile()).body;
    const res = await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, body: {} });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.note).toContain("scep_challenge_provider");
    expect(h.intune.intuneCalls()).toEqual([]);
    expect(h.intune.requests.map((r) => new URL(r.url).host)).toEqual(["login.microsoftonline.com", "graph.microsoft.com", "login.microsoftonline.com"]);

    h.intune.graphConsented = false;
    const denied = await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, body: {} });
    expect(denied.body.ok).toBe(false);
    expect(denied.body.error).toContain("Application.Read.All");

    const tested = (await auditOf()).filter((e) => e.action === "enrollment_validator.tested");
    expect(tested.map((e) => e.detail.ok).sort()).toEqual([false, true]);
    expect(JSON.stringify(tested)).not.toContain(INTUNE.secret);
  });

  test("fails the connection test, without quoting the secret, when Entra refuses the app's secret", async () => {
    const profile = (await createIntuneProfile({ ...INTUNE_VALIDATOR, secret: "an-old-secret" })).body;
    const res = await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, body: {} });
    expect(res.body.ok).toBe(false);
    expect(res.body.error).toContain("AADSTS7000215");
    expect(res.body.error).not.toContain("an-old-secret");
  });

  test("issues what Intune vouches for, with the device's Intune device ID, and tells Intune the certificate's details", async () => {
    const profile = (await createIntuneProfile()).body;
    const { certificate } = (await enroll(profile.scepUrl, {
      subject: "CN=laptop-17",
      subjectAltNames: { dns: ["laptop-17.devices.acme"], uri: [`IntuneDeviceId://${DEVICE_ID}`] },
      challengePassword: "intune-signed-challenge",
    })) as { certificate: { raw: Buffer } };
    const cert = new x509.X509Certificate(new Uint8Array(certificate.raw));

    expect(h.intune.validations).toHaveLength(1);
    const [validation] = h.intune.validations;
    const csr = new x509.Pkcs10CertificateRequest(Buffer.from(validation!.certificateRequest, "base64"));
    expect(csr.subject).toBe("CN=laptop-17");

    const listed = await h.api(`${profiles()}/${profile.id}/device-certificates?q=${DEVICE_ID}`, { cookie: org.cookie });
    expect(listed.body.items.map((c: { serial: string; deviceId: string }) => [c.serial, c.deviceId])).toEqual([[cert.serialNumber.toUpperCase(), DEVICE_ID]]);
    expect((await auditOf()).find((e) => e.action === "device_certificate.issued")!.detail.deviceId).toBe(DEVICE_ID);

    expect(h.intune.successes).toEqual([]);
    expect(await h.deliverEnrollmentNotifications()).toBe(1);
    expect(h.intune.successes).toEqual([
      expect.objectContaining({
        transactionId: validation!.transactionId,
        certificateRequest: validation!.certificateRequest,
        certificateThumbprint: createHash("sha1").update(new Uint8Array(cert.rawData)).digest("hex").toUpperCase(),
        certificateSerialNumber: cert.serialNumber.toUpperCase(),
        certificateExpirationDateUtc: cert.notAfter.toISOString(),
        issuingCertificateAuthority: cert.issuer,
      }),
    ]);
    expect(h.intune.failures).toEqual([]);
  });

  test("refuses what Intune refuses: FAILURE with Intune's code, enrollment.refused, nothing issued, and Intune told of the failure", async () => {
    const profile = (await createIntuneProfile()).body;
    h.intune.refusing = "ChallengeExpired";
    const failure = await enroll(profile.scepUrl, { subject: "CN=phone-03", challengePassword: "stale-challenge" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((failure as ScepFailureError).failInfo).toBe(FailInfo.badRequest);
    expect((failure as ScepFailureError).failInfoText).toContain("ChallengeExpired");

    const audit = await auditOf();
    expect(audit.some((e) => e.action === "device_certificate.issued")).toBe(false);
    expect(audit.find((e) => e.action === "enrollment.refused")!.detail).toMatchObject({ validator: { kind: "intune" }, transactionId: h.intune.validations[0]!.transactionId });

    expect(await h.deliverEnrollmentNotifications()).toBe(1);
    expect(h.intune.failures).toEqual([expect.objectContaining({ transactionId: h.intune.validations[0]!.transactionId, hResult: 0x80004005 })]);
    expect(h.intune.failures[0]!.errorDescription).toContain("ChallengeExpired");
  });

  test.each([
    ["failing", () => void (h.intune.failing = true)],
    ["unreachable", () => void (h.intune.unreachable = true)],
  ])("refuses every request while Intune is %s, issuing nothing, and tells Intune once it can", async (_, breakIntune) => {
    const profile = (await createIntuneProfile()).body;
    breakIntune();
    const failure = await enroll(profile.scepUrl, { subject: "CN=tablet-01", challengePassword: "challenge" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((failure as ScepFailureError).failInfoText).toContain("could not be asked");
    expect((await auditOf()).some((e) => e.action === "device_certificate.issued")).toBe(false);

    h.intune.reset();
    expect(await h.deliverEnrollmentNotifications()).toBe(1);
    expect(h.intune.failures).toHaveLength(1);
  });
});

describe("Intune's revocation queue", () => {
  const MINUTE_MS = 60_000;
  const START = Date.parse("2026-01-01T00:00:00Z");
  /** The CRL a certificate's CRL Distribution Point names, fetched from there as a relying party would. */
  async function crlFor(cert: x509.X509Certificate) {
    const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)!;
    const res = await h.app.request(cdp.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier!);
    expect(res.status).toBe(200);
    return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
  }
  const enrolled = async (scepUrl: string, subject: string) => {
    const { certificate } = (await enroll(scepUrl, { subject, challengePassword: "intune-signed-challenge" })) as { certificate: { raw: Buffer } };
    return new x509.X509Certificate(new Uint8Array(certificate.raw));
  };

  test("revokes the certificate of a device Intune retired: on the CRL once polled, audited with Intune, and the result uploaded once committed", async () => {
    const profile = (await createIntuneProfile()).body;
    const retired = await enrolled(profile.scepUrl, "CN=retired-laptop");
    const kept = await enrolled(profile.scepUrl, "CN=kept-laptop");
    const context = h.intune.queueRevocation(retired.serialNumber.toUpperCase(), retired.issuer);
    const unknown = h.intune.queueRevocation("0123456789ABCDEF");

    h.setNow(new Date(START + 5 * MINUTE_MS));
    expect(await h.pollRevocationFeeds()).toBe(1);
    expect(h.intune.downloads).toEqual([{ maxRequests: 500, issuerName: null }]);
    const crl = await crlFor(retired);
    expect(crl.entries.map((e) => [e.serialNumber.toUpperCase(), e.reason, e.revocationDate.getTime()])).toEqual([
      [retired.serialNumber.toUpperCase(), x509.X509CrlReason.cessationOfOperation, START + 5 * MINUTE_MS],
    ]);
    expect(crl.entries.some((e) => e.serialNumber.toUpperCase() === kept.serialNumber.toUpperCase())).toBe(false);
    const revoked = (await auditOf()).filter((e) => e.action === "device_certificate.revoked");
    expect(revoked.map((e) => e.detail)).toEqual([expect.objectContaining({ serial: retired.serialNumber.toUpperCase(), reason: "cessationOfOperation", by: { enrollmentValidator: { kind: "intune" } } })]);

    expect(h.intune.revocationResults).toEqual([]);
    await h.deliverEnrollmentNotifications();
    expect(h.intune.revocationResults).toEqual([
      { requestContext: context, succeeded: true, errorCode: "0", errorMessage: null },
      { requestContext: unknown, succeeded: false, errorCode: "4004", errorMessage: "No such certificate" },
    ]);
  });

  test("is downloaded at most hourly per tenant, once for every profile in it, whichever Entra app each uses", async () => {
    const first = (await createIntuneProfile()).body;
    const second = (await createIntuneProfile({ kind: "intune", settings: { tenantId: INTUNE.tenantId, appId: INTUNE.otherApp.appId }, secret: INTUNE.otherApp.secret })).body;
    const a = await enrolled(first.scepUrl, "CN=device-a");
    const b = await enrolled(second.scepUrl, "CN=device-b");
    h.intune.queueRevocation(a.serialNumber, a.issuer);
    expect(await h.pollRevocationFeeds()).toBe(1);

    h.intune.queueRevocation(b.serialNumber, b.issuer);
    h.setNow(new Date(START + 59 * MINUTE_MS));
    expect(await h.pollRevocationFeeds()).toBe(0);
    expect((await crlFor(b)).entries).toEqual([]);

    h.setNow(new Date(START + 60 * MINUTE_MS));
    expect(await h.pollRevocationFeeds()).toBe(1);
    expect(h.intune.downloads).toHaveLength(2);
    expect((await crlFor(a)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([a.serialNumber.toUpperCase()]);
    expect((await crlFor(b)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([b.serialNumber.toUpperCase()]);
  });

  test("answers a request for a certificate an Organization Administrator already revoked as a success, keeping the administrator's reason", async () => {
    const profile = (await createIntuneProfile()).body;
    const cert = await enrolled(profile.scepUrl, "CN=stolen-phone");
    const [listed] = (await h.api(`${profiles()}/${profile.id}/device-certificates`, { cookie: org.cookie })).body.items;
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates/${listed.id}/revocation`, { cookie: org.cookie, body: { reason: "keyCompromise" } })).status).toBe(200);

    h.intune.queueRevocation(cert.serialNumber, cert.issuer);
    await h.pollRevocationFeeds();
    await h.deliverEnrollmentNotifications();
    expect(h.intune.revocationResults.map((r) => r.succeeded)).toEqual([true]);
    expect((await crlFor(cert)).entries.map((e) => e.reason)).toEqual([x509.X509CrlReason.keyCompromise]);
  });

  test("uploads the results again while Intune does not record them", async () => {
    const profile = (await createIntuneProfile()).body;
    const cert = await enrolled(profile.scepUrl, "CN=wiped-tablet");
    h.intune.queueRevocation(cert.serialNumber, cert.issuer);
    h.intune.recordsResults = false;
    await h.pollRevocationFeeds();
    await h.deliverEnrollmentNotifications();
    expect(h.intune.revocationResults).toEqual([]);

    h.intune.recordsResults = true;
    h.setNow(new Date(START + 10 * MINUTE_MS));
    await h.deliverEnrollmentNotifications();
    expect(h.intune.revocationResults.map((r) => r.succeeded)).toEqual([true]);
  });
});
