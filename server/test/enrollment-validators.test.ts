// The Enrollment Validator seam, as the platform runs it: a profile names a validator kind, configured with settings and a
// write-only secret, which decides each SCEP request and is told the outcome in the background; a profile whose validator
// does not vouch for names carries name rules the platform enforces; and a validator's revocation feed revokes Device
// Certificates. Validators are the harness's test-only kinds; `test_double` is backed by the validator double.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { FailInfo, ScepFailureError } from "ts-scep";
import { DOUBLE_SECRET } from "./enrollment-validator-double";
import { PASSWORD, createHarness, type Harness } from "./harness";
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

const START = Date.parse("2026-01-01T00:00:00Z");
const MINUTE_MS = 60_000;
const profiles = (orgId = org.orgId) => `/api/organizations/${orgId}/enrollment-profiles`;
const auditOf = async (target = org) => (await h.api(`/api/organizations/${target.orgId}/audit-events`, { cookie: target.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];
const DOUBLE = { kind: "test_double", settings: { tenant: "contoso" }, secret: DOUBLE_SECRET };

let cas = 0;
/** A new Private CA's first Issuing CA, as `id` and `subject`. */
async function createIssuingCa(target = org) {
  const res = await h.api(`/api/organizations/${target.orgId}/private-cas`, {
    cookie: target.cookie,
    body: { name: `Devices ${++cas}`, subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(res.status).toBe(201);
  return { privateCaId: res.body.id as string, ...(res.body.issuingCas[0] as { id: string; subject: string }) };
}

/** A new Enrollment Profile on a new Issuing CA, with this validator and whatever else is given. */
async function createProfile(validator: Record<string, unknown> = DOUBLE, extra: Record<string, unknown> = {}, target = org) {
  const issuing = await createIssuingCa(target);
  const res = await h.api(profiles(target.orgId), { cookie: target.cookie, body: { name: "Wi-Fi", issuingCaId: issuing.id, validator, ...extra } });
  expect(res.status).toBe(201);
  return { ...(res.body as { id: string; scepUrl: string }), issuing };
}

/** Enrolls at the URL; the failure ts-scep throws for a FAILURE answer is returned rather than thrown. */
const enroll = (scepUrl: string, request: DeviceRequest) => scepDevice(h, scepUrl).enroll(request).catch((err: unknown) => err);

describe("a profile's Enrollment Validator", () => {
  test("refuses a request: the device is answered FAILURE with its reason, nothing is issued, and it is told of the failure in the background", async () => {
    const profile = await createProfile();
    h.validatorDouble.refusing = "ChallengeExpired";

    const failure = await enroll(profile.scepUrl, { subject: "CN=device-01", challengePassword: "expired-challenge" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((failure as ScepFailureError).failInfo).toBe(FailInfo.badRequest);
    expect((failure as ScepFailureError).failInfoText).toContain("ChallengeExpired");
    expect(h.validatorDouble.validations.map((v) => [v.tenant, v.challengePassword])).toEqual([["contoso", "expired-challenge"]]);

    const audit = await auditOf();
    expect(audit.some((e) => e.action === "device_certificate.issued")).toBe(false);
    const refused = audit.find((e) => e.action === "enrollment.refused")!;
    expect(refused.detail).toMatchObject({ validator: { kind: "test_double" }, transactionId: h.validatorDouble.validations[0]!.transactionId });
    expect(refused.detail.reason).toContain("ChallengeExpired");

    // Not while the device waited: only once the background pass runs.
    expect(h.validatorDouble.failed).toEqual([]);
    expect(await h.deliverEnrollmentNotifications()).toBe(1);
    expect(h.validatorDouble.failed).toHaveLength(1);
    expect(h.validatorDouble.failed[0]!.request.transactionId).toBe(h.validatorDouble.validations[0]!.transactionId);
    expect(Buffer.from(h.validatorDouble.failed[0]!.request.csr).equals(Buffer.from(h.validatorDouble.validations[0]!.csr))).toBe(true);
    expect(h.validatorDouble.failed[0]!.reason).toContain("ChallengeExpired");
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
  });

  test("is told of an issued request with the certificate's serial, expiry and issuer, in the background, again until it can be told", async () => {
    const profile = await createProfile();
    const { certificate } = (await enroll(profile.scepUrl, { subject: "CN=device-02", subjectAltNames: { dns: ["device-02.devices.acme"] }, challengePassword: "fresh" })) as { certificate: { raw: Buffer } };
    const cert = new x509.X509Certificate(new Uint8Array(certificate.raw));
    expect(h.validatorDouble.issued).toEqual([]);

    h.validatorDouble.unreachable = true;
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
    // Not again before its retry is due.
    h.validatorDouble.unreachable = false;
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
    h.setNow(new Date(START + 2 * MINUTE_MS));
    expect(await h.deliverEnrollmentNotifications()).toBe(1);

    expect(h.validatorDouble.issued).toHaveLength(1);
    const [told] = h.validatorDouble.issued;
    expect(told!.tenant).toBe("contoso");
    expect(told!.request.transactionId).toBe(h.validatorDouble.validations[0]!.transactionId);
    expect(told!.certificate).toMatchObject({ serial: cert.serialNumber.toUpperCase(), issuer: profile.issuing.subject, notAfter: cert.notAfter });
    expect(new x509.X509Certificate(told!.certificate.pem).equal(cert)).toBe(true);
    expect(h.validatorDouble.failed).toEqual([]);
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
  });

  test("that cannot be reached refuses the request: FAILURE, nothing issued, and it is told of the failure once it can be", async () => {
    const profile = await createProfile();
    h.validatorDouble.unreachable = true;

    const failure = await enroll(profile.scepUrl, { subject: "CN=device-03", challengePassword: "challenge" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((failure as ScepFailureError).failInfoText).toContain("could not be asked");
    const audit = await auditOf();
    expect(audit.some((e) => e.action === "device_certificate.issued")).toBe(false);
    expect(audit.filter((e) => e.action === "enrollment.refused")).toHaveLength(1);

    h.validatorDouble.unreachable = false;
    expect(await h.deliverEnrollmentNotifications()).toBe(1);
    expect(h.validatorDouble.failed.map((f) => f.reason)).toEqual([(failure as ScepFailureError).failInfoText!]);
    expect(h.validatorDouble.issued).toEqual([]);
  });

  test("is not asked, or told, of a request refused before it: a key the profile does not allow", async () => {
    const profile = await createProfile(DOUBLE, { allowedKeyTypes: ["rsa-3072"] });
    expect(await enroll(profile.scepUrl, { subject: "CN=device-04", keyBits: 2048 })).toBeInstanceOf(ScepFailureError);
    expect(h.validatorDouble.validations).toEqual([]);
    expect(await h.deliverEnrollmentNotifications()).toBe(0);
    expect(h.validatorDouble.failed).toEqual([]);
  });
});

describe("configuring a profile's Enrollment Validator", () => {
  test("its settings are shown and its secret is held as a Secret, given to it when it runs and never shown", async () => {
    const profile = await createProfile();
    const shown = await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie });
    expect(shown.body.validator).toEqual({ kind: "test_double", settings: { tenant: "contoso" }, hasSecret: true });
    expect(shown.body.nameRules).toBeNull();
    expect(JSON.stringify(shown.body)).not.toContain(DOUBLE_SECRET);
    expect(JSON.stringify((await h.api(profiles(), { cookie: org.cookie })).body)).not.toContain(DOUBLE_SECRET);
    const audit = await auditOf();
    expect(audit.find((e) => e.action === "enrollment_profile.created")!.detail.validator).toEqual({ kind: "test_double", settings: { tenant: "contoso" } });
    expect(JSON.stringify(audit)).not.toContain(DOUBLE_SECRET);

    // The double takes only its own credential, so an issue shows the secret reached it.
    expect(await enroll(profile.scepUrl, { subject: "CN=device-05" })).not.toBeInstanceOf(ScepFailureError);
  });

  test("is refused settings its kind does not take, a missing secret, or one its kind takes none of", async () => {
    const issuing = await createIssuingCa();
    const create = (validator: Record<string, unknown>) => h.api(profiles(), { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId: issuing.id, validator } });

    expect((await create({ ...DOUBLE, settings: { tenant: "" } })).status).toBe(400);
    expect((await create({ ...DOUBLE, settings: { tenant: "contoso", other: 1 } })).status).toBe(400);
    const missing = await create({ kind: "test_double", settings: { tenant: "contoso" } });
    expect(missing.status).toBe(400);
    expect(missing.body.error ?? missing.body.message ?? JSON.stringify(missing.body)).toContain("secret");
    expect((await create({ kind: "test_allow", secret: "not-wanted" })).status).toBe(400);
    expect((await create(DOUBLE)).status).toBe(201);
  });

  test("lists the kinds the platform runs, with whether each vouches for names and takes a secret", async () => {
    const kinds = (await h.api(`/api/organizations/${org.orgId}/enrollment-validator-kinds`, { cookie: org.cookie })).body.items;
    expect(kinds).toEqual([
      { kind: "test_allow", vouchesForNames: true, takesSecret: false },
      { kind: "test_names", vouchesForNames: false, takesSecret: false },
      { kind: "test_double", vouchesForNames: true, takesSecret: true },
      { kind: "intune", vouchesForNames: true, takesSecret: true },
    ]);
  });
});

describe("name rules", () => {
  const RULES = {
    requiredSubjectAttributes: ["CN"],
    subjectPatterns: { CN: ["kiosk-*"], O: ["Acme"] },
    allowedSanTypes: ["dns", "url"],
    sanPatterns: { dns: ["*.devices.acme"] },
  };

  test("a profile whose validator does not vouch for names must have them, and one whose validator does may not", async () => {
    const issuing = await createIssuingCa();
    const create = (body: Record<string, unknown>) => h.api(profiles(), { cookie: org.cookie, body: { name: "Kiosks", issuingCaId: issuing.id, ...body } });

    expect((await create({ validator: { kind: "test_names" } })).status).toBe(422);
    expect((await create({ validator: DOUBLE, nameRules: RULES })).status).toBe(422);
    expect((await create({ validator: { kind: "test_names" }, nameRules: { ...RULES, sanPatterns: { email: ["*@acme.test"] } } })).status).toBe(400);
    const created = await create({ validator: { kind: "test_names" }, nameRules: RULES });
    expect(created.status).toBe(201);
    expect(created.body.nameRules).toEqual({ ...RULES, requiredSubjectAttributes: ["CN"], subjectPatterns: { CN: ["kiosk-*"], O: ["Acme"] } });
    expect((await auditOf()).find((e) => e.action === "enrollment_profile.created")!.detail.nameRules).toEqual(created.body.nameRules);
  });

  test("refuse a request that breaks them, before its validator is asked, and issue one that keeps them", async () => {
    const profile = await createProfile({ kind: "test_names" }, { nameRules: RULES });
    const refusalOf = async (request: DeviceRequest) => {
      const failure = await enroll(profile.scepUrl, request);
      expect(failure).toBeInstanceOf(ScepFailureError);
      expect((failure as ScepFailureError).failInfo).toBe(FailInfo.badRequest);
      return (failure as ScepFailureError).failInfoText!;
    };

    expect(await refusalOf({ subject: "O=Acme" })).toContain("CN");
    expect(await refusalOf({ subject: "CN=laptop-01" })).toContain("laptop-01");
    expect(await refusalOf({ subject: "CN=kiosk-01, O=Globex" })).toContain("Globex");
    expect(await refusalOf({ subject: "CN=kiosk-01, OU=Lobby" })).toContain("OU");
    expect(await refusalOf({ subject: "CN=kiosk-01", subjectAltNames: { dns: ["kiosk-01.elsewhere.acme"] } })).toContain("kiosk-01.elsewhere.acme");
    expect(await refusalOf({ subject: "CN=kiosk-01", subjectAltNames: { email: ["kiosk@acme.test"] } })).toContain("email");
    expect(h.enrollmentValidations).toEqual([]);
    const refused = (await auditOf()).filter((e) => e.action === "enrollment.refused");
    expect(refused).toHaveLength(6);
    expect(refused.every((e) => e.detail.validator.kind === "test_names")).toBe(true);

    // Patterns ignore case; a URI SAN, allowed without patterns, may be anything.
    const { certificate } = (await enroll(profile.scepUrl, {
      subject: "CN=KIOSK-01, O=Acme",
      subjectAltNames: { dns: ["kiosk-01.Devices.acme"], uri: ["urn:kiosk:01"] },
    })) as { certificate: { raw: Buffer } };
    expect(new x509.X509Certificate(new Uint8Array(certificate.raw)).subject).toBe("O=Acme, CN=KIOSK-01");
    expect(h.enrollmentValidations).toHaveLength(1);
  });

  test("are not checked for a validator that vouches for names", async () => {
    const profile = await createProfile();
    expect(await enroll(profile.scepUrl, { subject: "CN=anything, OU=Whatever", subjectAltNames: { email: ["someone@acme.test"] } })).not.toBeInstanceOf(ScepFailureError);
  });
});

describe("testing a profile's Enrollment Validator", () => {
  test("asks its service whether it can be reached, without validating anything, and is audited either way", async () => {
    const profile = await createProfile();
    const testIt = () => h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, body: {} });

    expect((await testIt()).body).toEqual({ ok: true });
    expect(h.validatorDouble.tests).toBe(1);
    h.validatorDouble.unreachable = true;
    const failed = await testIt();
    expect(failed.status).toBe(200);
    expect(failed.body).toEqual({ ok: false, error: "the validator service did not answer" });
    expect(h.validatorDouble.validations).toEqual([]);

    const tested = (await auditOf()).filter((e) => e.action === "enrollment_validator.tested");
    expect(tested.map((e) => e.detail)).toEqual(
      expect.arrayContaining([
        { validator: { kind: "test_double" }, ok: true },
        { validator: { kind: "test_double" }, ok: false, error: "the validator service did not answer" },
      ]),
    );
    expect(tested[0]!.actor.email).toBe("admin@acme.test");
    expect(tested[0]!.target).toEqual({ type: "enrollment_profile", id: profile.id });
  });

  test("is only Organization Administrators' to do", async () => {
    const profile = await createProfile();
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email: "member@acme.test", role: "member", organizationId: org.orgId } });
    const cookie = await h.signUp("member@acme.test", PASSWORD);
    await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
    expect((await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: await h.signIn("member@acme.test", PASSWORD), body: {} })).status).toBe(403);
    expect(h.validatorDouble.tests).toBe(0);
  });
});

describe("a validator's revocation feed", () => {
  /** The CRL a certificate's CRL Distribution Point names, fetched from there as a relying party would. */
  async function crlFor(cert: x509.X509Certificate) {
    const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)!;
    const res = await h.app.request(cdp.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier!);
    expect(res.status).toBe(200);
    return new x509.X509Crl(new Uint8Array(await res.arrayBuffer()));
  }
  const enrolled = async (scepUrl: string, subject: string) => {
    const { certificate } = (await enroll(scepUrl, { subject })) as { certificate: { raw: Buffer } };
    return new x509.X509Certificate(new Uint8Array(certificate.raw));
  };

  test("revokes the Device Certificates it asks for by serial and issuer: on the CRL at once, audited with the validator, and told each outcome", async () => {
    const profile = await createProfile();
    const retired = await enrolled(profile.scepUrl, "CN=retired-device");
    const kept = await enrolled(profile.scepUrl, "CN=kept-device");
    expect((await crlFor(retired)).entries).toEqual([]);

    h.setNow(new Date(START + 5 * MINUTE_MS));
    h.validatorDouble.queueRevocation("contoso", retired.serialNumber.toLowerCase(), retired.issuer);
    h.validatorDouble.queueRevocation("contoso", "0123456789ABCDEF", retired.issuer);
    h.validatorDouble.queueRevocation("contoso", kept.serialNumber, "CN=Some Other CA");
    expect(await h.pollRevocationFeeds()).toBe(1);

    const crl = await crlFor(retired);
    expect(crl.entries.map((e) => [e.serialNumber.toUpperCase(), e.reason, e.revocationDate.getTime()])).toEqual([
      [retired.serialNumber.toUpperCase(), x509.X509CrlReason.cessationOfOperation, START + 5 * MINUTE_MS],
    ]);
    const revoked = (await auditOf()).filter((e) => e.action === "device_certificate.revoked");
    expect(revoked).toHaveLength(1);
    expect(revoked[0]!.actor).toEqual({ id: null, email: null });
    expect(revoked[0]!.detail).toMatchObject({ enrollmentProfile: { id: profile.id }, serial: retired.serialNumber.toUpperCase(), reason: "cessationOfOperation", by: { enrollmentValidator: { kind: "test_double" } } });

    // Told only by the delivery pass, once the Revocation has committed.
    expect(h.validatorDouble.reports).toEqual([]);
    expect(await h.deliverEnrollmentNotifications()).toBeGreaterThanOrEqual(1);
    expect(h.validatorDouble.reports).toEqual([
      {
        tenant: "contoso",
        outcomes: [
          { ref: "request-1", outcome: "revoked" },
          { ref: "request-2", outcome: "not_found" },
          { ref: "request-3", outcome: "not_found" },
        ],
      },
    ]);
  });

  test("is pulled at most as often as its kind allows, once for every profile sharing it, and an already revoked certificate is told as such", async () => {
    const first = await createProfile();
    const second = await createProfile(DOUBLE, { name: "VPN" });
    await createProfile({ ...DOUBLE, settings: { tenant: "fabrikam" } }, { name: "Lab" });
    const device = await enrolled(second.scepUrl, "CN=vpn-device");
    expect(first.id).not.toBe(second.id);

    expect(await h.pollRevocationFeeds()).toBe(2);
    expect(h.validatorDouble.pulls.sort()).toEqual(["contoso", "fabrikam"]);
    h.validatorDouble.queueRevocation("contoso", device.serialNumber);
    expect(await h.pollRevocationFeeds()).toBe(0);

    h.setNow(new Date(START + 60 * MINUTE_MS));
    expect(await h.pollRevocationFeeds()).toBe(2);
    expect((await crlFor(device)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([device.serialNumber.toUpperCase()]);

    // Another tenant's feed revokes nothing of this one's.
    h.setNow(new Date(START + 120 * MINUTE_MS));
    h.validatorDouble.queueRevocation("fabrikam", device.serialNumber);
    h.validatorDouble.queueRevocation("contoso", device.serialNumber);
    expect(await h.pollRevocationFeeds()).toBe(2);
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.reports.map((r) => [r.tenant, r.outcomes.map((o) => o.outcome)])).toEqual(
      expect.arrayContaining([
        ["contoso", ["revoked"]],
        ["fabrikam", ["not_found"]],
        ["contoso", ["already_revoked"]],
      ]),
    );
    expect((await auditOf()).filter((e) => e.action === "device_certificate.revoked")).toHaveLength(1);
  });

  test("keeps what it pulled until it is revoked: a change that rolls back is tried again on the next pass, without pulling again", async () => {
    const profile = await createProfile();
    const device = await enrolled(profile.scepUrl, "CN=device-kms");
    h.validatorDouble.queueRevocation("contoso", device.serialNumber);
    h.kms.failing = true;
    expect(await h.pollRevocationFeeds()).toBe(1);
    expect((await auditOf()).some((e) => e.action === "device_certificate.revoked")).toBe(false);
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.reports).toEqual([]);

    h.kms.failing = false;
    h.setNow(new Date(START + MINUTE_MS));
    expect(await h.pollRevocationFeeds()).toBe(0);
    expect(h.validatorDouble.pulls).toEqual(["contoso"]);
    expect((await crlFor(device)).entries.map((e) => e.serialNumber.toUpperCase())).toEqual([device.serialNumber.toUpperCase()]);
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.reports.map((r) => r.outcomes.map((o) => o.outcome))).toEqual([["revoked"]]);
  });

  test("answers as failed, and revokes nothing, what still cannot be revoked after five tries", async () => {
    const profile = await createProfile();
    const device = await enrolled(profile.scepUrl, "CN=device-kms");
    h.validatorDouble.queueRevocation("contoso", device.serialNumber);
    h.kms.failing = true;
    for (let pass = 0; pass < 5; pass++) {
      h.setNow(new Date(START + pass * MINUTE_MS));
      await h.pollRevocationFeeds();
    }
    h.kms.failing = false;
    await h.pollRevocationFeeds();

    expect((await crlFor(device)).entries).toEqual([]);
    expect((await auditOf()).some((e) => e.action === "device_certificate.revoked")).toBe(false);
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.reports.map((r) => r.outcomes.map((o) => o.outcome))).toEqual([["failed"]]);
  });

  test("shared by profiles holding different secrets is pulled, and told, with whichever still works", async () => {
    const stale = await createProfile({ ...DOUBLE, secret: "a-rotated-out-secret" });
    const current = await createProfile(DOUBLE, { name: "VPN" });
    const device = await enrolled(current.scepUrl, "CN=vpn-device");
    expect(stale.id).not.toBe(current.id);
    h.validatorDouble.queueRevocation("contoso", device.serialNumber);

    expect(await h.pollRevocationFeeds()).toBe(1);
    expect((await crlFor(device)).entries).toHaveLength(1);
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.reports.map((r) => r.outcomes.map((o) => o.outcome))).toEqual([["revoked"]]);
  });
});

describe("a validator that fails unexpectedly", () => {
  test("refuses the request, and its error, which may quote anything, is never shown or kept", async () => {
    const profile = await createProfile();
    h.validatorDouble.buggy = true;

    const failure = await enroll(profile.scepUrl, { subject: "CN=device-bug" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    const tested = await h.api(`${profiles()}/${profile.id}/validator/test`, { cookie: org.cookie, body: {} });
    expect(tested.body.ok).toBe(false);
    expect(tested.body.error).toContain("unexpectedly");
    await h.deliverEnrollmentNotifications();

    expect(JSON.stringify(tested.body)).not.toContain(DOUBLE_SECRET);
    expect(JSON.stringify(await auditOf())).not.toContain(DOUBLE_SECRET);
    const kept = await h.pool.query("select last_error from enrollment_validator_message");
    expect(kept.rows.length).toBeGreaterThan(0);
    expect(JSON.stringify(kept.rows)).not.toContain(DOUBLE_SECRET);
  });
});

describe("a request the validator allowed", () => {
  test("that the platform then fails to issue is refused, recorded and told to the validator, not left unanswered", async () => {
    const profile = await createProfile();
    h.kms.failing = true;

    const failure = await enroll(profile.scepUrl, { subject: "CN=device-kms" });
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect((failure as ScepFailureError).failInfo).toBe(FailInfo.badRequest);
    expect(h.validatorDouble.validations).toHaveLength(1);
    const audit = await auditOf();
    expect(audit.some((e) => e.action === "device_certificate.issued")).toBe(false);
    expect(audit.filter((e) => e.action === "enrollment.refused")).toHaveLength(1);

    h.kms.failing = false;
    await h.deliverEnrollmentNotifications();
    expect(h.validatorDouble.failed).toHaveLength(1);
  });
});
