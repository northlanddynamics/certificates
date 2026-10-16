// Device enrollment over SCEP (the tracer): an Organization Administrator creates an Enrollment Profile on a Private CA's
// Issuing CA, and a device enrolls at the profile's SCEP URL and gets a Device Certificate that follows the profile.
// Validation is the harness's test-only Enrollment Validator kind, which allows everything. Every check is of what a
// device, an administrator and a relying party see: SCEP answers, the certificates, the API and Audit Events.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { PASSWORD, PKI_BASE_URL, createHarness, type Harness } from "./harness";
import { FailInfo, ScepFailureError, type CreateCsrOptions } from "ts-scep";
import { scepDevice } from "./scep-device";
import { DOUBLE_SECRET } from "./enrollment-validator-double";

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

const DAY_MS = 86_400_000;
const START = Date.parse("2026-01-01T00:00:00Z");
const CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const cas = (orgId = org.orgId) => `/api/organizations/${orgId}/private-cas`;
const profiles = (orgId = org.orgId) => `/api/organizations/${orgId}/enrollment-profiles`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const certificatesIn = (pem: string) => (pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((one) => new x509.X509Certificate(one));

/** A new Private CA with a platform-made root, and its first Issuing CA as `issuing`. */
async function createCa(target = org, lifetimeYears = 5) {
  const res = await h.api(cas(target.orgId), {
    cookie: target.cookie,
    body: { name: "Devices", subject: "CN=Acme Devices, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears, permittedNames: { exact: [], zones: ["devices.acme"] } },
  });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuing: res.body.issuingCas[0] as { id: string } };
}

/** A new Enrollment Profile on the Issuing CA, as the API shows it. */
async function createProfile(issuingCaId: string, extra: Record<string, unknown> = {}, target = org) {
  const res = await h.api(profiles(target.orgId), { cookie: target.cookie, body: { name: "Wi-Fi", issuingCaId, validator: { kind: "test_allow" }, ...extra } });
  expect(res.status).toBe(201);
  return res.body as { id: string; publicId: string; scepUrl: string };
}

/** The Issuing CA's chain: the Issuing CA, then the root. */
async function chainOf(ca: { id: string; issuing: { id: string } }) {
  const res = await h.app.request(`http://localhost${cas()}/${ca.id}/issuing-cas/${ca.issuing.id}/chain`, { headers: { cookie: org.cookie } });
  const [issuing, root] = certificatesIn(await res.text());
  return { issuing: issuing!, root: root! };
}

/** The certificate as @peculiar/x509 reads it, to look at its extensions. */
const read = (cert: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(cert.raw));

describe("a device enrolling over SCEP", () => {
  test("gets a Device Certificate that follows the profile: its EKU, key usage and validity, the CSR's subject and SANs, a chain to the root and the CDP", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    expect(profile.scepUrl).toBe(`http://localhost/scep/${profile.publicId}`);
    const device = scepDevice(h, profile.scepUrl);

    const caps = await device.client.getCACaps();
    for (const capability of ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard"]) expect(caps.has(capability)).toBe(true);

    const { certificate } = await device.enroll({
      subject: "CN=device-01, O=Acme",
      subjectAltNames: { dns: ["device-01.devices.acme"], uri: ["IntuneDeviceId://5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11"] },
      challengePassword: "one-time-challenge",
    });
    const cert = read(certificate);
    const chain = await chainOf(ca);
    expect(h.enrollmentValidations.map((v) => v.challengePassword)).toEqual(["one-time-challenge"]);

    // The device gave it in RFC 4514's order, most specific first; @peculiar/x509 shows it in the order it is encoded.
    expect(cert.subject).toBe("O=Acme, CN=device-01");
    const sans = cert.getExtension(x509.SubjectAlternativeNameExtension)!.names.toJSON();
    expect(sans).toEqual([
      { type: "dns", value: "device-01.devices.acme" },
      { type: "url", value: "IntuneDeviceId://5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11" },
    ]);
    expect(cert.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([CLIENT_AUTH]);
    expect(cert.getExtension(x509.KeyUsagesExtension)!.usages).toBe(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment);
    expect(cert.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);
    // 365 days unless the profile says otherwise.
    expect(cert.notBefore.getTime()).toBe(START);
    expect(cert.notAfter.getTime()).toBe(START + 365 * DAY_MS);
    expect(cert.issuer).toBe(chain.issuing.subject);
    expect(await cert.verify({ publicKey: chain.issuing.publicKey, signatureOnly: true })).toBe(true);
    expect(await chain.issuing.verify({ publicKey: chain.root.publicKey, signatureOnly: true })).toBe(true);
    const cdp = cert.getExtension(x509.CRLDistributionPointsExtension)!;
    expect(cdp.distributionPoints[0]!.distributionPoint!.fullName![0]!.uniformResourceIdentifier).toBe(`${PKI_BASE_URL}/pki/issuing-cas/${ca.issuing.id}/ca.crl`);
  });

  test("is given the RA certificate and the CA chain by GetCACert, and can send PKIOperation by GET", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl, { usePost: false });
    const chain = await chainOf(ca);

    const certs = await device.client.getCACert();
    expect(Buffer.from(certs.ca.raw).equals(Buffer.from(chain.issuing.rawData))).toBe(true);
    const ra = read(certs.encryptionCertificate);
    expect(ra.serialNumber.toUpperCase()).toBe((await h.api(`${profiles()}/${profile.id}`, { cookie: org.cookie })).body.raCertificate.serial);
    expect(ra.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);
    expect(await ra.verify({ publicKey: chain.issuing.publicKey, signatureOnly: true })).toBe(true);
    expect(certs.all.some((cert) => Buffer.from(cert.raw).equals(Buffer.from(chain.root.rawData)))).toBe(true);

    const { certificate } = await device.enroll({ subject: "CN=device-02", subjectAltNames: { dns: ["device-02.devices.acme"] } });
    expect(read(certificate).subject).toBe("CN=device-02");
  });

  test("gets nothing a CSR asks for beyond the profile: other EKUs, CA:true or extra extensions are ignored", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id, { validityDays: 30, extendedKeyUsage: ["clientAuth", "smartcardLogon"], keyUsage: ["digitalSignature"] });
    const device = scepDevice(h, profile.scepUrl);
    // basicConstraints CA:true, and a private extension, asked for in the CSR.
    // ts-scep takes them as the ASN.1 objects @peculiar/x509 builds on, which it keeps (protected) as `asn`.
    const asnOf = (extension: x509.Extension) => (extension as unknown as { asn: NonNullable<CreateCsrOptions["extensions"]>[number] }).asn;
    const extensions = [asnOf(new x509.BasicConstraintsExtension(true, undefined, true)), asnOf(new x509.Extension("1.3.6.1.4.1.99999.1", false, new Uint8Array([5, 0])))];

    const { certificate } = await device.enroll({ subject: "CN=device-03", extendedKeyUsage: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.3"], extensions });
    const cert = read(certificate);
    expect(cert.getExtension(x509.ExtendedKeyUsageExtension)!.usages).toEqual([CLIENT_AUTH, "1.3.6.1.4.1.311.20.2.2"]);
    expect(cert.getExtension(x509.KeyUsagesExtension)!.usages).toBe(x509.KeyUsageFlags.digitalSignature);
    expect(cert.getExtension(x509.BasicConstraintsExtension)!.ca).toBe(false);
    expect(cert.extensions.some((e) => e.type === "1.3.6.1.4.1.99999.1")).toBe(false);
    expect(cert.notAfter.getTime()).toBe(START + 30 * DAY_MS);
  });

  test("is refused a key the profile does not allow, with FAILURE badRequest, and nothing is issued", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id, { allowedKeyTypes: ["rsa-3072"] });
    const device = scepDevice(h, profile.scepUrl);

    const failure = await device.enroll({ subject: "CN=device-04", keyBits: 2048 }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect(failure.failInfo).toBe(FailInfo.badRequest);
    expect(failure.failInfoText).toContain("rsa-2048");
    expect(h.enrollmentValidations).toEqual([]);
    expect((await auditOf()).some((e) => e.action === "device_certificate.issued")).toBe(false);
    const refusals = (await auditOf()).filter((e) => e.action === "enrollment.refused");
    expect(refusals).toHaveLength(1);
    expect(refusals[0]!.actor).toEqual({ id: null, email: null });
    expect(refusals[0]!.target).toEqual({ type: "enrollment_profile", id: profile.id });
    expect(refusals[0]!.detail).toMatchObject({ enrollmentProfile: { id: profile.id, name: "Wi-Fi" }, validator: { kind: "test_allow" }, reason: failure.failInfoText });
    expect(typeof refusals[0]!.detail.transactionId).toBe("string");

    const { certificate } = await device.enroll({ subject: "CN=device-04", keyBits: 3072 });
    expect(read(certificate).subject).toBe("CN=device-04");
  });

  test("is refused a DNS name outside its Issuing CA's permitted names", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);

    const failure = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-05", subjectAltNames: { dns: ["device-05.elsewhere.example"] } }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect(failure.failInfo).toBe(FailInfo.badRequest);
    expect(failure.failInfoText).toContain("device-05.elsewhere.example");
    // Refused before the validator is asked, so a one-time challenge is not used up.
    expect(h.enrollmentValidations).toEqual([]);
  });

  test("is refused once the profile's Issuing CA is retired", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    expect((await h.api(`${cas()}/${ca.id}/issuing-cas/${ca.issuing.id}/retire`, { cookie: org.cookie, body: {} })).status).toBe(200);

    const failure = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-06" }).catch((err) => err);
    expect(failure).toBeInstanceOf(ScepFailureError);
    expect(failure.failInfoText).toContain("retired");
    expect(h.enrollmentValidations).toEqual([]);
  });

  test("gets a certificate that ends with its Issuing CA when the profile's validity would outlast it", async () => {
    const ca = await createCa(org, 1);
    const profile = await createProfile(ca.issuing.id, { validityDays: 1825 });
    h.setNow(new Date(START + 300 * DAY_MS));

    const { certificate } = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-07" });
    expect(read(certificate).notAfter.getTime()).toBe((await chainOf(ca)).issuing.notAfter.getTime());
  });

  test("is answered 404 at a SCEP URL that is no profile's", async () => {
    const res = await h.app.request("http://localhost/scep/0123456789abcdef0123456789abcdef?operation=GetCACaps");
    expect(res.status).toBe(404);
  });

  test("leaves a device_certificate.issued Audit Event, by no person, and no Managed Certificate", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const { certificate } = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-08", subjectAltNames: { dns: ["device-08.devices.acme"] } });
    const cert = read(certificate);

    const issued = (await auditOf()).filter((e) => e.action === "device_certificate.issued");
    expect(issued).toHaveLength(1);
    expect(issued[0]!.actor).toEqual({ id: null, email: null });
    expect(issued[0]!.target.type).toBe("device_certificate");
    expect(issued[0]!.detail).toMatchObject({
      enrollmentProfile: { id: profile.id, name: "Wi-Fi" },
      serial: cert.serialNumber.toUpperCase(),
      subject: "CN=device-08",
      subjectAltNames: [{ type: "dns", value: "device-08.devices.acme" }],
      deviceId: null,
      notAfter: cert.notAfter.toISOString(),
    });
    expect(typeof issued[0]!.detail.transactionId).toBe("string");

    const mcs = await h.api(`/api/organizations/${org.orgId}/managed-certificates`, { cookie: org.cookie });
    expect(mcs.status).toBe(200);
    expect(mcs.body.items).toEqual([]);
  });
});

describe("Enrollment Profiles", () => {
  test("an Organization Administrator creates one, with the defaults, and it is audited", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    expect(profile).toMatchObject({
      name: "Wi-Fi",
      issuingCaId: ca.issuing.id,
      privateCaId: ca.id,
      validityDays: 365,
      keyUsage: ["digitalSignature", "keyEncipherment"],
      extendedKeyUsage: ["clientAuth"],
      allowedKeyTypes: ["rsa-2048", "rsa-3072", "rsa-4096"],
      validator: { kind: "test_allow", settings: {}, hasSecret: false },
      nameRules: null,
    });
    // Opaque: it is neither the profile's id nor anything of the Organization's.
    expect(profile.publicId).toMatch(/^[0-9a-f]{32}$/);
    expect(profile.publicId).not.toBe(profile.id);

    const listed = await h.api(profiles(), { cookie: org.cookie });
    expect(listed.body.items.map((p: { id: string }) => p.id)).toEqual([profile.id]);
    const created = (await auditOf()).find((e) => e.action === "enrollment_profile.created");
    expect(created).toMatchObject({ target: { type: "enrollment_profile", id: profile.id }, detail: { name: "Wi-Fi", issuingCa: { id: ca.issuing.id }, validator: { kind: "test_allow" } } });
    expect(JSON.stringify(created)).not.toContain("PRIVATE KEY");
  });

  test("offers the root and Issuing CA certificates to download, for the device management platform", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const chain = await chainOf(ca);
    const download = async (query: string) => certificatesIn(await (await h.app.request(`http://localhost${profiles()}/${profile.id}/ca-certificate${query}`, { headers: { cookie: org.cookie } })).text());

    expect((await download("")).map((cert) => cert.subject)).toEqual([chain.root.subject]);
    expect((await download("?ca=issuing")).map((cert) => cert.subject)).toEqual([chain.issuing.subject]);
  });

  test("is refused a validator kind the platform does not run, an Issuing CA that is not the Organization's or does not issue, and a name taken", async () => {
    const ca = await createCa();
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = await createCa(other);
    const create = (body: Record<string, unknown>) => h.api(profiles(), { cookie: org.cookie, body: { name: "Wi-Fi", issuingCaId: ca.issuing.id, validator: { kind: "test_allow" }, ...body } });

    expect((await h.api(`/api/organizations/${org.orgId}/enrollment-validator-kinds`, { cookie: org.cookie })).body.items.map((k: { kind: string }) => k.kind)).toContain("test_allow");
    expect((await create({ validator: { kind: "intune" } })).status).toBe(422);
    expect((await create({ issuingCaId: theirs.issuing.id })).status).toBe(422);
    expect((await create({ allowedKeyTypes: ["ecdsa-p256"] })).status).toBe(400);
    expect((await create({})).status).toBe(201);
    expect((await create({})).status).toBe(409);
    expect((await h.api(`${cas()}/${ca.id}/issuing-cas/${ca.issuing.id}/retire`, { cookie: org.cookie, body: {} })).status).toBe(200);
    expect((await create({ name: "VPN" })).status).toBe(422);
  });

  test("are only Organization Administrators' business, as /api/me reports", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const join = async (email: string, role: string) => {
      const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
      const cookie = await h.signUp(email, PASSWORD);
      await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
      return h.signIn(email, PASSWORD);
    };
    const permissionsOf = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
    expect((await permissionsOf(org.cookie)).enrollmentProfile).toEqual(["read", "create", "update", "disable"]);

    for (const role of ["approver", "member"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await permissionsOf(cookie)).enrollmentProfile).toBeUndefined();
      expect((await h.api(profiles(), { cookie })).status).toBe(403);
      expect((await h.api(`${profiles()}/${profile.id}`, { cookie })).status).toBe(403);
      expect((await h.api(profiles(), { cookie, body: { name: "Mine", issuingCaId: ca.issuing.id, validator: { kind: "test_allow" } } })).status).toBe(403);
      expect((await h.api(`/api/organizations/${org.orgId}/enrollment-validator-kinds`, { cookie })).status).toBe(403);
    }
  });

  test("are kept apart per Organization: another's profile is not found, and its SCEP URL issues only from its own CA", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirCa = await createCa(other);
    const theirs = await createProfile(theirCa.issuing.id, {}, other);

    expect((await h.api(`${profiles(other.orgId)}/${profile.id}`, { cookie: other.cookie })).status).toBe(404);
    expect((await h.api(`${profiles()}/${profile.id}`, { cookie: other.cookie })).status).toBe(404);
    expect((await h.api(profiles(other.orgId), { cookie: other.cookie })).body.items.map((p: { id: string }) => p.id)).toEqual([theirs.id]);

    const { certificate } = await scepDevice(h, theirs.scepUrl).enroll({ subject: "CN=globex-device" });
    expect(read(certificate).issuer).toBe(theirCa.issuing.id && (await h.api(`${cas(other.orgId)}/${theirCa.id}`, { cookie: other.cookie })).body.issuingCas[0].subject);
    expect((await auditOf()).some((e) => e.action === "device_certificate.issued")).toBe(false);
  });
});


describe("a profile's Device Certificates", () => {
  const certificatesOf = (profileId: string, query = "", cookie = org.cookie) => h.api(`${profiles()}/${profileId}/device-certificates${query}`, { cookie });

  test("lists what devices enrolled for, newest first, as an Organization Administrator sees it", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl);
    const first = read((await device.enroll({ subject: "CN=device-a", subjectAltNames: { dns: ["device-a.devices.acme"], uri: ["IntuneDeviceId://5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11"] } })).certificate);
    h.setNow(new Date(START + DAY_MS));
    const second = read((await device.enroll({ subject: "CN=device-b" })).certificate);

    const res = await certificatesOf(profile.id);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ total: 2, page: 1, pageSize: 25 });
    expect(res.body.items.map((c: { serial: string }) => c.serial)).toEqual([second.serialNumber.toUpperCase(), first.serialNumber.toUpperCase()]);
    expect(res.body.items[1]).toEqual({
      id: expect.any(String),
      enrollmentProfileId: profile.id,
      serial: first.serialNumber.toUpperCase(),
      subject: "CN=device-a",
      subjectAltNames: [
        { type: "dns", value: "device-a.devices.acme" },
        { type: "url", value: "IntuneDeviceId://5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11" },
      ],
      deviceId: "5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11",
      issuer: first.issuer,
      notBefore: new Date(START).toISOString(),
      notAfter: new Date(START + 365 * DAY_MS).toISOString(),
      status: "active",
      revocation: null,
      createdAt: new Date(START).toISOString(),
    });
  });

  test("are found by part of the subject, a SAN, the serial or the Intune device ID, and by status", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl);
    const enroll = async (subject: string, subjectAltNames: Parameters<typeof device.enroll>[0]["subjectAltNames"] = {}) => read((await device.enroll({ subject, subjectAltNames })).certificate).serialNumber.toUpperCase();
    const laptop = await enroll("CN=laptop-17, O=Acme", { dns: ["laptop-17.devices.acme"], uri: ["IntuneDeviceId://aaaaaaaa-1111-4a57-9a1d-0c6f3e2a7b11"] });
    const phone = await enroll("CN=phone-03, O=Acme", { email: ["ann@devices.acme"], uri: ["IntuneDeviceId://bbbbbbbb-2222-4a57-9a1d-0c6f3e2a7b11"] });
    h.setNow(new Date(START + 200 * DAY_MS));
    const tablet = await enroll("CN=tablet-100%_x, O=Acme");
    const serialsFor = async (query: string) => {
      const res = await certificatesOf(profile.id, query);
      expect(res.status).toBe(200);
      expect(res.body.total).toBe(res.body.items.length);
      return res.body.items.map((c: { serial: string }) => c.serial).sort();
    };

    expect(await serialsFor("?q=LAPTOP")).toEqual([laptop]);
    expect(await serialsFor("?q=ann%40devices")).toEqual([phone]);
    expect(await serialsFor(`?q=${phone.slice(4, 14).toLowerCase()}`)).toEqual([phone]);
    expect(await serialsFor(`?q=${encodeURIComponent(laptop.slice(0, 8).match(/../g)!.join(":"))}`)).toEqual([laptop]);
    expect(await serialsFor("?q=BBBBBBBB-2222")).toEqual([phone]);
    // LIKE's wildcards are taken as they are written.
    expect(await serialsFor("?q=100%25_")).toEqual([tablet]);
    expect(await serialsFor("?q=_")).toEqual([tablet]);
    expect(await serialsFor("?q=nothing-like-it")).toEqual([]);

    // The first two end at START + 365 days; the tablet a year after it enrolled.
    h.setNow(new Date(START + 400 * DAY_MS));
    expect(await serialsFor("?status=expired")).toEqual([laptop, phone].sort());
    expect(await serialsFor("?status=active")).toEqual([tablet]);
    expect(await serialsFor("?status=revoked")).toEqual([]);
    expect(await serialsFor("?status=expired&q=phone")).toEqual([phone]);
    expect((await certificatesOf(profile.id, "?status=lost")).status).toBe(400);
  });

  test("are paged on the server", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const device = scepDevice(h, profile.scepUrl);
    const serials: string[] = [];
    for (let i = 0; i < 5; i++) {
      h.setNow(new Date(START + i * DAY_MS));
      serials.unshift(read((await device.enroll({ subject: `CN=device-${i}` })).certificate).serialNumber.toUpperCase());
    }

    const pages = await Promise.all([1, 2, 3].map((page) => certificatesOf(profile.id, `?page=${page}&pageSize=2`)));
    expect(pages.map((p) => p.body.total)).toEqual([5, 5, 5]);
    expect(pages.flatMap((p) => p.body.items.map((c: { serial: string }) => c.serial))).toEqual(serials);
    expect((await certificatesOf(profile.id, "?pageSize=101")).status).toBe(400);
  });

  test("shows a Device Certificate revoked through its validator's feed as revoked, with the reason", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id, { validator: { kind: "test_double", settings: { tenant: "contoso" }, secret: DOUBLE_SECRET } });
    const cert = read((await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=retired" })).certificate);
    h.validatorDouble.queueRevocation("contoso", cert.serialNumber);
    h.setNow(new Date(START + DAY_MS));
    await h.pollRevocationFeeds();

    const [listed] = (await certificatesOf(profile.id, "?status=revoked")).body.items;
    expect(listed).toMatchObject({ serial: cert.serialNumber.toUpperCase(), status: "revoked", revocation: { reason: "cessationOfOperation", revokedAt: new Date(START + DAY_MS).toISOString() } });
  });

  test("can each be looked at and downloaded", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    const { certificate } = await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-dl" });
    const [listed] = (await certificatesOf(profile.id)).body.items;

    const one = await h.api(`${profiles()}/${profile.id}/device-certificates/${listed.id}`, { cookie: org.cookie });
    expect(one.status).toBe(200);
    expect(one.body).toEqual(listed);

    const res = await h.app.request(`http://localhost${profiles()}/${profile.id}/device-certificates/${listed.id}/certificate`, { headers: { cookie: org.cookie } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-disposition")).toBe(`attachment; filename="${listed.serial.toLowerCase()}.pem"`);
    const downloaded = certificatesIn(await res.text());
    expect(downloaded).toHaveLength(1);
    expect(Buffer.from(downloaded[0]!.rawData).equals(Buffer.from(certificate.raw))).toBe(true);

    expect((await h.api(`${profiles()}/${profile.id}/device-certificates/${crypto.randomUUID()}`, { cookie: org.cookie })).status).toBe(404);
    expect((await h.api(`${profiles()}/${profile.id}/device-certificates/not-an-id`, { cookie: org.cookie })).status).toBe(404);
  });

  test("are only Organization Administrators' business, as /api/me reports", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=device-p" });
    const [listed] = (await certificatesOf(profile.id)).body.items;
    const join = async (email: string, role: string) => {
      const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
      const cookie = await h.signUp(email, PASSWORD);
      await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
      return h.signIn(email, PASSWORD);
    };
    const permissionsOf = async (cookie: string) => (await h.api("/api/me", { cookie })).body.organizations[0].permissions;
    expect((await permissionsOf(org.cookie)).deviceCertificate).toEqual(["read"]);

    for (const role of ["approver", "member"]) {
      const cookie = await join(`${role}@acme.test`, role);
      expect((await permissionsOf(cookie)).deviceCertificate).toBeUndefined();
      expect((await certificatesOf(profile.id, "", cookie)).status).toBe(403);
      expect((await h.api(`${profiles()}/${profile.id}/device-certificates/${listed.id}`, { cookie })).status).toBe(403);
      expect((await h.app.request(`http://localhost${profiles()}/${profile.id}/device-certificates/${listed.id}/certificate`, { headers: { cookie } })).status).toBe(403);
    }
  });

  test("are kept apart per Organization", async () => {
    const ca = await createCa();
    const profile = await createProfile(ca.issuing.id);
    await scepDevice(h, profile.scepUrl).enroll({ subject: "CN=acme-device" });
    const [listed] = (await certificatesOf(profile.id)).body.items;
    const other = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
    const theirs = await createProfile((await createCa(other)).issuing.id, {}, other);

    expect((await h.api(`${profiles(other.orgId)}/${profile.id}/device-certificates`, { cookie: other.cookie })).status).toBe(404);
    expect((await certificatesOf(profile.id, "", other.cookie)).status).toBe(404);
    expect((await h.api(`${profiles(other.orgId)}/${theirs.id}/device-certificates/${listed.id}`, { cookie: other.cookie })).status).toBe(404);
    expect((await h.api(`${profiles(other.orgId)}/${theirs.id}/device-certificates`, { cookie: other.cookie })).body.total).toBe(0);
  });
});
