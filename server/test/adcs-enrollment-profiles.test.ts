// Enrollment Profiles on an ADCS CA, through the platform's HTTP API, its SCEP endpoint and the Agent protocol: an
// Organization Administrator names an ADCS CA, one of its device templates and a template for the RA certificate; the
// profile serves SCEP once ADCS has issued its RA certificate through an Agent, and renews it when a third of its life is
// left. A device's request passes the profile's checks and the Enrollment Validator, is submitted through an Agent and
// answered PENDING, and the device asks after it with GetCertInitial until ADCS issues it (SUCCESS), denies it or holds
// it too long (FAILURE). Here the Agents are stand-ins (agent-double.ts) and ADCS an in-memory double (adcs-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { randomBytes } from "node:crypto";
import { FailInfo, ScepFailureError } from "ts-scep";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, defaultTemplates } from "./support/adcs-double";
import { INTUNE } from "./support/intune-double";
import { scepDevice, type DeviceRequest, type Enrolled, type Pending, type ScepDevice } from "./support/scep-device";
import { FIRST_CHECK_AFTER_MS, PENDING_TIMEOUT_MS } from "../src/adcs/adcs-issuance";
import type { TemplateFacts } from "../src/adcs/adcs-kinds";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
let adcs: AdcsDouble;
type Org = typeof acmeOrg;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";
const START = new Date("2026-01-01T00:00:00Z");
const DAY_MS = 86_400_000;

/** A template for SCEP RA certificates: the Certificate Request Agent EKU, as NDES's has, issued at once. */
const RA_TEMPLATE: TemplateFacts = {
  name: "CorpScepRa",
  oid: "1.3.6.1.4.1.311.21.8.1.4",
  displayName: "Corp SCEP RA",
  extendedKeyUsages: ["1.3.6.1.4.1.311.20.2.1"],
  validityDays: 300,
  minimumKeySize: 2048,
  keyAlgorithms: ["rsa"],
  managerApproval: false,
  subjectFromRequest: true,
  enrollable: true,
  published: true,
};

beforeAll(async () => {
  h = await createHarness({ adcsRelay: { attemptTimeoutMs: 1500 } });
  adcs = await AdcsDouble.create(CONFIG);
});
beforeEach(async () => {
  await h.reset();
  adcs.failure = null;
  adcs.templates = [...defaultTemplates(), { ...RA_TEMPLATE }];
  adcs.issued.length = 0;
  adcs.hold = false;
  adcs.denyWith = null;
  adcs.pending.clear();
  adcs.denied.clear();
  adcs.now = () => START;
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const auditOf = async (action: string, org: Org = acmeOrg) =>
  ((await api(org, "/audit-events?pageSize=200")).body.items as { action: string; detail: any; target: any }[]).filter((e) => e.action === action);

type Template = { id: string; name: string };
type Ca = { id: string; name: string; templates: Template[] };
type Profile = {
  id: string;
  scepUrl: string;
  caFingerprint: string;
  issuingCaId: string | null;
  adcs: { adcsCaId: string; templateId: string; raTemplateId: string; templateUnavailable: string | null } | null;
  validityDays: number | null;
  allowedKeyTypes: string[];
  raCertificate: { subject: string; serial: string; notAfter: string } | null;
  raRequested: boolean;
  sharedChallenge: { id: string; challenge: string } | null;
};

/** An ADCS CA of the Organization's, added with a Windows Agent that reaches the double, and its templates. */
async function adcsCa(org: Org = acmeOrg) {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: `win-${randomBytes(3).toString("hex")}`, os: "windows" });
  agent.adcs = adcs;
  const stop = agent.startWorking();
  let res;
  try {
    res = await api(org, "/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: [agent.id] });
  } finally {
    await stop();
  }
  expect(res.status).toBe(201);
  const ca = res.body as Ca;
  const template = (name: string) => ca.templates.find((t) => t.name === name)!;
  return { ca, agent, tls: template("CorpWebServer"), device: template("CorpDevice"), directory: template("Workstation"), ra: template("CorpScepRa") };
}
type Added = Awaited<ReturnType<typeof adcsCa>>;

/** The double's own facts of a template, to change how ADCS treats requests under it. */
const atAdcs = (name: string) => adcs.templates.find((t) => t.name === name)!;

/** Creates a profile on the ADCS CA's device and RA templates, with a validator that allows every request and does not vouch for names unless told otherwise. */
const createProfile = (added: Added, extra: Record<string, unknown> = {}, org: Org = acmeOrg) =>
  api(org, "/enrollment-profiles", { name: "Wi-Fi", adcs: { adcsCaId: added.ca.id, templateId: added.device.id, raTemplateId: added.ra.id }, validator: { kind: "test_names" }, ...extra });

const profileOf = async (id: string, org: Org = acmeOrg) => (await api(org, `/enrollment-profiles/${id}`)).body as Profile;

/** A profile whose RA certificate ADCS has issued, through its Agent, ready for devices. */
async function readyProfile(added: Added, extra: Record<string, unknown> = {}) {
  const created = await createProfile(added, extra);
  expect(created.status).toBe(201);
  await added.agent.work();
  const profile = await profileOf(created.body.id);
  expect(profile.raCertificate).not.toBeNull();
  return { ...profile, sharedChallenge: created.body.sharedChallenge } as Profile;
}

/** Has the Agent discover the CA again. */
async function refresh(added: Added) {
  const stop = added.agent.startWorking();
  try {
    expect((await api(acmeOrg, `/adcs-cas/${added.ca.id}/refresh`, {}, "POST")).status).toBe(200);
  } finally {
    await stop();
  }
}

/** Moves the clock, has the Agent say it is there, runs a pass over the requests to ADCS, and has the Agent carry out what it is given. */
async function passAt(at: Date, agent: TestAgent) {
  h.setNow(at);
  adcs.now = () => at;
  await agent.poll();
  await h.runAdcsRequests();
  await agent.work();
}

/** Sends the request and expects PENDING. */
async function submitPending(device: ScepDevice, request: DeviceRequest, current?: Enrolled): Promise<Pending> {
  const sent = await device.submit(request, current);
  if (!("pending" in sent)) throw new Error("expected PENDING");
  return sent;
}

const certificateOf = (enrolled: Enrolled) => new x509.X509Certificate(new Uint8Array(enrolled.certificate.raw));
const failureOf = (err: unknown) => {
  expect(err).toBeInstanceOf(ScepFailureError);
  return err as ScepFailureError;
};

describe("creating an Enrollment Profile on an ADCS CA", () => {
  test("names the ADCS CA, its device template and its RA template; the template decides validity, and the RA certificate is asked of ADCS", async () => {
    const added = await adcsCa();
    const created = await createProfile(added);
    expect(created.status).toBe(201);
    const profile = created.body as Profile;
    expect(profile.issuingCaId).toBeNull();
    expect(profile.adcs).toEqual({ adcsCaId: added.ca.id, templateId: added.device.id, raTemplateId: added.ra.id, templateUnavailable: null });
    expect(profile.validityDays).toBeNull();
    expect(profile.raCertificate).toBeNull();
    expect(profile.raRequested).toBe(true);
    expect(profile.caFingerprint).toBe(new Bun.CryptoHasher("sha256").update(new Uint8Array(adcs.ca.certificate.rawData)).digest("hex"));

    const [event] = await auditOf("enrollment_profile.created");
    expect(event!.detail).toMatchObject({ adcsCa: { id: added.ca.id, name: "Corp" }, template: { id: added.device.id, name: "CorpDevice" }, raTemplate: { id: added.ra.id, name: "CorpScepRa" }, validityDays: null, raCertificate: null });
    expect((await auditOf("enrollment_profile.ra_requested"))[0]!.detail.replacing).toBeNull();
  });

  test("is refused a validity or key usages (400), both or neither issuer (400), and a template not offered for devices or an unavailable RA template (422)", async () => {
    const added = await adcsCa();
    for (const extra of [{ validityDays: 30 }, { keyUsage: ["digitalSignature"] }, { extendedKeyUsage: ["clientAuth"] }]) expect((await createProfile(added, extra)).status).toBe(400);
    expect((await createProfile(added, { issuingCaId: "00000000-0000-4000-8000-000000000000" })).status).toBe(400);
    expect((await api(acmeOrg, "/enrollment-profiles", { name: "None", validator: { kind: "test_names" } })).status).toBe(400);

    const tlsOnly = await createProfile({ ...added, device: added.tls });
    expect(tlsOnly.status).toBe(422);
    expect(tlsOnly.body.message ?? tlsOnly.body.error ?? JSON.stringify(tlsOnly.body)).toContain("not offered for devices");
    expect((await createProfile({ ...added, ra: added.directory })).status).toBe(422);
    expect((await api(acmeOrg, `/adcs-cas/${added.ca.id}/templates/${added.device.id}/hide`, {}, "POST")).status).toBe(200);
    expect((await createProfile(added)).status).toBe(422);
  });

  test("allows only device keys the template takes: of the defaults those, and a key it does not take is refused", async () => {
    const added = await adcsCa();
    expect((await createProfile(added, { allowedKeyTypes: ["rsa-1024", "rsa-2048"] })).status).toBe(422);
    const created = await createProfile(added);
    expect(created.body.allowedKeyTypes).toEqual(["rsa-2048", "rsa-3072", "rsa-4096"]);
    expect((await api(acmeOrg, `/enrollment-profiles/${created.body.id}`, { allowedKeyTypes: ["rsa-1024"] }, "PATCH")).status).toBe(422);
  });

  test("is refused another Organization's ADCS CA, and is not pointed at an Issuing CA later", async () => {
    const theirs = await adcsCa(globex);
    const added = await adcsCa();
    expect((await createProfile({ ...added, ca: theirs.ca, device: theirs.device, ra: theirs.ra })).status).toBe(422);
    const created = await createProfile(added);
    expect((await api(acmeOrg, `/enrollment-profiles/${created.body.id}`, { issuingCaId: "00000000-0000-4000-8000-000000000000" }, "PATCH")).status).toBe(422);
  });

  test("keeps the ADCS CA from being removed while it names it", async () => {
    const added = await adcsCa();
    expect((await createProfile(added)).status).toBe(201);
    expect((await api(acmeOrg, `/adcs-cas/${added.ca.id}`, undefined, "DELETE")).status).toBe(409);
  });
});

describe("the RA certificate of a profile on an ADCS CA", () => {
  test("is issued by ADCS through an Agent under the RA template; until then the profile serves no SCEP", async () => {
    const added = await adcsCa();
    const created = (await createProfile(added)).body as Profile;
    const before = await h.app.request(`${created.scepUrl}?operation=GetCACaps`);
    expect(before.status).toBe(503);

    const items = await added.agent.work();
    expect(items.map((i) => [i.type, i.payload.template])).toEqual([["adcs.submit", "CorpScepRa"]]);
    const profile = await profileOf(created.id);
    expect(profile.raRequested).toBe(false);
    const ra = adcs.issued.find((i) => i.template === "CorpScepRa")!;
    expect(profile.raCertificate).toEqual({ subject: ra.certificate.subject, serial: ra.certificate.serialNumber.toUpperCase(), notAfter: ra.certificate.notAfter.toISOString() });
    expect((await auditOf("enrollment_profile.ra_issued"))[0]!.detail).toMatchObject({ adcsRequestId: ra.requestId, from: null, to: { serial: ra.certificate.serialNumber.toUpperCase() } });

    // GetCACert serves the RA certificate with the ADCS CA's chain.
    const served = await scepDevice(h, profile.scepUrl).client.getCACert();
    const read = (c: { raw: Buffer }) => new x509.X509Certificate(new Uint8Array(c.raw));
    expect(read(served.ca).equal(adcs.ca.certificate)).toBe(true);
    expect(served.ra.map(read).map((c) => c.serialNumber)).toEqual([ra.certificate.serialNumber]);
    expect(served.all.some((c) => read(c).equal(adcs.root.certificate))).toBe(true);
  });

  test("that ADCS refuses is audited, and asked again a day after, or at once by an Organization Administrator", async () => {
    const added = await adcsCa();
    adcs.denyWith = "Denied by Policy Module";
    const created = (await createProfile(added)).body as Profile;
    await added.agent.work();
    expect((await profileOf(created.id)).raRequested).toBe(false);
    expect((await auditOf("enrollment_profile.ra_request_failed"))[0]!.detail.reason).toContain("Denied by Policy Module");
    adcs.denyWith = null;

    expect(await h.renewAdcsRaCertificates()).toBe(0);
    h.setNow(new Date(START.getTime() + DAY_MS));
    expect(await h.renewAdcsRaCertificates()).toBe(1);
    expect((await api(acmeOrg, `/enrollment-profiles/${created.id}/ra-rotation`, {}, "POST")).status).toBe(409);
    await passAt(new Date(START.getTime() + DAY_MS), added.agent);
    expect((await profileOf(created.id)).raCertificate).not.toBeNull();
  });

  test("is renewed through ADCS once a third of its life is left, the old one serving until the new one is issued", async () => {
    const added = await adcsCa();
    // Issued for 30 days, it is renewed from 10 days before its end.
    atAdcs("CorpScepRa").validityDays = 30;
    const profile = await readyProfile(added);
    const first = profile.raCertificate!;
    const notAfter = new Date(first.notAfter).getTime();
    h.setNow(new Date(notAfter - 11 * DAY_MS));
    expect(await h.renewAdcsRaCertificates()).toBe(0);
    const due = new Date(notAfter - 9 * DAY_MS);
    h.setNow(due);
    expect(await h.renewAdcsRaCertificates()).toBe(1);
    expect(await h.renewAdcsRaCertificates()).toBe(0);
    const renewing = await profileOf(profile.id);
    expect(renewing.raRequested).toBe(true);
    expect(renewing.raCertificate).toEqual(first);

    await passAt(due, added.agent);
    const renewed = await profileOf(profile.id);
    expect(renewed.raCertificate!.serial).not.toBe(first.serial);
    expect(renewed.raRequested).toBe(false);
    const [issued] = (await auditOf("enrollment_profile.ra_issued")).filter((e) => e.detail.from);
    expect(issued!.detail.from.serial).toBe(first.serial);

    // Devices enroll with the new RA certificate.
    atAdcs("CorpDevice").managerApproval = false;
    const device = scepDevice(h, renewed.scepUrl);
    const pending = await submitPending(device, { subject: "CN=laptop-01" });
    await added.agent.work();
    expect(await device.check(pending)).not.toBe("pending");
  });
});

describe("a device enrolling under a profile on an ADCS CA", () => {
  test("is answered PENDING, its request is submitted through an Agent, and GetCertInitial gives it the Certificate ADCS issued", async () => {
    const added = await adcsCa();
    atAdcs("CorpDevice").managerApproval = false;
    const profile = await readyProfile(added);
    const device = scepDevice(h, profile.scepUrl);
    const pending = await submitPending(device, { subject: "CN=laptop-17, O=Acme", subjectAltNames: { dns: ["laptop-17.corp.example"] } });
    expect(await device.check(pending)).toBe("pending");

    const [item] = await added.agent.work();
    expect(item).toMatchObject({ type: "adcs.submit", payload: { configString: CONFIG, template: "CorpDevice" } });
    const enrolled = await device.check(pending);
    if (enrolled === "pending") throw new Error("still pending");
    const certificate = certificateOf(enrolled);
    const issued = adcs.issued.find((i) => i.template === "CorpDevice")!;
    expect(certificate.equal(issued.certificate)).toBe(true);
    expect(certificate.issuer).toBe(adcs.ca.certificate.subject);
    // GetCertInitial again, and the same PKCSReq sent again, are answered the same: nothing is submitted twice.
    expect(certificateOf((await device.check(pending)) as Enrolled).equal(issued.certificate)).toBe(true);
    const again = await device.submit({ subject: "CN=laptop-17, O=Acme", subjectAltNames: { dns: ["laptop-17.corp.example"] }, privateKey: pending.privateKey });
    expect("enrolled" in again && certificateOf(again.enrolled).equal(issued.certificate)).toBe(true);
    expect(adcs.issued.filter((i) => i.template === "CorpDevice")).toHaveLength(1);

    // Listed and searched like any Device Certificate, recording its ADCS request.
    const listed = await api(acmeOrg, `/enrollment-profiles/${profile.id}/device-certificates?q=laptop-17`);
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0]).toMatchObject({ serial: certificate.serialNumber.toUpperCase(), issuer: adcs.ca.certificate.subject, status: "active" });
    const [event] = await auditOf("device_certificate.issued");
    expect(event!.detail).toMatchObject({ adcsCa: { id: added.ca.id }, template: { id: added.device.id }, adcsRequestId: issued.requestId });
    const submitted = (await auditOf("adcs_ca.request_submitted")).filter((e) => e.detail.purpose === "device");
    expect(submitted.map((e) => [e.target, e.detail.adcsRequestId, e.detail.disposition])).toEqual([[{ type: "enrollment_profile", id: profile.id }, issued.requestId, "issued"]]);
  });

  test("held for a CA manager's approval stays PENDING until ADCS issues it on a later check", async () => {
    const added = await adcsCa();
    const profile = await readyProfile(added);
    const device = scepDevice(h, profile.scepUrl);
    const pending = await submitPending(device, { subject: "CN=laptop-02" });
    await added.agent.work();
    expect(adcs.pending.size).toBe(1);
    const [requestId] = [...adcs.pending.keys()];
    expect(await device.check(pending)).toBe("pending");
    expect((await auditOf("adcs_ca.request_pending"))[0]!.target).toEqual({ type: "enrollment_profile", id: profile.id });

    await adcs.approve(requestId!);
    await passAt(new Date(START.getTime() + FIRST_CHECK_AFTER_MS), added.agent);
    const enrolled = await device.check(pending);
    expect(enrolled).not.toBe("pending");
    expect(certificateOf(enrolled as Enrolled).serialNumber).toBe(adcs.issued.find((i) => i.requestId === requestId)!.certificate.serialNumber);
  });

  test("denied by ADCS is answered FAILURE badRequest with ADCS's reason, and refused for good", async () => {
    const added = await adcsCa();
    const profile = await readyProfile(added);
    const device = scepDevice(h, profile.scepUrl);
    const pending = await submitPending(device, { subject: "CN=laptop-03" });
    await added.agent.work();
    const [requestId] = [...adcs.pending.keys()];
    adcs.deny(requestId!, "Denied by the CA manager");
    await passAt(new Date(START.getTime() + FIRST_CHECK_AFTER_MS), added.agent);

    const failure = failureOf(await device.check(pending).catch((err: unknown) => err));
    expect(failure.failInfo).toBe(FailInfo.badRequest);
    expect(failure.failInfoText).toContain("Denied by the CA manager");
    expect((await auditOf("enrollment.refused"))[0]!.detail).toMatchObject({ adcsRequestId: requestId });
    expect((await api(acmeOrg, `/enrollment-profiles/${profile.id}/device-certificates`)).body.total).toBe(0);
  });

  test("held 7 days is answered FAILURE badRequest, as pending too long", async () => {
    const added = await adcsCa();
    const profile = await readyProfile(added);
    const device = scepDevice(h, profile.scepUrl);
    const pending = await submitPending(device, { subject: "CN=laptop-04" });
    await added.agent.work();
    await passAt(new Date(START.getTime() + PENDING_TIMEOUT_MS), added.agent);
    const failure = failureOf(await device.check(pending).catch((err: unknown) => err));
    expect(failure.failInfo).toBe(FailInfo.badRequest);
    expect(failure.failInfoText).toContain("for 7 days");
  });

  test("is refused before anything is submitted when it breaks the profile's name rules, the CA's Permitted Name Rules, or the template's key size", async () => {
    const added = await adcsCa();
    atAdcs("CorpDevice").managerApproval = false;
    expect((await api(acmeOrg, `/adcs-cas/${added.ca.id}`, { permittedNames: { exact: [], zones: ["devices.corp.example"] } }, "PATCH")).status).toBe(200);
    const nameRules = { requiredSubjectAttributes: ["CN"], subjectPatterns: { CN: ["laptop-*"] }, allowedSanTypes: ["dns"], sanPatterns: {} };
    const profile = await readyProfile(added, { nameRules, allowedKeyTypes: ["rsa-2048", "rsa-3072"] });
    const refusedFor = async (request: DeviceRequest) => failureOf(await scepDevice(h, profile.scepUrl).submit(request).catch((err: unknown) => err)).failInfoText;

    expect(await refusedFor({ subject: "CN=printer-01" })).toContain("CN");
    expect(await refusedFor({ subject: "CN=laptop-05", subjectAltNames: { dns: ["laptop-05.elsewhere.example"] } })).toContain("outside the Permitted Name Rules of the ADCS CA Corp");
    atAdcs("CorpDevice").minimumKeySize = 3072;
    await refresh(added);
    expect(await refusedFor({ subject: "CN=laptop-06", keyBits: 2048 })).toContain("at least 3072 bits");
    expect(added.agent.received.filter((i) => i.type === "adcs.submit" && i.payload.template === "CorpDevice")).toEqual([]);
    expect(await auditOf("enrollment.refused")).toHaveLength(3);
  });

  test("is refused while the device template is unavailable, which the profile shows without being disabled", async () => {
    const added = await adcsCa();
    const profile = await readyProfile(added);
    atAdcs("CorpDevice").enrollable = false;
    await refresh(added);
    const shown = await profileOf(profile.id);
    expect(shown.adcs!.templateUnavailable).toContain("may not enroll");
    const failure = failureOf(await scepDevice(h, profile.scepUrl).submit({ subject: "CN=laptop-07" }).catch((err: unknown) => err));
    expect(failure.failInfoText).toContain("is unavailable");
  });

  test("renewing with RenewalReq is answered PENDING too, and issued its replacement", async () => {
    const added = await adcsCa();
    atAdcs("CorpDevice").managerApproval = false;
    const profile = await readyProfile(added, { validator: { kind: "test_renewal" } });
    const device = scepDevice(h, profile.scepUrl);
    const first = await submitPending(device, { subject: "CN=laptop-08" });
    await added.agent.work();
    const current = (await device.check(first)) as Enrolled;

    const renewal = await submitPending(device, { subject: "CN=laptop-08" }, current);
    await added.agent.work();
    const replacement = await device.check(renewal);
    expect(replacement).not.toBe("pending");
    expect(certificateOf(replacement as Enrolled).serialNumber).not.toBe(certificateOf(current).serialNumber);
    expect((await api(acmeOrg, `/enrollment-profiles/${profile.id}/device-certificates`)).body.total).toBe(2);
  });
});

describe("Enrollment Validators on a profile on an ADCS CA", () => {
  const INTUNE_VALIDATOR = { kind: "intune", settings: { tenantId: INTUNE.tenantId, appId: INTUNE.appId }, secret: INTUNE.secret };
  const DEVICE_ID = "5b1e4f0e-8b2c-4a57-9a1d-0c6f3e2a7b11";
  const intuneRequest = { subject: "CN=laptop-20", subjectAltNames: { uri: [`IntuneDeviceId://${DEVICE_ID}`] }, challengePassword: "intune-signed-challenge" };

  test("Intune decides before anything is submitted, and is told of the Certificate once ADCS issues it", async () => {
    const added = await adcsCa();
    atAdcs("CorpDevice").managerApproval = false;
    const profile = await readyProfile(added, { validator: INTUNE_VALIDATOR });
    const device = scepDevice(h, profile.scepUrl);

    h.intune.refusing = "ChallengeExpired";
    const refused = failureOf(await device.submit({ ...intuneRequest, subject: "CN=laptop-21" }).catch((err: unknown) => err));
    expect(refused.failInfoText).toContain("ChallengeExpired");
    expect(added.agent.received.filter((i) => i.payload.template === "CorpDevice")).toEqual([]);
    h.intune.refusing = null;

    const pending = await submitPending(device, intuneRequest);
    expect(h.intune.validations).toHaveLength(2);
    await h.deliverEnrollmentNotifications();
    const successesBefore = h.intune.successes.length;
    await added.agent.work();
    const enrolled = (await device.check(pending)) as Enrolled;
    expect(await h.deliverEnrollmentNotifications()).toBeGreaterThanOrEqual(1);
    expect(h.intune.successes.slice(successesBefore)).toEqual([
      expect.objectContaining({ transactionId: h.intune.validations[1]!.transactionId, certificateSerialNumber: certificateOf(enrolled).serialNumber.toUpperCase() }),
    ]);
    const listed = await api(acmeOrg, `/enrollment-profiles/${profile.id}/device-certificates?q=${DEVICE_ID}`);
    expect(listed.body.items.map((c: { deviceId: string }) => c.deviceId)).toEqual([DEVICE_ID]);
  });

  test("Intune is told of the failure when ADCS denies what it allowed", async () => {
    const added = await adcsCa();
    adcs.denyWith = "Denied by Policy Module";
    const profile = await readyProfileDespiteDenial(added, { validator: INTUNE_VALIDATOR });
    const device = scepDevice(h, profile.scepUrl);
    const pending = await submitPending(device, intuneRequest);
    await added.agent.work();
    expect(failureOf(await device.check(pending).catch((err: unknown) => err)).failInfoText).toContain("Denied by Policy Module");
    await h.deliverEnrollmentNotifications();
    expect(h.intune.failures).toEqual([expect.objectContaining({ transactionId: h.intune.validations[0]!.transactionId })]);
  });

  test("a Shared Challenge profile is issued what ADCS issues once the challenge is presented", async () => {
    const added = await adcsCa();
    atAdcs("CorpDevice").managerApproval = false;
    const profile = await readyProfile(added, { validator: { kind: "shared_challenge" } });
    const device = scepDevice(h, profile.scepUrl);
    expect(failureOf(await device.submit({ subject: "CN=mac-01", challengePassword: "wrong" }).catch((err: unknown) => err)).failInfoText).toContain("not the Enrollment Profile's Shared Challenge");
    const pending = await submitPending(device, { subject: "CN=mac-02", challengePassword: profile.sharedChallenge!.challenge });
    await added.agent.work();
    expect(await device.check(pending)).not.toBe("pending");
    expect((await auditOf("device_certificate.issued"))[0]!.detail.sharedChallenge).toEqual({ id: profile.sharedChallenge!.id });
  });
});

/** A profile ready for devices while ADCS denies requests: its RA certificate is issued before the denials start. */
async function readyProfileDespiteDenial(added: Added, extra: Record<string, unknown>) {
  const denial = adcs.denyWith;
  adcs.denyWith = null;
  const profile = await readyProfile(added, extra);
  adcs.denyWith = denial;
  return profile;
}
