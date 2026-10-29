// Revoking Device Certificates from an ADCS CA, through the platform's HTTP API, its SCEP endpoint and the Agent protocol:
// an Organization Administrator, the Enrollment Validator's revocation feed and a RenewalReq's replacement (as
// `superseded`) each have an Agent carry out `adcs.revoke`, and the Revocation is recorded only once ADCS confirms it. The
// feed is answered only once ADCS has; a refusal, or no Agent to ask, is tried again as the feed's rules say, and a
// superseded one is asked again until ADCS revokes it. Here the Agents are stand-ins (agent-double.ts), ADCS an in-memory
// double (adcs-double.ts) and the validator service another (enrollment-validator-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { randomBytes } from "node:crypto";
import { ScepFailureError } from "ts-scep";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, AdcsDoubleError, CDP_URL, defaultTemplates } from "./support/adcs-double";
import { DOUBLE_SECRET } from "./support/enrollment-validator-double";
import { scepDevice, type DeviceRequest, type Enrolled, type ScepDevice } from "./support/scep-device";
import type { TemplateFacts } from "../src/adcs/adcs-kinds";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let adcs: AdcsDouble;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";
const START = new Date("2026-01-01T00:00:00Z");
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** A template for SCEP RA certificates, issued at once. */
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
  adcs.templates.find((t) => t.name === "CorpDevice")!.managerApproval = false;
  adcs.issued.length = 0;
  adcs.revoked.clear();
  adcs.hold = false;
  adcs.denyWith = null;
  adcs.pending.clear();
  adcs.denied.clear();
  adcs.now = () => START;
  h.setNow(START);
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
});
afterAll(async () => {
  await h.close();
});

const api = (path: string, body?: unknown, method?: string) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, body, method });
const auditOf = async (action: string) => ((await api("/audit-events?pageSize=200")).body.items as { action: string; actor: any; detail: any; target: any }[]).filter((e) => e.action === action);
const certificateOf = (enrolled: Enrolled) => new x509.X509Certificate(new Uint8Array(enrolled.certificate.raw));
const serialOf = (enrolled: Enrolled) => certificateOf(enrolled).serialNumber.toUpperCase();

/** Moves the clock, for the platform and ADCS alike. */
function at(ms: number) {
  const now = new Date(START.getTime() + ms);
  h.setNow(now);
  adcs.now = () => now;
}

type Profile = { id: string; scepUrl: string };

/**
 * An ADCS CA with a Windows Agent that reaches the double, and an Enrollment Profile on its device template whose RA
 * certificate ADCS has issued, with the validator given.
 */
async function adcsProfile(validator: Record<string, unknown> = { kind: "test_renewal" }) {
  const agent = await TestAgent.registered(h, org.cookie, org.orgId, { hostName: `win-${randomBytes(3).toString("hex")}`, os: "windows" });
  agent.adcs = adcs;
  const stop = agent.startWorking();
  let added;
  try {
    added = await api("/adcs-cas", { name: "Corp", configString: CONFIG, agentIds: [agent.id] });
  } finally {
    await stop();
  }
  expect(added.status).toBe(201);
  const template = (name: string) => (added.body.templates as { id: string; name: string }[]).find((t) => t.name === name)!;
  const created = await api("/enrollment-profiles", { name: "Wi-Fi", adcs: { adcsCaId: added.body.id, templateId: template("CorpDevice").id, raTemplateId: template("CorpScepRa").id }, validator });
  expect(created.status).toBe(201);
  await agent.work();
  return { agent, profile: created.body as Profile, device: scepDevice(h, created.body.scepUrl) };
}

/** Enrolls (or, given `current`, renews) through ADCS: PENDING, then issued once the Agent has carried out the submission. */
async function enroll(device: ScepDevice, agent: TestAgent, request: DeviceRequest, current?: Enrolled) {
  const sent = await device.submit(request, current);
  if (!("pending" in sent)) throw new Error("expected PENDING");
  await agent.work();
  const enrolled = await device.check(sent);
  if (enrolled === "pending") throw new Error("still pending");
  return enrolled;
}

type DeviceCertificate = { id: string; serial: string; status: string; revocation: any; revocationRequest: any; crlDistributionPoints: string[] };
const deviceCertificates = async (profile: Profile) => (await api(`/enrollment-profiles/${profile.id}/device-certificates`)).body.items as DeviceCertificate[];
const deviceCertificate = async (profile: Profile, serial: string) => (await deviceCertificates(profile)).find((c) => c.serial === serial)!;
const revokeType = (agent: TestAgent) => agent.received.filter((i) => i.type === "adcs.revoke");

describe("an Organization Administrator revoking a Device Certificate from an ADCS CA", () => {
  test("has an Agent carry out adcs.revoke, and it shows Revoked, with its CRL Distribution Points, once ADCS confirms", async () => {
    const { agent, profile, device } = await adcsProfile();
    const enrolled = await enroll(device, agent, { subject: "CN=laptop-01" });
    const before = await deviceCertificate(profile, serialOf(enrolled));
    expect(before.crlDistributionPoints).toEqual([CDP_URL]);

    const asked = await api(`/enrollment-profiles/${profile.id}/device-certificates/${before.id}/revocation`, { reason: "keyCompromise" });
    expect(asked.status).toBe(202);
    expect(asked.body).toMatchObject({ status: "active", revocation: null, revocationRequest: { status: "pending", reason: "keyCompromise" } });
    expect(await auditOf("device_certificate.revoked")).toEqual([]);
    // Asked again while ADCS has yet to answer, it is not asked twice.
    expect((await api(`/enrollment-profiles/${profile.id}/device-certificates/${before.id}/revocation`, { reason: "keyCompromise" })).status).toBe(409);

    const [item] = await agent.work();
    expect(item).toMatchObject({ type: "adcs.revoke", payload: { configString: CONFIG, serialNumber: BigInt(`0x${before.serial}`).toString(16), reason: 1 } });
    const after = await deviceCertificate(profile, before.serial);
    expect(after).toMatchObject({ status: "revoked", revocation: { reason: "keyCompromise" }, revocationRequest: null, crlDistributionPoints: [CDP_URL] });
    const [event] = await auditOf("device_certificate.revoked");
    expect(event!.actor.email).toBe("admin@acme.test");
    expect(event!.detail).toMatchObject({ serial: before.serial, reason: "keyCompromise" });
  });

  test("is refused privilegeWithdrawn, which ADCS does not take, and 502 with no Agent online to ask, recording nothing", async () => {
    const { agent, profile, device } = await adcsProfile();
    const enrolled = await enroll(device, agent, { subject: "CN=laptop-02" });
    const { id } = await deviceCertificate(profile, serialOf(enrolled));
    expect((await api(`/enrollment-profiles/${profile.id}/device-certificates/${id}/revocation`, { reason: "privilegeWithdrawn" })).status).toBe(422);

    at(2 * HOUR_MS);
    const offline = await api(`/enrollment-profiles/${profile.id}/device-certificates/${id}/revocation`, { reason: "keyCompromise" });
    expect(offline.status).toBe(502);
    expect(await deviceCertificate(profile, serialOf(enrolled))).toMatchObject({ status: "active", revocationRequest: null });
  });

  test("refused by ADCS, it stays active with the failure shown, and may be revoked again", async () => {
    const { agent, profile, device } = await adcsProfile();
    const enrolled = await enroll(device, agent, { subject: "CN=laptop-03" });
    const { id } = await deviceCertificate(profile, serialOf(enrolled));
    await api(`/enrollment-profiles/${profile.id}/device-certificates/${id}/revocation`, { reason: "cessationOfOperation" });
    adcs.failure = new AdcsDoubleError("rejected", "Access is denied");
    await agent.work();
    const refused = await deviceCertificate(profile, serialOf(enrolled));
    expect(refused).toMatchObject({ status: "active", revocationRequest: { status: "failed", failure: { code: "rejected" } } });
    expect((await auditOf("device_certificate.revocation_failed")).map((e) => e.target.id)).toEqual([id]);

    adcs.failure = null;
    expect((await api(`/enrollment-profiles/${profile.id}/device-certificates/${id}/revocation`, { reason: "cessationOfOperation" })).status).toBe(202);
    await agent.work();
    expect((await deviceCertificate(profile, serialOf(enrolled))).status).toBe("revoked");
  });
});

describe("an Enrollment Validator's revocation feed on a profile on an ADCS CA", () => {
  const DOUBLE = { kind: "test_double", settings: { tenant: "contoso" }, secret: DOUBLE_SECRET };

  /** What the feed has been told, outcome by outcome. */
  const told = async () => {
    await h.deliverEnrollmentNotifications();
    return h.validatorDouble.reports.flatMap((r) => r.outcomes.map((o) => o.outcome));
  };

  test("revokes at ADCS, and is told the outcome only once ADCS has confirmed it", async () => {
    const { agent, profile, device } = await adcsProfile(DOUBLE);
    const retired = await enroll(device, agent, { subject: "CN=retired" });
    h.validatorDouble.queueRevocation("contoso", serialOf(retired).toLowerCase(), certificateOf(retired).issuer);

    expect(await h.pollRevocationFeeds()).toBe(1);
    expect(await deviceCertificate(profile, serialOf(retired))).toMatchObject({ status: "active", revocationRequest: { status: "pending", reason: "cessationOfOperation" } });
    const [requested] = await auditOf("device_certificate.revocation_requested");
    expect(requested!.actor.id).toBeNull();
    expect(requested!.detail).toMatchObject({ serial: serialOf(retired), reason: "cessationOfOperation", by: { enrollmentValidator: { kind: "test_double" } } });
    expect(await told()).toEqual([]);
    // Passes while ADCS has yet to answer neither ask again nor answer the feed.
    at(MINUTE_MS);
    await h.pollRevocationFeeds();
    expect(await told()).toEqual([]);

    const [item] = await agent.work();
    expect(item).toMatchObject({ type: "adcs.revoke", payload: { reason: 5 } });
    expect(revokeType(agent)).toHaveLength(1);
    expect(await deviceCertificate(profile, serialOf(retired))).toMatchObject({ status: "revoked", revocation: { reason: "cessationOfOperation" } });
    const [event] = await auditOf("device_certificate.revoked");
    expect(event!.detail.by).toEqual({ enrollmentValidator: { kind: "test_double" } });

    at(2 * MINUTE_MS);
    await h.pollRevocationFeeds();
    expect(await told()).toEqual(["revoked"]);
    // Told once.
    at(3 * MINUTE_MS);
    await h.pollRevocationFeeds();
    expect(await told()).toEqual(["revoked"]);
  });

  test("refused by ADCS, it is asked again on each pass, and answered failed with ADCS's reason after five tries", async () => {
    const { agent, profile, device } = await adcsProfile(DOUBLE);
    const retired = await enroll(device, agent, { subject: "CN=refused" });
    h.validatorDouble.queueRevocation("contoso", serialOf(retired));
    adcs.failure = new AdcsDoubleError("rejected", "Access is denied");
    for (let pass = 0; pass < 6; pass++) {
      at(pass * MINUTE_MS);
      await agent.poll();
      await h.pollRevocationFeeds();
      await agent.work();
    }
    expect(revokeType(agent)).toHaveLength(5);
    expect((await deviceCertificate(profile, serialOf(retired))).status).toBe("active");
    await h.deliverEnrollmentNotifications();
    const outcomes = h.validatorDouble.reports.flatMap((r) => r.outcomes);
    expect(outcomes).toEqual([{ ref: expect.any(String), outcome: "failed", message: expect.stringContaining("Access is denied") }]);
  });

  test("refused once, it is revoked when asked again, and told revoked", async () => {
    const { agent, device } = await adcsProfile(DOUBLE);
    const retired = await enroll(device, agent, { subject: "CN=flaky" });
    h.validatorDouble.queueRevocation("contoso", serialOf(retired));
    adcs.failure = new AdcsDoubleError("unreachable", "the RPC server is unavailable");
    await h.pollRevocationFeeds();
    await agent.work();
    adcs.failure = null;
    at(MINUTE_MS);
    await agent.poll();
    await h.pollRevocationFeeds();
    expect(await told()).toEqual([]);
    await agent.work();
    at(2 * MINUTE_MS);
    await h.pollRevocationFeeds();
    expect(await told()).toEqual(["revoked"]);
  });

  test("with no Agent online, it is tried again on later passes, and revoked once one is", async () => {
    const { agent, profile, device } = await adcsProfile(DOUBLE);
    const retired = await enroll(device, agent, { subject: "CN=offline" });
    h.validatorDouble.queueRevocation("contoso", serialOf(retired));
    at(2 * HOUR_MS);
    await h.pollRevocationFeeds();
    expect(await deviceCertificate(profile, serialOf(retired))).toMatchObject({ status: "active", revocationRequest: null });
    expect(await told()).toEqual([]);

    at(2 * HOUR_MS + MINUTE_MS);
    await agent.work();
    await h.pollRevocationFeeds();
    await agent.work();
    at(2 * HOUR_MS + 2 * MINUTE_MS);
    await h.pollRevocationFeeds();
    expect((await deviceCertificate(profile, serialOf(retired))).status).toBe("revoked");
    expect(await told()).toEqual(["revoked"]);
  });
});

describe("a RenewalReq on a profile on an ADCS CA", () => {
  test("revokes the Device Certificate it renews as superseded at ADCS, once the replacement is issued and ADCS confirms", async () => {
    const { agent, profile, device } = await adcsProfile();
    const current = await enroll(device, agent, { subject: "CN=laptop-08" });
    const renewal = await device.submit({ subject: "CN=laptop-08" }, current);
    if (!("pending" in renewal)) throw new Error("expected PENDING");
    // Nothing is revoked before the replacement is issued.
    expect(revokeType(agent)).toEqual([]);
    await agent.work();
    const replacement = (await device.check(renewal)) as Enrolled;
    expect(await deviceCertificate(profile, serialOf(current))).toMatchObject({ status: "active", revocationRequest: { status: "pending", reason: "superseded" } });
    const [requested] = await auditOf("device_certificate.revocation_requested");
    expect(requested!.detail).toMatchObject({ serial: serialOf(current), reason: "superseded", by: { renewal: { serial: serialOf(replacement) } } });

    const [item] = await agent.work();
    expect(item).toMatchObject({ type: "adcs.revoke", payload: { serialNumber: BigInt(`0x${serialOf(current)}`).toString(16), reason: 4 } });
    expect(await deviceCertificate(profile, serialOf(current))).toMatchObject({ status: "revoked", revocation: { reason: "superseded" } });
    expect((await deviceCertificate(profile, serialOf(replacement))).status).toBe("active");
    const [event] = await auditOf("device_certificate.revoked");
    expect(event!.detail.by).toEqual({ renewal: { serial: serialOf(replacement) } });
  });

  test("refused by ADCS, it is asked again a day later until ADCS revokes it", async () => {
    const { agent, profile, device } = await adcsProfile();
    const current = await enroll(device, agent, { subject: "CN=laptop-09" });
    await enroll(device, agent, { subject: "CN=laptop-09" }, current);
    adcs.failure = new AdcsDoubleError("rejected", "Access is denied");
    await agent.work();
    expect(await deviceCertificate(profile, serialOf(current))).toMatchObject({ status: "active", revocationRequest: { status: "failed" } });

    adcs.failure = null;
    at(HOUR_MS);
    await agent.poll();
    expect(await h.supersedeRenewed()).toBe(0);
    at(DAY_MS + HOUR_MS);
    await agent.poll();
    expect(await h.supersedeRenewed()).toBe(1);
    await agent.work();
    expect(await deviceCertificate(profile, serialOf(current))).toMatchObject({ status: "revoked", revocation: { reason: "superseded" } });
    expect(await h.supersedeRenewed()).toBe(0);
  });

  test("with no Agent online when the replacement is issued, it is asked once one is", async () => {
    const { agent, profile, device } = await adcsProfile();
    const current = await enroll(device, agent, { subject: "CN=laptop-10" });
    const renewal = await device.submit({ subject: "CN=laptop-10" }, current);
    if (!("pending" in renewal)) throw new Error("expected PENDING");
    // The Agent takes the submission and reports it only once it is no longer online.
    agent.stalled = true;
    const [submission] = await agent.work();
    at(2 * HOUR_MS);
    expect((await agent.report(submission!.id, { ok: true, submission: await adcs.submit(CONFIG, submission!.payload.template, submission!.payload.csr) })).status).toBe(200);
    expect(await device.check(renewal)).not.toBe("pending");
    expect(await deviceCertificate(profile, serialOf(current))).toMatchObject({ status: "active", revocationRequest: null });
    expect(await h.supersedeRenewed()).toBe(0);

    agent.stalled = false;
    at(2 * HOUR_MS + MINUTE_MS);
    await agent.poll();
    expect(await h.supersedeRenewed()).toBe(1);
    await agent.work();
    expect((await deviceCertificate(profile, serialOf(current))).status).toBe("revoked");
  });

  test("signed with a Device Certificate already renewed is refused, so a device holds one valid certificate", async () => {
    const { agent, device } = await adcsProfile();
    const current = await enroll(device, agent, { subject: "CN=laptop-11" });
    await enroll(device, agent, { subject: "CN=laptop-11" }, current);
    // ADCS has yet to revoke it, but it is renewed already.
    const again = await device.submit({ subject: "CN=laptop-11" }, current).catch((err: unknown) => err);
    expect(again).toBeInstanceOf(ScepFailureError);
    expect((again as ScepFailureError).failInfoText).toContain("already renewed");
    expect((await auditOf("enrollment.refused")).map((e) => e.detail.reason)).toEqual([expect.stringContaining("already renewed")]);
  });
});
