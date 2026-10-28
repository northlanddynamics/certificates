// Certificate Profiles on an ADCS CA, through the platform's HTTP API and the Agent protocol: an Organization
// Administrator names an ADCS CA and one of its TLS templates as a profile's issuer, with no validity, since the template
// decides it; members propose through it under its name rules and the CA's Permitted Name Rules. A profile whose template
// becomes unavailable says so but stays enabled, and its Issuances fail with that cause until the template is back. Here
// the Agents are stand-ins (agent-double.ts) and ADCS an in-memory double (adcs-double.ts).
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { PASSWORD, createHarness, type Harness } from "./support/harness";
import { TestAgent } from "./support/agent-double";
import { AdcsDouble, defaultTemplates } from "./support/adcs-double";
import { acmeAccount, secret } from "../src/platform/db/schema";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };
let adcs: AdcsDouble;
type Org = typeof acmeOrg;

const CONFIG = "ca01.corp.example\\Corp Issuing CA";

beforeAll(async () => {
  h = await createHarness({ adcsRelay: { attemptTimeoutMs: 1500 }, dnsRelay: { pollMs: 10 } });
  adcs = await AdcsDouble.create(CONFIG);
});
beforeEach(async () => {
  await h.reset();
  adcs.failure = null;
  adcs.templates = defaultTemplates();
  adcs.issued.length = 0;
  adcs.hold = false;
  adcs.denyWith = null;
  adcs.pending.clear();
  adcs.denied.clear();
  adcs.now = () => new Date("2026-01-01T00:00:00Z");
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const api = (org: Org, path: string, body?: unknown, method?: string, cookie = org.cookie) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie, body, method });
const auditOf = async (action: string, org: Org = acmeOrg) =>
  ((await api(org, "/audit-events")).body.items as { action: string; detail: any; target: any }[]).filter((e) => e.action === action);

type Template = { id: string; name: string };
type Ca = { id: string; name: string; templates: Template[] };

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
  return { ca, agent, tls: template("CorpWebServer"), device: template("CorpDevice"), directory: template("Workstation") };
}

/** A key and a CSR for the names: RSA 2048 unless asked otherwise. */
async function csrFor(names: string[], keyAlgorithm: "rsa-2048" | "ecdsa-p256" = "rsa-2048") {
  const key = keyAlgorithm === "ecdsa-p256" ? await acme.crypto.createPrivateEcdsaKey("P-256") : await acme.crypto.createPrivateRsaKey(2048);
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { csr: csr.toString(), keyAlgorithm };
}

/** A member of the Organization in the role, signed in. */
async function memberWithRole(role: string, email = `${role}@acme.test`) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return await h.signIn(email, PASSWORD);
}

/** Requests a Managed Certificate for the names through the profile, as the one whose cookie it is. */
const requestThrough = async (profileId: string, names: string[], cookie: string, keyAlgorithm: "rsa-2048" | "ecdsa-p256" = "rsa-2048") =>
  api(acmeOrg, "/managed-certificates", { names, ...(await csrFor(names, keyAlgorithm)), profileId }, undefined, cookie);

/** The Managed Certificate as it is now. */
const mcOf = async (id: string) => (await api(acmeOrg, `/managed-certificates/${id}`)).body;

/** Has the Agent take its work once, after the Issuances started so far have had their say. */
async function work(agent: TestAgent) {
  await h.settleIssuances();
  await agent.work();
}

/** An ACME Account of the Organization's with the ACME CA, as registering one would leave it (registration itself is the ACME Accounts tests' to check). */
async function haveAcmeAccount(acmeCaId = "letsencrypt-staging") {
  const [held] = await h.db.insert(secret).values({ organizationId: acmeOrg.orgId, ciphertext: Buffer.from("not-a-key") }).returning();
  await h.db.insert(acmeAccount).values({ organizationId: acmeOrg.orgId, acmeCaId, accountUrl: `https://acme.test/acct/${acmeCaId}`, secretId: held!.id });
}

/** Has the Agent discover the CA again. */
async function refresh(ca: Ca, agent: TestAgent) {
  const stop = agent.startWorking();
  try {
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}/refresh`, {}, "POST")).status).toBe(200);
  } finally {
    await stop();
  }
}

const issuerOf = (ca: Ca, template: Template) => ({ kind: "adcs", adcsCaId: ca.id, templateId: template.id });
const createProfile = (body: Record<string, unknown>, org: Org = acmeOrg) => api(org, "/certificate-profiles", body);
const updateProfile = (id: string, body: Record<string, unknown>) => api(acmeOrg, `/certificate-profiles/${id}`, body, "PATCH");

/** A profile on the ADCS CA's template, as an Organization Administrator creates it, with `extra` given too. */
async function profileOn(ca: Ca, template: Template, extra: Record<string, unknown> = {}) {
  const res = await createProfile({ name: "Corp web", issuer: issuerOf(ca, template), allowedKeyAlgorithms: ["rsa-2048"], ...extra });
  expect(res.status).toBe(201);
  return res.body as { id: string; name: string };
}

describe("a Certificate Profile on an ADCS CA", () => {
  test("an Organization Administrator creates one on a TLS template, with no validity, which is listed and audited", async () => {
    const { ca, tls } = await adcsCa();
    const res = await createProfile({ name: "Corp web", issuer: issuerOf(ca, tls), allowedKeyAlgorithms: ["rsa-2048", "ecdsa-p256"] });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ issuer: { kind: "adcs", adcsCaId: ca.id, templateId: tls.id }, allowedKeyAlgorithms: ["rsa-2048", "ecdsa-p256"], validityDays: null, templateUnavailable: null, enabled: true });
    expect((await api(acmeOrg, "/certificate-profiles")).body.items).toEqual([res.body]);
    expect((await auditOf("certificate_profile.created"))[0]!.detail).toMatchObject({ issuer: { kind: "adcs", adcsCaId: ca.id, templateId: tls.id }, validityDays: null });
  });

  test("its template must be offered for TLS, its keys taken by the template, and no validity given", async () => {
    const { ca, tls, device, directory } = await adcsCa();
    const body = (template: Template, extra: Record<string, unknown> = {}) => ({ name: "Corp web", issuer: issuerOf(ca, template), allowedKeyAlgorithms: ["rsa-2048"], ...extra });

    const validity = await createProfile(body(tls, { validityDays: 90 }));
    expect(validity.status).toBe(400);
    expect(validity.body.error).toContain("an ADCS CA's Certificate Template decides it");

    const forDevices = await createProfile(body(device));
    expect(forDevices.status).toBe(422);
    expect(forDevices.body.error).toBe("the Certificate Template Corp Device of the ADCS CA Corp is not offered for TLS: It has no Server Authentication EKU.");
    const fromDirectory = await createProfile(body(directory));
    expect(fromDirectory.status).toBe(422);
    expect(fromDirectory.body.error).toContain("It builds the subject from Active Directory");

    const p384 = await createProfile(body(tls, { allowedKeyAlgorithms: ["rsa-2048", "ecdsa-p384"] }));
    expect(p384.status).toBe(422);
    expect(p384.body.error).toBe("the Certificate Template CorpWebServer takes keys of RSA, ECDSA P-256, not ecdsa-p384");
    expect((await createProfile(body(tls, { allowedKeyAlgorithms: ["ml-dsa-65"] }))).status).toBe(422);

    expect((await api(acmeOrg, `/adcs-cas/${ca.id}/templates/${tls.id}/hide`, {}, "POST")).status).toBe(200);
    const hidden = await createProfile(body(tls));
    expect(hidden.status).toBe(422);
    expect(hidden.body.error).toContain("an Organization Administrator hid it");
    expect(await auditOf("certificate_profile.created")).toEqual([]);
  });

  test("another Organization's ADCS CA is refused, as one it has none such", async () => {
    const { ca, tls } = await adcsCa(globex);
    const res = await createProfile({ name: "Corp web", issuer: issuerOf(ca, tls), allowedKeyAlgorithms: ["rsa-2048"] });
    expect(res.status).toBe(422);
    expect(res.body.error).toBe("the Organization has no such ADCS CA");
    expect((await createProfile({ name: "Corp web", issuer: { kind: "adcs", adcsCaId: "not-an-id", templateId: tls.id }, allowedKeyAlgorithms: ["rsa-2048"] })).status).toBe(422);
  });

  test("editing points a profile at an ADCS template and back, checked as when it is created", async () => {
    const { ca, tls } = await adcsCa();
    const privateCa = await api(acmeOrg, "/private-cas", {
      name: "Internal",
      subject: "CN=Internal, O=Acme",
      keyAlgorithm: "ecdsa-p256",
      lifetimeYears: 5,
      permittedNames: { exact: [], zones: ["corp.example"] },
    });
    const issuingCaId = privateCa.body.issuingCas[0].id as string;
    const created = await createProfile({ name: "Corp web", issuer: { kind: "private_ca", issuingCaId }, allowedKeyAlgorithms: ["rsa-2048"], validityDays: 90 });
    expect(created.status).toBe(201);

    // The validity it has is checked with the new issuer, so it must go with it.
    expect((await updateProfile(created.body.id, { issuer: issuerOf(ca, tls) })).status).toBe(400);
    const moved = await updateProfile(created.body.id, { issuer: issuerOf(ca, tls), validityDays: null });
    expect(moved.status).toBe(200);
    expect(moved.body).toMatchObject({ issuer: { kind: "adcs", adcsCaId: ca.id, templateId: tls.id }, validityDays: null });
    expect((await auditOf("certificate_profile.updated"))[0]!.detail.changes.issuer).toEqual({ from: { kind: "private_ca", issuingCaId }, to: { kind: "adcs", adcsCaId: ca.id, templateId: tls.id } });

    const back = await updateProfile(created.body.id, { issuer: { kind: "private_ca", issuingCaId } });
    expect(back.status).toBe(200);
    expect(back.body.issuer).toEqual({ kind: "private_ca", issuingCaId });
  });
});

describe("requesting through a Certificate Profile on an ADCS CA", () => {
  test("a Member's proposal copies the ADCS CA and template onto the Managed Certificate, and is issued through an Agent once approved", async () => {
    const { ca, agent, tls } = await adcsCa();
    const profile = await profileOn(ca, tls);
    const member = await memberWithRole("member");
    const proposed = await requestThrough(profile.id, ["web.corp.example"], member);
    expect(proposed.status).toBe(201);
    expect(proposed.body).toMatchObject({
      issuer: { kind: "adcs", adcsCa: { id: ca.id, name: "Corp" }, template: { id: tls.id, name: "CorpWebServer" } },
      validityDays: null,
      approval: { status: "pending" },
      profile: { id: profile.id, name: "Corp web", enabled: true },
    });

    const approver = await memberWithRole("approver");
    expect((await api(acmeOrg, `/managed-certificates/${proposed.body.id}/approve`, {}, "POST", approver)).status).toBe(200);
    await work(agent);
    const mc = await mcOf(proposed.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded" });
    expect(mc.currentCertificate.names).toEqual(["web.corp.example"]);
    expect(adcs.issued.map((i) => i.template)).toEqual(["CorpWebServer"]);
  });

  test("a Member keeps to the profile's name rules and the ADCS CA's Permitted Name Rules; an Organization Administrator to the CA's alone", async () => {
    const { ca, tls } = await adcsCa();
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, { permittedNames: { exact: [], zones: ["corp.example"] } }, "PATCH")).status).toBe(200);
    const profile = await profileOn(ca, tls, { nameRules: { exact: [], zones: ["web.corp.example"], maxNames: null, wildcards: false } });
    const member = await memberWithRole("member");

    const outsideProfile = await requestThrough(profile.id, ["mail.corp.example"], member);
    expect(outsideProfile.status).toBe(422);
    expect(outsideProfile.body.error).toContain("Corp web");
    expect((await requestThrough(profile.id, ["a.web.corp.example"], member)).status).toBe(201);

    // The profile's rules let it through; the CA's do not.
    expect((await updateProfile(profile.id, { nameRules: { exact: [], zones: [], maxNames: null, wildcards: false } })).status).toBe(200);
    const outsideCa = await requestThrough(profile.id, ["web.other.example"], member);
    expect(outsideCa.status).toBe(422);
    expect(outsideCa.body.error).toBe("web.other.example is outside the Permitted Name Rules of the ADCS CA Corp");
    const byAdmin = await requestThrough(profile.id, ["web.other.example"], acmeOrg.cookie);
    expect(byAdmin.status).toBe(422);
    expect(byAdmin.body.error).toBe("web.other.example is outside the Permitted Name Rules of the ADCS CA Corp");
    expect(adcs.issued).toHaveLength(0);
  });

  test("a key the profile does not allow is refused", async () => {
    const { ca, tls } = await adcsCa();
    const profile = await profileOn(ca, tls);
    const res = await requestThrough(profile.id, ["web.corp.example"], await memberWithRole("member"), "ecdsa-p256");
    expect(res.status).toBe(422);
    expect(res.body.error).toBe("the Certificate Profile Corp web allows keys of rsa-2048, not ecdsa-p256");
  });
});

describe("a profile whose template is unavailable", () => {
  test("shows why, in the list and when read, but stays enabled; requests through it are refused and its Issuances fail until the template is back", async () => {
    const { ca, agent, tls } = await adcsCa();
    const profile = await profileOn(ca, tls);
    const made = await requestThrough(profile.id, ["web.corp.example"], acmeOrg.cookie);
    expect(made.status).toBe(201);
    await work(agent);
    expect((await mcOf(made.body.id)).issuance.status).toBe("succeeded");

    // The gMSA loses the right to enroll on it.
    adcs.templates = defaultTemplates().map((t) => (t.name === "CorpWebServer" ? { ...t, enrollable: false } : t));
    await refresh(ca, agent);
    const read = await api(acmeOrg, `/certificate-profiles/${profile.id}`);
    expect(read.body).toMatchObject({ enabled: true, templateUnavailable: "The Agents' account may not enroll on it." });
    expect((await api(acmeOrg, "/certificate-profiles")).body.items).toEqual([expect.objectContaining({ id: profile.id, enabled: true, templateUnavailable: "The Agents' account may not enroll on it." })]);
    // Members still see it.
    const member = await memberWithRole("member");
    expect((await api(acmeOrg, "/certificate-profiles", undefined, undefined, member)).body.items).toHaveLength(1);

    const refused = await requestThrough(profile.id, ["api.corp.example"], member);
    expect(refused.status).toBe(422);
    expect(refused.body.error).toBe(
      "the Certificate Profile Corp web cannot issue now: the Certificate Template Corp Web Server of the ADCS CA Corp is unavailable: The Agents' account may not enroll on it.",
    );
    expect((await api(acmeOrg, `/managed-certificates/${made.body.id}/renewals`, {}, "POST")).status).toBe(202);
    await h.settleIssuances();
    expect((await mcOf(made.body.id)).issuance).toMatchObject({ status: "failed", failure: { code: "template_unavailable" } });
    // Editing what does not touch its issuer is not held up by it.
    expect((await updateProfile(profile.id, { description: "Internal web servers" })).status).toBe(200);

    // ADCS is fixed: the next discovery makes it available again, with nothing reconfigured.
    adcs.templates = defaultTemplates();
    await refresh(ca, agent);
    expect((await api(acmeOrg, `/certificate-profiles/${profile.id}`)).body.templateUnavailable).toBeNull();
    expect((await requestThrough(profile.id, ["api.corp.example"], member)).status).toBe(201);
    expect((await api(acmeOrg, `/managed-certificates/${made.body.id}/renewals`, {}, "POST")).status).toBe(202);
    await work(agent);
    expect((await mcOf(made.body.id)).issuance).toMatchObject({ kind: "renewal", status: "succeeded" });
  });
});

describe("removing an ADCS CA", () => {
  test("is refused while a Certificate Profile names it, and allowed once none does", async () => {
    const { ca, tls } = await adcsCa();
    const profile = await profileOn(ca, tls);
    const refused = await api(acmeOrg, `/adcs-cas/${ca.id}`, undefined, "DELETE");
    expect(refused.status).toBe(409);
    expect(refused.body.error).toContain("cannot be removed");

    await haveAcmeAccount();
    expect((await updateProfile(profile.id, { issuer: { kind: "acme", acmeCaId: "letsencrypt-staging" } })).status).toBe(200);
    expect((await api(acmeOrg, `/adcs-cas/${ca.id}`, undefined, "DELETE")).status).toBe(204);
  });
});

