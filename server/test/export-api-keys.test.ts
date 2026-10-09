// Export and API keys: a Certificate downloads as PEM, DER or PKCS#7 with its chain as leaf only, with intermediates or
// with the root too, the current one or any earlier one; and a user's API key, scoped to one Organization, fetches
// the current Certificate the same way without a session. Each Certificate here is issued by Pebble for real.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { X509Certificates } from "@peculiar/x509";
import acme from "acme-client";
import { X509Certificate, randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let org: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const keysPath = (orgId = org.orgId) => `/api/organizations/${orgId}/api-keys`;

/** A download, as a session (cookie) or an API key would ask for it; the raw response, since it is not always text. */
const download = (who: { cookie?: string; apiKey?: string }, orgId: string, id: string, query = "", certificateId?: string) =>
  h.app.request(`http://localhost${base(orgId)}/${id}/${certificateId ? `certificates/${certificateId}/download` : "certificate"}${query}`, {
    headers: { ...(who.cookie && { cookie: who.cookie }), ...(who.apiKey && { "x-api-key": who.apiKey }) },
  });
const asAdmin = { get cookie() { return org.cookie; } };

const auditOf = async (orgId = org.orgId, cookie = org.cookie) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

async function join(email: string, role: string, target = org) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: target.cookie, body: { email, role, organizationId: target.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}
const userId = async (cookie: string) => (await h.api("/api/me", { cookie })).body.user.id as string;

/** An Organization that can issue: an ACME account and a DNS Provider that publishes into BIND. */
async function readyToIssue(target = org) {
  expect((await h.api(`/api/organizations/${target.orgId}/acme-accounts`, { cookie: target.cookie, body: { termsOfServiceAgreed: true } })).status).toBe(201);
  expect(
    (
      await h.api(`/api/organizations/${target.orgId}/dns-providers`, {
        cookie: target.cookie,
        body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
      })
    ).status,
  ).toBe(201);
}

/** A Managed Certificate with a Certificate issued (and a second one when asked for). */
async function issued(target = org, owners: { type: string; id: string }[] = [], renewals = 0) {
  const created = await h.api(base(target.orgId), { cookie: target.cookie, body: { ...(await request()), owners } });
  expect(created.status).toBe(201);
  await h.settleIssuances();
  for (let i = 0; i < renewals; i++) {
    expect((await h.api(`${base(target.orgId)}/${created.body.id}/issuances`, { cookie: target.cookie, method: "POST", body: {} })).status).toBe(202);
    await h.settleIssuances();
  }
  const certificates = (await h.api(`${base(target.orgId)}/${created.body.id}/certificates`, { cookie: target.cookie })).body.items as { id: string }[];
  expect(certificates).toHaveLength(renewals + 1);
  return { id: created.body.id as string, certificates };
}

const pemBlocks = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];
/** The certificates of a run of DER certificates one after the other. */
function derCertificates(bytes: Uint8Array): X509Certificate[] {
  const out: X509Certificate[] = [];
  let at = 0;
  while (at < bytes.length) {
    expect(bytes[at]).toBe(0x30);
    const first = bytes[at + 1]!;
    const lengthBytes = first & 0x80 ? first & 0x7f : 0;
    let length = lengthBytes ? 0 : first;
    for (let i = 0; i < lengthBytes; i++) length = length * 256 + bytes[at + 2 + i]!;
    const size = 2 + lengthBytes + length;
    out.push(new X509Certificate(Buffer.from(bytes.slice(at, at + size))));
    at += size;
  }
  return out;
}
const bytesOf = async (res: Response) => new Uint8Array(await res.arrayBuffer());
const fingerprints = (certs: X509Certificate[]) => certs.map((c) => c.fingerprint256);

/** The certificates a response carries, whatever its format. */
async function certificatesIn(res: Response, format: string): Promise<X509Certificate[]> {
  expect(res.status).toBe(200);
  if (format === "pem") return pemBlocks(await res.text()).map((pem) => new X509Certificate(pem));
  if (format === "der") return derCertificates(await bytesOf(res));
  const pkcs7 = await res.text();
  expect(pkcs7).toStartWith("-----BEGIN PKCS7-----");
  return new X509Certificates(pkcs7).map((c) => new X509Certificate(Buffer.from(c.rawData)));
}

const FORMATS = ["pem", "der", "p7b"] as const;
const CHAINS = ["leaf", "with-intermediates", "with-root"] as const;

describe("Export", () => {
  test("each format carries the leaf, the leaf with its intermediates, or those with the root", async () => {
    await readyToIssue();
    const mc = await issued();
    const [root] = await h.caRoots.current();
    const rootCert = new X509Certificate(root!);

    // The reference: what the CA served, which is the leaf and its intermediates.
    const served = await certificatesIn(await download(asAdmin, org.orgId, mc.id, "?format=pem&chain=with-intermediates"), "pem");
    expect(served.length).toBeGreaterThanOrEqual(2);
    const [leaf, ...intermediates] = served as [X509Certificate, ...X509Certificate[]];
    expect(leaf.subjectAltName).toContain("DNS:");
    expect(intermediates.at(-1)!.verify(rootCert.publicKey)).toBe(true);

    for (const format of FORMATS) {
      expect(fingerprints(await certificatesIn(await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=leaf`), format))).toEqual([leaf.fingerprint256]);
      expect(fingerprints(await certificatesIn(await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=with-intermediates`), format))).toEqual(fingerprints(served));
      const withRoot = await certificatesIn(await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=with-root`), format);
      expect(fingerprints(withRoot)).toEqual([...fingerprints(served), rootCert.fingerprint256]);
    }
  });

  test("without a format or chain it is PEM with the intermediates, and it says what it is", async () => {
    await readyToIssue();
    const mc = await issued();
    const res = await download(asAdmin, org.orgId, mc.id);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/x-pem-file");
    const pem = await res.text();
    expect(pemBlocks(pem).length).toBeGreaterThanOrEqual(2);
    expect(pem).not.toContain("PRIVATE KEY");
    const explicit = await (await download(asAdmin, org.orgId, mc.id, "?format=pem&chain=with-intermediates")).text();
    expect(pem).toBe(explicit);

    const types = { pem: "application/x-pem-file", der: "application/pkix-cert", p7b: "application/x-pkcs7-certificates" };
    const extensions = { pem: "pem", der: "der", p7b: "p7b" };
    for (const format of FORMATS) {
      const res = await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=leaf`);
      expect(res.headers.get("content-type")).toContain(types[format]);
      expect(res.headers.get("content-disposition")).toMatch(new RegExp(`^attachment; filename="t[0-9a-f]+\\.rfc2136\\.test\\.leaf\\.${extensions[format]}"$`));
    }
  });

  test("there is no PFX or JKS, and a format or chain that does not exist is refused", async () => {
    await readyToIssue();
    const mc = await issued();
    for (const query of ["?format=pfx", "?format=p12", "?format=jks", "?format=zip", "?chain=everything", "?format=pem&chain="]) {
      expect((await download(asAdmin, org.orgId, mc.id, query)).status).toBe(400);
    }
  });

  test("any earlier Certificate can be downloaded, in every form, and only one of this Managed Certificate", async () => {
    await readyToIssue();
    const mc = await issued(org, [], 1);
    const other = await issued();
    const [newest, earliest] = mc.certificates as [{ id: string }, { id: string }];

    const currentLeaf = await certificatesIn(await download(asAdmin, org.orgId, mc.id, "?chain=leaf"), "pem");
    for (const format of FORMATS) {
      const earlier = await certificatesIn(await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=leaf`, earliest.id), format);
      expect(earlier).toHaveLength(1);
      expect(earlier[0]!.fingerprint256).not.toBe(currentLeaf[0]!.fingerprint256);
      expect(
        (await certificatesIn(await download(asAdmin, org.orgId, mc.id, `?format=${format}&chain=with-root`, earliest.id), format)).length,
      ).toBeGreaterThanOrEqual(3);
    }
    // The newest is the current one.
    const viaId = await certificatesIn(await download(asAdmin, org.orgId, mc.id, "?chain=leaf", newest.id), "pem");
    expect(viaId[0]!.fingerprint256).toBe(currentLeaf[0]!.fingerprint256);

    expect((await download(asAdmin, org.orgId, mc.id, "", other.certificates[0]!.id)).status).toBe(404);
    expect((await download(asAdmin, org.orgId, mc.id, "", crypto.randomUUID())).status).toBe(404);
    expect((await download(asAdmin, org.orgId, mc.id, "", "not-a-uuid")).status).toBe(404);
  });

  test("nothing to download before a Certificate is issued", async () => {
    const mc = (await h.api(base(), { cookie: org.cookie, body: await request() })).body; // no ACME account: Issuance fails
    await h.settleIssuances();
    expect((await download(asAdmin, org.orgId, mc.id)).status).toBe(404);
  });

  test("the root is added only when the platform knows it, and says so when it does not", async () => {
    await readyToIssue();
    const mc = await issued();
    h.caRoots.current = async () => [];
    const refused = await download(asAdmin, org.orgId, mc.id, "?chain=with-root");
    expect(refused.status).toBe(422);
    expect((await refused.json()).error).toContain("root");
    // Without the root nothing needs it.
    expect((await download(asAdmin, org.orgId, mc.id, "?chain=with-intermediates")).status).toBe(200);
  });

  test("a Member downloads only what they own, a user outside the Organization nothing", async () => {
    await readyToIssue();
    const owner = await join("owner@acme.test", "member");
    const stranger = await join("stranger@acme.test", "member");
    const mine = await issued(org, [{ type: "user", id: await userId(owner) }], 1);
    const notMine = await issued();

    expect((await download({ cookie: owner }, org.orgId, mine.id, "?format=der")).status).toBe(200);
    expect((await download({ cookie: owner }, org.orgId, mine.id, "?format=p7b&chain=with-root", mine.certificates[1]!.id)).status).toBe(200);
    expect((await download({ cookie: owner }, org.orgId, notMine.id)).status).toBe(403);
    expect((await download({ cookie: stranger }, org.orgId, mine.id)).status).toBe(403);
    expect((await download({ cookie: globex.cookie }, org.orgId, mine.id)).status).toBe(404);
    expect((await download({}, org.orgId, mine.id)).status).toBe(401);
  });
});

describe("API keys", () => {
  const createKey = (cookie: string, body: unknown = { name: "ci" }, orgId = org.orgId) => h.api(keysPath(orgId), { cookie, body });
  const listKeys = (cookie: string, orgId = org.orgId) => h.api(keysPath(orgId), { cookie });
  const revokeKey = (cookie: string, keyId: string, orgId = org.orgId) => h.api(`${keysPath(orgId)}/${keyId}`, { cookie, method: "DELETE" });

  test("a key is shown once when made, listed without its value, and revoked", async () => {
    const alice = await join("alice@acme.test", "member");
    const created = await createKey(alice, { name: "deploy pipeline" });
    expect(created.status).toBe(201);
    // Read before matching: matching with matchers writes them over the received values.
    const { id, key } = created.body as { id: string; key: string };
    expect(created.body).toMatchObject({ id: expect.any(String), name: "deploy pipeline", key: expect.stringMatching(/^cp_/), expiresAt: null, createdAt: expect.any(String) });

    const listed = await listKeys(alice);
    expect(listed.status).toBe(200);
    expect(listed.body.items).toEqual([expect.objectContaining({ id, name: "deploy pipeline", expiresAt: null })]);
    expect(JSON.stringify(listed.body)).not.toContain(key);
    expect(listed.body.items[0].key).toBeUndefined();

    expect((await revokeKey(alice, id)).status).toBe(200);
    expect((await listKeys(alice)).body.items).toEqual([]);
    expect((await revokeKey(alice, id)).status).toBe(404);
  });

  test("a key may be given an expiry, and needs a name", async () => {
    const withExpiry = await createKey(org.cookie, { name: "short", expiresInDays: 7 });
    expect(withExpiry.status).toBe(201);
    const expiresAt = new Date(withExpiry.body.expiresAt).getTime();
    expect(Math.abs(expiresAt - (Date.now() + 7 * 86_400_000))).toBeLessThan(60_000);
    expect((await createKey(org.cookie, {})).status).toBe(400);
    expect((await createKey(org.cookie, { name: "" })).status).toBe(400);
    expect((await createKey(org.cookie, { name: "x", expiresInDays: 0 })).status).toBe(400);
  });

  test("a key fetches the current Certificate in the format and chain asked for, without a session", async () => {
    await readyToIssue();
    const mc = await issued(org, [], 1);
    const key = (await createKey(org.cookie)).body.key as string;

    for (const format of FORMATS) {
      for (const chain of CHAINS) {
        const query = `?format=${format}&chain=${chain}`;
        const viaKey = await download({ apiKey: key }, org.orgId, mc.id, query);
        const viaSession = await download(asAdmin, org.orgId, mc.id, query);
        expect(viaKey.status).toBe(200);
        expect(new Uint8Array(await viaKey.arrayBuffer())).toEqual(new Uint8Array(await viaSession.arrayBuffer()));
      }
    }
    // An earlier Certificate too.
    expect((await download({ apiKey: key }, org.orgId, mc.id, "?format=der", mc.certificates[1]!.id)).status).toBe(200);
  });

  test("a key reaches only its own Organization, and carries only what its user may see", async () => {
    await readyToIssue();
    await readyToIssue(globex);
    const owner = await join("owner@acme.test", "member");
    const mine = await issued(org, [{ type: "user", id: await userId(owner) }]);
    const notMine = await issued();
    const elsewhere = await issued(globex);
    const key = (await createKey(owner)).body.key as string;

    expect((await download({ apiKey: key }, org.orgId, mine.id)).status).toBe(200);
    // Visibility is the user's: a Member's key sees what the Member owns.
    expect((await download({ apiKey: key }, org.orgId, notMine.id)).status).toBe(403);
    // The key was made for acme; globex is not somewhere it can go, nor is it known to exist.
    expect((await download({ apiKey: key }, globex.orgId, elsewhere.id)).status).toBe(404);
  });

  test("a key opens nothing but downloads, and a key cannot make or revoke keys", async () => {
    const key = (await createKey(org.cookie)).body.key as string;
    const asKey = { "x-api-key": key };
    const call = (path: string, init: RequestInit = {}) => h.app.request(`http://localhost${path}`, { ...init, headers: { ...asKey, "content-type": "application/json", origin: "http://localhost" } });
    expect((await call(base())).status).toBe(401);
    expect((await call("/api/me")).status).toBe(401);
    expect((await call(`/api/organizations/${org.orgId}/audit-events`)).status).toBe(401);
    expect((await call(keysPath(), { method: "POST", body: JSON.stringify({ name: "more" }) })).status).toBe(401);
    expect((await call(keysPath())).status).toBe(401);
    // The plugin's own endpoints are not served.
    expect((await call("/api/auth/api-key/create", { method: "POST", body: JSON.stringify({ name: "more" }) })).status).toBe(404);
    expect((await call("/api/auth/api-key/list")).status).toBe(404);
    expect((await call("/api/auth/api-key/verify", { method: "POST", body: JSON.stringify({ key }) })).status).toBe(404);
  });

  test("a revoked, unknown or missing key opens nothing", async () => {
    await readyToIssue();
    const mc = await issued();
    const made = (await createKey(org.cookie)).body;
    expect((await download({ apiKey: made.key }, org.orgId, mc.id)).status).toBe(200);
    await revokeKey(org.cookie, made.id);
    expect((await download({ apiKey: made.key }, org.orgId, mc.id)).status).toBe(401);
    expect((await download({ apiKey: "cp_unknown" }, org.orgId, mc.id)).status).toBe(401);
    expect((await download({}, org.orgId, mc.id)).status).toBe(401);
  });

  test("a key stops working when its user leaves the Organization", async () => {
    await readyToIssue();
    const mc = await issued();
    const alice = await join("alice@acme.test", "approver");
    const aliceId = await userId(alice);
    const key = (await createKey(alice)).body.key as string;
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(200);

    const members = (await h.api(`/api/auth/organization/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
    const removed = await h.api("/api/auth/organization/remove-member", {
      cookie: org.cookie,
      body: { memberIdOrEmail: members.find((m) => m.userId === aliceId)!.id, organizationId: org.orgId },
    });
    expect(removed.status).toBe(200);
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(404);
  });

  test("a key stops working when its user is banned", async () => {
    await readyToIssue();
    const mc = await issued();
    const alice = await join("alice@acme.test", "approver");
    const key = (await createKey(alice)).body.key as string;
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(200);
    await h.pool.query(`update "user" set banned = true where email = 'alice@acme.test'`);
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(401);
  });

  test("people see and revoke only their own keys, and only members can make them", async () => {
    const alice = await join("alice@acme.test", "member");
    const bob = await join("bob@acme.test", "member");
    const aliceKey = (await createKey(alice, { name: "alice's" })).body;
    await createKey(bob, { name: "bob's" });

    expect((await listKeys(alice)).body.items.map((k: any) => k.name)).toEqual(["alice's"]);
    expect((await listKeys(org.cookie)).body.items).toEqual([]); // not even an Organization Administrator's view
    expect((await revokeKey(bob, aliceKey.id)).status).toBe(404);
    expect((await revokeKey(org.cookie, aliceKey.id)).status).toBe(404);
    expect((await listKeys(alice)).body.items).toHaveLength(1);

    expect((await createKey(alice, { name: "x" }, globex.orgId)).status).toBe(404);
    expect((await listKeys(alice, globex.orgId)).status).toBe(404);
    expect((await h.api(keysPath())).status).toBe(401);
    // A key made in one Organization is not listed in another the same user belongs to.
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: globex.cookie, body: { email: "alice@acme.test", role: "member", organizationId: globex.orgId } });
    await h.api("/api/auth/organization/accept-invitation", { cookie: alice, body: { invitationId: invited.body.id } });
    expect((await listKeys(alice, globex.orgId)).body.items).toEqual([]);
    expect((await listKeys(alice)).body.items).toHaveLength(1);
  });

  test("creating, revoking and each use of a key are audited, and the key's value is nowhere in the log", async () => {
    await readyToIssue();
    const alice = await join("alice@acme.test", "approver");
    const aliceId = await userId(alice);
    const mc = await issued(org, [], 1);
    const made = (await createKey(alice, { name: "ci" })).body;
    const before = (await auditOf()).length;

    await download({ apiKey: made.key }, org.orgId, mc.id, "?format=der&chain=with-root");
    await download({ apiKey: made.key }, org.orgId, mc.id, "", mc.certificates[1]!.id);
    await revokeKey(alice, made.id);

    const events = await auditOf();
    const created = events.find((e) => e.action === "api_key.created")!;
    expect(created).toMatchObject({ actor: { id: aliceId, email: "alice@acme.test" }, target: { type: "api_key", id: made.id }, detail: { name: "ci" } });
    const used = events.slice(before).filter((e) => e.action === "api_key.used");
    expect(used).toHaveLength(2);
    expect(used[0]).toMatchObject({
      actor: { id: aliceId, email: "alice@acme.test" },
      target: { type: "managed_certificate", id: mc.id },
      detail: { apiKeyId: made.id, apiKeyName: "ci", format: "der", chain: "with-root", certificateId: mc.certificates[0]!.id },
    });
    expect(used[1]!.detail).toMatchObject({ apiKeyId: made.id, certificateId: mc.certificates[1]!.id });
    expect(events.at(-1)).toMatchObject({ action: "api_key.revoked", actor: { id: aliceId }, target: { type: "api_key", id: made.id }, detail: { name: "ci" } });
    expect(JSON.stringify(events)).not.toContain(made.key);
    // Downloading as a person, not with a key, is not a use of a key.
    const count = (await auditOf()).filter((e) => e.action === "api_key.used").length;
    await download(asAdmin, org.orgId, mc.id);
    expect((await auditOf()).filter((e) => e.action === "api_key.used")).toHaveLength(count);
  });

  test("a download that is refused leaves no use behind", async () => {
    await readyToIssue();
    const owner = await join("owner@acme.test", "member");
    const notMine = await issued();
    const key = (await createKey(owner)).body.key as string;
    expect((await download({ apiKey: key }, org.orgId, notMine.id)).status).toBe(403);
    expect((await auditOf()).filter((e) => e.action === "api_key.used")).toEqual([]);
  });

  test("a key reports what it carries: its user's permissions when it was made", async () => {
    const approver = await join("approver@acme.test", "approver");
    const made = (await createKey(approver)).body;
    expect(made.permissions).toEqual(expect.objectContaining({ managedCertificate: expect.arrayContaining(["download"]) }));
    expect(made.permissions.approval).toEqual(["read", "decide"]);
    const adminKey = (await createKey(org.cookie)).body;
    expect(adminKey.permissions.audit).toEqual(["read"]);
    expect((await listKeys(approver)).body.items[0].permissions).toEqual(made.permissions);
  });
});

describe("Organization API keys", () => {
  const createKey = (cookie: string, body: unknown = { name: "ci", type: "organization" }, orgId = org.orgId) => h.api(keysPath(orgId), { cookie, body });
  const listKeys = (cookie: string, orgId = org.orgId) => h.api(keysPath(orgId), { cookie });
  const revokeKey = (cookie: string, keyId: string, orgId = org.orgId) => h.api(`${keysPath(orgId)}/${keyId}`, { cookie, method: "DELETE" });
  /** A second Organization Administrator, so the first can leave. */
  const secondAdmin = () => join("second@acme.test", "organization-administrator");

  test("an Organization Administrator makes one; it belongs to the Organization and carries only downloads", async () => {
    const made = await createKey(org.cookie, { name: "pipeline", type: "organization" });
    expect(made.status).toBe(201);
    const { id, key } = made.body as { id: string; key: string };
    expect(key).toStartWith("cpo_");
    expect(made.body).toMatchObject({ type: "organization", name: "pipeline", permissions: { managedCertificate: ["download"] }, createdBy: { email: "admin@acme.test" } });
    expect(Object.keys(made.body.permissions)).toEqual(["managedCertificate"]);

    // Every Organization Administrator sees it, with the person's own keys; nobody else does.
    const mine = await createKey(org.cookie, { name: "mine" });
    const other = await secondAdmin();
    expect((await listKeys(other)).body.items.map((k: any) => [k.name, k.type])).toEqual([["pipeline", "organization"]]);
    expect((await listKeys(org.cookie)).body.items.map((k: any) => [k.name, k.type])).toEqual([["pipeline", "organization"], ["mine", "user"]]);
    expect(JSON.stringify((await listKeys(other)).body)).not.toContain(key);
    expect(mine.body.type).toBe("user");
    const member = await join("member@acme.test", "member");
    expect((await listKeys(member)).body.items).toEqual([]);
    expect((await listKeys(await join("approver@acme.test", "approver"))).body.items).toEqual([]);
    expect(id).toBeString();
  });

  test("only Organization Administrators make them, and only for their own Organization", async () => {
    for (const role of ["member", "approver"]) {
      const who = await join(`${role}@acme.test`, role);
      expect((await createKey(who)).status).toBe(403);
      // A user's key is still theirs to make.
      expect((await createKey(who, { name: "own", type: "user" })).status).toBe(201);
    }
    expect((await createKey(org.cookie, { name: "x", type: "organization" }, globex.orgId)).status).toBe(404);
    expect((await createKey(org.cookie, { name: "x", type: "robot" })).status).toBe(400);
    // Left out, a key is a user's.
    expect((await createKey(org.cookie, { name: "plain" })).body.type).toBe("user");
  });

  test("it downloads any Managed Certificate of the Organization, in any form, and nothing of another", async () => {
    await readyToIssue();
    await readyToIssue(globex);
    const member = await join("member@acme.test", "member");
    const owned = await issued(org, [{ type: "user", id: await userId(member) }]);
    const unowned = await issued(org, [], 1);
    const elsewhere = await issued(globex);
    const key = (await createKey(org.cookie)).body.key as string;

    for (const mc of [owned, unowned]) {
      for (const format of FORMATS) {
        for (const chain of CHAINS) {
          const query = `?format=${format}&chain=${chain}`;
          const viaKey = await download({ apiKey: key }, org.orgId, mc.id, query);
          const viaAdmin = await download(asAdmin, org.orgId, mc.id, query);
          expect(viaKey.status).toBe(200);
          expect(new Uint8Array(await viaKey.arrayBuffer())).toEqual(new Uint8Array(await viaAdmin.arrayBuffer()));
        }
      }
    }
    expect((await download({ apiKey: key }, org.orgId, unowned.id, "?format=der", unowned.certificates[1]!.id)).status).toBe(200);
    expect((await download({ apiKey: key }, org.orgId, unowned.id, "", owned.certificates[0]!.id)).status).toBe(404);
    expect((await download({ apiKey: key }, org.orgId, crypto.randomUUID())).status).toBe(404);
    expect((await download({ apiKey: key }, globex.orgId, elsewhere.id)).status).toBe(404);
  });

  test("it opens nothing but downloads", async () => {
    const key = (await createKey(org.cookie)).body.key as string;
    const call = (path: string, init: RequestInit = {}) => h.app.request(`http://localhost${path}`, { ...init, headers: { "x-api-key": key, "content-type": "application/json", origin: "http://localhost" } });
    expect((await call(base())).status).toBe(401);
    expect((await call("/api/me")).status).toBe(401);
    expect((await call(keysPath())).status).toBe(401);
    expect((await call(keysPath(), { method: "POST", body: JSON.stringify({ name: "more", type: "organization" }) })).status).toBe(401);
  });

  test("it outlives the person who made it", async () => {
    await readyToIssue();
    const mc = await issued();
    const maker = await secondAdmin();
    const makerId = await userId(maker);
    const key = (await createKey(maker)).body.key as string;
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(200);

    // Banned, then removed from the Organization: the key is the Organization's, not theirs.
    await h.pool.query(`update "user" set banned = true where id = $1`, [makerId]);
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(200);
    const members = (await h.api(`/api/auth/organization/list-members?organizationId=${org.orgId}`, { cookie: org.cookie })).body.members as { id: string; userId: string }[];
    const removed = await h.api("/api/auth/organization/remove-member", { cookie: org.cookie, body: { memberIdOrEmail: members.find((m) => m.userId === makerId)!.id, organizationId: org.orgId } });
    expect(removed.status).toBe(200);
    expect((await download({ apiKey: key }, org.orgId, mc.id)).status).toBe(200);
    // Still listed, and still says who made it.
    expect((await listKeys(org.cookie)).body.items[0]).toMatchObject({ type: "organization", createdBy: { email: "second@acme.test" } });
  });

  test("any Organization Administrator revokes it, and no one else", async () => {
    await readyToIssue();
    const mc = await issued();
    const other = await secondAdmin();
    const made = (await createKey(org.cookie)).body;
    const member = await join("member@acme.test", "member");
    const approver = await join("approver@acme.test", "approver");

    expect((await revokeKey(member, made.id)).status).toBe(404);
    expect((await revokeKey(approver, made.id)).status).toBe(404);
    expect((await download({ apiKey: made.key }, org.orgId, mc.id)).status).toBe(200);
    expect((await revokeKey(other, made.id)).status).toBe(200);
    expect((await download({ apiKey: made.key }, org.orgId, mc.id)).status).toBe(401);
    expect((await listKeys(org.cookie)).body.items).toEqual([]);
    expect((await revokeKey(org.cookie, made.id)).status).toBe(404);
    // A user's key of someone else is still not an administrator's to revoke.
    const alices = (await createKey(member, { name: "alice's", type: "user" })).body;
    expect((await revokeKey(org.cookie, alices.id)).status).toBe(404);
  });

  test("making, using and revoking it are audited: by the person, and by the key, who is no one", async () => {
    await readyToIssue();
    const mc = await issued();
    const other = await secondAdmin();
    const otherId = await userId(other);
    const adminId = await userId(org.cookie);
    const made = (await createKey(org.cookie, { name: "ci", type: "organization" })).body;
    const before = (await auditOf()).length;
    await download({ apiKey: made.key }, org.orgId, mc.id, "?format=p7b&chain=leaf");
    await revokeKey(other, made.id);

    const events = await auditOf();
    expect(events.find((e) => e.action === "api_key.created")).toMatchObject({
      actor: { id: adminId, email: "admin@acme.test" },
      target: { type: "api_key", id: made.id },
      detail: { name: "ci", type: "organization", permissions: { managedCertificate: ["download"] } },
    });
    const used = events.slice(before).filter((e) => e.action === "api_key.used");
    expect(used).toHaveLength(1);
    expect(used[0]).toMatchObject({
      actor: { id: null, email: null },
      target: { type: "managed_certificate", id: mc.id },
      detail: { apiKeyId: made.id, apiKeyName: "ci", apiKeyType: "organization", createdBy: { id: adminId, email: "admin@acme.test" }, format: "p7b", chain: "leaf" },
    });
    expect(events.at(-1)).toMatchObject({ action: "api_key.revoked", actor: { id: otherId }, target: { type: "api_key", id: made.id }, detail: { name: "ci", type: "organization" } });
    expect(JSON.stringify(events)).not.toContain(made.key);
  });

  test("a key's name may be as long as the plugin allows, 32 characters", async () => {
    const name = "n".repeat(32);
    for (const type of ["user", "organization"]) expect((await createKey(org.cookie, { name, type })).status).toBe(201);
    for (const type of ["user", "organization"]) expect((await createKey(org.cookie, { name: "n".repeat(33), type })).status).toBe(400);
  });
});
