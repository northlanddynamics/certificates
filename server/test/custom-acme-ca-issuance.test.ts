// Issuing from a custom ACME CA: a Managed Certificate on one is issued, renewed and revoked through the Organization's
// account with it, as one on Let's Encrypt is. The custom CA is Pebble, at its own directory or at one the harness serves
// without some of its endpoints, for a CA that offers no revocation or no ARI. Certificates are issued by Pebble for real.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import acme from "acme-client";
import { randomBytes } from "node:crypto";
import { certificateId } from "../src/issuance/acme/certificate-authority";
import { BIND, PASSWORD, PEBBLE_DIRECTORY, createHarness, type Harness } from "./support/harness";

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

const DAY = 86_400_000;
const HOUR = 3_600_000;
const base = (orgId = org.orgId) => `/api/organizations/${orgId}/managed-certificates`;
const auditOf = async () => (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; target: any; detail: any }[];

const host = () => `t${randomBytes(5).toString("hex")}.${BIND.zone}`;
async function request(names = [host()]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256" as const, csr: csr.toString() };
}

/** Adds a custom ACME CA at `directoryUrl` (Pebble's unless given), which registers the Organization's account with it, and returns its id and its account's. */
async function customCa(directoryUrl = PEBBLE_DIRECTORY, target = org, name = "Internal CA") {
  const created = await h.api(`/api/organizations/${target.orgId}/acme-cas`, { cookie: target.cookie, body: { name, directoryUrl, tag: "production", termsOfServiceAgreed: true } });
  expect(created.status).toBe(201);
  return { acmeCaId: created.body.acmeCa.id as string, accountId: created.body.account.id as string };
}

/** The DNS Provider that answers the CA's DNS-01 challenges, as for Let's Encrypt; no account with any built-in ACME CA. */
async function dnsProvider(target = org) {
  const created = await h.api(`/api/organizations/${target.orgId}/dns-providers`, {
    cookie: target.cookie,
    body: { name: "BIND", type: "rfc2136", settings: { server: BIND.server, port: BIND.port, zone: BIND.zone, keyName: BIND.keyName }, secret: BIND.keySecret },
  });
  expect(created.status).toBe(201);
}

const create = (acmeCaId: string, target = org) => request().then((body) => h.api(base(target.orgId), { cookie: target.cookie, body: { ...body, issuer: { kind: "acme", acmeCaId }, owners: [] } }));
const get = async (id: string) => {
  const res = await h.api(`${base()}/${id}`, { cookie: org.cookie });
  expect(res.status).toBe(200);
  return res.body;
};
const certificates = async (id: string) =>
  (await h.api(`${base()}/${id}/certificates`, { cookie: org.cookie })).body.items as { id: string; fingerprint: string; ca: string; acmeCaId: string; acmeAccountId: string; revocation: any; notBefore: string; notAfter: string }[];
const downloaded = async (id: string) => (await h.app.request(`http://localhost${base()}/${id}/certificate`, { headers: { cookie: org.cookie } })).text();
const revoke = (id: string, certificateId: string) => h.api(`${base()}/${id}/certificates/${certificateId}/revocation`, { cookie: org.cookie, method: "POST", body: { reason: "keyCompromise" } });
const setPolicy = (id: string, daysBeforeExpiry: number) => h.api(`${base()}/${id}/renewal-policy`, { cookie: org.cookie, method: "PUT", body: { mode: "automatic", daysBeforeExpiry } });

/** A Managed Certificate on the custom ACME CA whose first Certificate is issued. */
async function issuedFrom(acmeCaId: string) {
  const created = await create(acmeCaId);
  expect(created.status).toBe(201);
  await h.settleIssuances();
  expect((await get(created.body.id)).issuance).toMatchObject({ status: "succeeded", failure: null });
  return created.body.id as string;
}

/** One pass of the Renewal scheduler, and the Renewals it started run to their end. */
async function schedule() {
  const started = await h.runRenewalScheduler();
  await h.settleIssuances();
  return started;
}

describe("issuing from a custom ACME CA", () => {
  test("a Managed Certificate on it is issued through DNS-01 and the Organization's account with it, and its Certificate records the CA", async () => {
    const { acmeCaId, accountId } = await customCa();
    await dnsProvider();
    const created = await create(acmeCaId);
    expect(created.status).toBe(201);
    expect(created.body.issuer).toEqual({ kind: "acme", acmeCaId });
    await h.settleIssuances();

    const mc = await get(created.body.id);
    expect(mc.issuance).toMatchObject({ status: "succeeded", failure: null });
    // There is no account with any built-in ACME CA: the custom one's is what it was issued through.
    expect(mc.currentCertificate).toMatchObject({ acmeCaId, acmeAccountId: accountId, ca: "Internal CA", issuingCaId: null });
    expect((await auditOf()).find((e) => e.action === "managed_certificate.created")?.detail).toMatchObject({ acmeCaId });
  });

  test("not from another Organization's custom ACME CA", async () => {
    const { acmeCaId } = await customCa(PEBBLE_DIRECTORY, globex);
    await dnsProvider();
    expect((await create(acmeCaId)).status).toBe(422);
    expect((await h.api(base(), { cookie: org.cookie })).body.items).toEqual([]);
  });
});

describe("renewing from a custom ACME CA", () => {
  test("a Renewal asked for is issued from it again, through the same account", async () => {
    const { acmeCaId, accountId } = await customCa();
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);
    expect((await h.api(`${base()}/${id}/renewals`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(202);
    await h.settleIssuances();
    expect((await get(id)).issuance).toMatchObject({ status: "succeeded", failure: null });
    const issued = await certificates(id);
    expect(issued).toHaveLength(2);
    expect(issued.map((c) => [c.acmeCaId, c.acmeAccountId])).toEqual([
      [acmeCaId, accountId],
      [acmeCaId, accountId],
    ]);
  });

  test("the scheduler renews it at the days before expiry", async () => {
    const { acmeCaId } = await customCa();
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);
    expect((await setPolicy(id, 2)).status).toBe(200);
    const notAfter = Date.parse((await get(id)).currentCertificate.notAfter);
    h.setNow(new Date(notAfter - 3 * DAY));
    expect(await schedule()).toBe(0);
    h.setNow(new Date(notAfter - 2 * DAY));
    expect(await schedule()).toBe(1);
    expect(await certificates(id)).toHaveLength(2);
    expect((await get(id)).currentCertificate.acmeCaId).toBe(acmeCaId);
  });

  describe("with ARI", () => {
    beforeEach(() => {
      h.ari.enabled = true;
    });

    /** A Managed Certificate on `acmeCaId` due a day before expiry, a day into its first Certificate's life, after a pass of the scheduler. */
    async function started(acmeCaId: string) {
      await dnsProvider();
      const id = await issuedFrom(acmeCaId);
      expect((await setPolicy(id, 1)).status).toBe(200);
      const first = (await get(id)).currentCertificate;
      h.setNow(new Date(Date.parse(first.notBefore) + DAY));
      expect(await schedule()).toBe(0);
      return { id, first };
    }

    test("the schedule follows the window the CA's ARI suggests, and the Renewal names the Certificate it replaces", async () => {
      const { acmeCaId } = await customCa();
      const { id, first } = await started(acmeCaId);
      const pem = await downloaded(id);
      expect(h.ari.asked.map(certificateId)).toEqual([certificateId(pem)]);
      const mc = await get(id);
      expect(mc.renewal.dueBecause).toBe("ari");
      const window = { start: Date.parse(mc.renewal.ari.window.start), end: Date.parse(mc.renewal.ari.window.end) };
      // Pebble's window comes before the day before expiry, so it is the window that makes it due.
      expect(window.end).toBeLessThanOrEqual(Date.parse(first.notAfter) - DAY);

      h.setNow(new Date(window.end));
      expect(await schedule()).toBe(1);
      expect((await get(id)).issuance.status).toBe("succeeded");
      expect(h.ari.replaces.map((r) => r && certificateId(r))).toEqual([undefined, certificateId(pem)]);
    });

    test("a window the CA moves earlier moves the Renewal earlier", async () => {
      const { acmeCaId } = await customCa();
      const { id } = await started(acmeCaId);
      const t0 = new Date(Date.parse((await get(id)).currentCertificate.notBefore) + DAY);
      await h.setPebbleWindow(await downloaded(id), { start: new Date(t0.getTime() - 2 * HOUR), end: new Date(t0.getTime() - HOUR) });
      h.setNow(new Date(t0.getTime() + 6 * HOUR));
      expect(await schedule()).toBe(1);
      expect(await certificates(id)).toHaveLength(2);
      expect((await get(id)).currentCertificate.acmeCaId).toBe(acmeCaId);
    });

    test("a CA whose directory advertises no ARI renews by the days before expiry alone", async () => {
      const { acmeCaId } = await customCa(h.pebbleDirectoryWithout("renewalInfo"));
      const { id, first } = await started(acmeCaId);
      const mc = await get(id);
      expect(mc.renewal.ari).toMatchObject({ window: null });
      expect(mc.renewal.dueBecause).toBe("policy");
      // Where Pebble's window would be: no Renewal there.
      h.setNow(new Date(Date.parse(first.notBefore) + 0.7 * (Date.parse(first.notAfter) - Date.parse(first.notBefore))));
      expect(await schedule()).toBe(0);
      h.setNow(new Date(Date.parse(first.notAfter) - DAY));
      expect(await schedule()).toBe(1);
      expect(await certificates(id)).toHaveLength(2);
      expect((await get(id)).issuance).toMatchObject({ status: "succeeded", failure: null });
    });
  });
});

describe("revoking from a custom ACME CA", () => {
  test("a Certificate it issued is revoked at the CA, through the account it was issued through, and recorded", async () => {
    const { acmeCaId } = await customCa();
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);
    const [issued] = await certificates(id);
    const res = await revoke(id, issued!.id);
    expect(res.status).toBe(200);
    expect(res.body.revocation).toMatchObject({ reason: "keyCompromise" });
    expect(h.revocations).toHaveLength(1);
    expect((await certificates(id))[0]!.revocation).toMatchObject({ reason: "keyCompromise" });
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toHaveLength(1);
    // Revoked once is revoked.
    expect((await revoke(id, issued!.id)).status).toBe(409);
  });

  test("a CA whose directory advertises no revocation endpoint: revoking fails with a clear error and nothing is recorded as revoked", async () => {
    const { acmeCaId } = await customCa(h.pebbleDirectoryWithout("revokeCert"));
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);
    const [issued] = await certificates(id);
    const res = await revoke(id, issued!.id);
    expect(res.status).toBe(422);
    expect(JSON.stringify(res.body)).toContain("Internal CA offers no revocation");
    expect(h.revocations).toEqual([]);
    expect((await certificates(id))[0]!.revocation).toBeNull();
    expect((await get(id)).currentCertificate.revocation).toBeNull();
    expect((await auditOf()).filter((e) => e.action === "certificate.revoked")).toEqual([]);
  });
});

describe("deleting a custom ACME CA", () => {
  const remove = (acmeCaId: string) => h.api(`/api/organizations/${org.orgId}/acme-cas/${acmeCaId}`, { cookie: org.cookie, method: "DELETE" });
  const listed = async () => ((await h.api(`/api/organizations/${org.orgId}/acme-cas`, { cookie: org.cookie })).body.items as { id: string }[]).map((ca) => ca.id);

  test("is refused, with the reason, while a Managed Certificate refers to it, archived or not, and its history and revocation keep working", async () => {
    const { acmeCaId, accountId } = await customCa();
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);

    const refused = await remove(acmeCaId);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("Internal CA is the issuer of 1 Managed Certificate and 1 Certificate (archived ones included), so it cannot be deleted");

    // Its account is still there to revoke through.
    const [issued] = await certificates(id);
    expect(issued).toMatchObject({ acmeCaId, acmeAccountId: accountId });
    expect((await revoke(id, issued!.id)).status).toBe(200);

    expect((await h.api(`${base()}/${id}/archive`, { cookie: org.cookie, method: "POST", body: {} })).status).toBe(200);
    expect((await remove(acmeCaId)).status).toBe(409);
    expect(await listed()).toContain(acmeCaId);
    expect((await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie })).body.items.map((a: any) => a.id)).toEqual([accountId]);
    expect((await auditOf()).map((e) => e.action)).not.toContain("acme_ca.deleted");
  });

  test("is refused while a Certificate refers to it, though no Managed Certificate does", async () => {
    const { acmeCaId } = await customCa();
    await dnsProvider();
    const id = await issuedFrom(acmeCaId);
    // No route moves a Managed Certificate off an ACME CA; as if one had, its Certificate still came from this one.
    await h.pool.query(`update managed_certificate set acme_ca_id = 'letsencrypt-staging' where id = $1`, [id]);
    const refused = await remove(acmeCaId);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("Internal CA is the issuer of 1 Certificate (archived ones included), so it cannot be deleted");
    expect(await listed()).toContain(acmeCaId);
  });

  test("a Managed Certificate whose first Issuance has not succeeded refers to it all the same", async () => {
    const { acmeCaId } = await customCa();
    // No DNS Provider, so its Issuance fails: it still refers to the CA.
    expect((await create(acmeCaId)).status).toBe(201);
    await h.settleIssuances();
    const refused = await remove(acmeCaId);
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("Internal CA is the issuer of 1 Managed Certificate (archived ones included), so it cannot be deleted");
  });

  test("another custom ACME CA's Managed Certificates do not stop it", async () => {
    const used = await customCa(PEBBLE_DIRECTORY, org, "Used CA");
    const unused = await customCa(PEBBLE_DIRECTORY, org, "Unused CA");
    await dnsProvider();
    await issuedFrom(used.acmeCaId);
    expect((await remove(unused.acmeCaId)).status).toBe(200);
    expect(await listed()).toEqual(["letsencrypt-staging", "letsencrypt-production", used.acmeCaId]);
  });
});

describe("changing a custom ACME CA", () => {
  test("a renamed and retagged one goes on issuing through the same account", async () => {
    const { acmeCaId, accountId } = await customCa();
    await dnsProvider();
    const changed = await h.api(`/api/organizations/${org.orgId}/acme-cas/${acmeCaId}`, { cookie: org.cookie, method: "PATCH", body: { name: "Renamed CA", tag: "staging" } });
    expect(changed.status).toBe(200);
    const id = await issuedFrom(acmeCaId);
    expect((await get(id)).currentCertificate).toMatchObject({ acmeCaId, acmeAccountId: accountId, ca: "Renamed CA" });
  });
});
