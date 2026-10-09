// An Organization Administrator creates a Managed Certificate (Key Custody: Owner) with names, a key algorithm and a
// CSR, and the platform issues its first Certificate: a real ACME order against Pebble, Direct DCV through an RFC 2136
// DNS Provider that updates a real BIND, which Pebble reads back. The private key stays with the test, as with an Owner.
import { afterAll, beforeAll, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { Pkcs10CertificateRequest } from "@peculiar/x509";
import acme from "acme-client";
import { X509Certificate, createHash, randomBytes } from "node:crypto";
import { BIND, PASSWORD, createHarness, type Harness } from "./harness";

setDefaultTimeout(60_000);

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

const base = (orgId: string) => `/api/organizations/${orgId}/managed-certificates`;
const certs = (cookie: string, orgId: string) => ({
  list: () => h.api(base(orgId), { cookie }),
  create: (body: unknown) => h.api(base(orgId), { cookie, body }),
  get: (id: string) => h.api(`${base(orgId)}/${id}`, { cookie }),
  retry: (id: string) => h.api(`${base(orgId)}/${id}/issuances`, { cookie, method: "POST", body: {} }),
  certificates: (id: string) => h.api(`${base(orgId)}/${id}/certificates`, { cookie }),
  download: (id: string) => h.app.request(`http://localhost${base(orgId)}/${id}/certificate.pem`, { headers: { cookie } }),
});
const admin = () => certs(acmeOrg.cookie, acmeOrg.orgId);
const auditOf = async (cookie = acmeOrg.cookie, orgId = acmeOrg.orgId) =>
  (await h.api(`/api/organizations/${orgId}/audit-events`, { cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

/** A host name of its own inside the zone BIND serves for RFC 2136 updates, so tests never share challenge records. */
const host = (zone = BIND.zone) => `t${randomBytes(5).toString("hex")}.${zone}`;

const KEYS = {
  "ecdsa-p256": () => acme.crypto.createPrivateEcdsaKey("P-256"),
  "ecdsa-p384": () => acme.crypto.createPrivateEcdsaKey("P-384"),
  "rsa-2048": () => acme.crypto.createPrivateRsaKey(2048),
  "rsa-3072": () => acme.crypto.createPrivateRsaKey(3072),
  "rsa-4096": () => acme.crypto.createPrivateRsaKey(4096),
} as const;

/** What an Owner submits: a CSR for names under a fresh key of the algorithm; the key itself stays here. */
async function request(names: string[], keyAlgorithm: keyof typeof KEYS = "ecdsa-p256", over: { csrNames?: string[]; environment?: string } = {}) {
  const key = await KEYS[keyAlgorithm]();
  const csrNames = over.csrNames ?? names;
  const [, csr] = await acme.crypto.createCsr({ commonName: csrNames[0], altNames: csrNames }, key);
  return { names, keyAlgorithm, csr: csr.toString(), ...(over.environment && { environment: over.environment }) };
}

/** The Organization's ACME account in staging and a DNS Provider for the BIND zone, which issuing needs. */
async function readyToIssue(org = acmeOrg) {
  const account = await h.api(`/api/organizations/${org.orgId}/acme-accounts`, { cookie: org.cookie, body: { termsOfServiceAgreed: true } });
  expect(account.status).toBe(201);
  await addBind(org);
  return account.body as { id: string };
}
const addBind = async (org = acmeOrg, over: { name?: string; zone?: string; port?: number } = {}) => {
  const created = await h.api(`/api/organizations/${org.orgId}/dns-providers`, {
    cookie: org.cookie,
    body: {
      name: over.name ?? "BIND",
      type: "rfc2136",
      settings: { server: BIND.server, port: over.port ?? BIND.port, zone: over.zone ?? BIND.zone, keyName: BIND.keyName },
      secret: BIND.keySecret,
    },
  });
  expect(created.status).toBe(201);
};

/** The Managed Certificate once its latest Issuance has ended. */
async function ended(id: string, who = admin()) {
  await h.settleIssuances();
  const res = await who.get(id);
  expect(res.status).toBe(200);
  expect(res.body.issuance.status).not.toBe("running");
  return res.body;
}

const sha256 = (cert: X509Certificate) => createHash("sha256").update(cert.raw).digest("hex");
const pemBlocks = (pem: string) => pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];

describe("issuing the first Certificate", () => {
  test("an Organization Administrator creates a Managed Certificate, and its Certificate is issued, stored and downloadable", async () => {
    const account = await readyToIssue();
    const name = host();
    const body = await request([name]);

    const created = await admin().create(body);
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      names: [name],
      keyAlgorithm: "ecdsa-p256",
      keyCustody: "owner",
      environment: "staging",
      issuance: { status: "running", failure: null, certificateId: null },
      currentCertificate: null,
    });

    const issued = await ended(created.body.id);
    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null, certificateId: issued.currentCertificate.id });

    const download = await admin().download(created.body.id);
    expect(download.status).toBe(200);
    expect(download.headers.get("content-type")).toContain("application/x-pem-file");
    const pem = await download.text();
    // The full chain: the Certificate first, then what the CA served after it.
    const blocks = pemBlocks(pem);
    expect(blocks.length).toBeGreaterThanOrEqual(2);
    const leaf = new X509Certificate(blocks[0]!);
    expect(pem).not.toContain("PRIVATE KEY");

    // What is stored is what the CA issued.
    expect(issued.currentCertificate).toEqual({
      id: expect.any(String),
      fingerprint: sha256(leaf),
      serial: leaf.serialNumber,
      notBefore: new Date(leaf.validFrom).toISOString(),
      notAfter: new Date(leaf.validTo).toISOString(),
      names: [name],
      ca: "lets-encrypt",
      environment: "staging",
      acmeAccountId: account.id,
      issuedAt: expect.any(String),
    });
    expect(leaf.subjectAltName).toBe(`DNS:${name}`);
    // It is for the key the Owner holds: the one in the CSR.
    expect(leaf.publicKey.export({ type: "spki", format: "der" })).toEqual(Buffer.from(new Pkcs10CertificateRequest(body.csr).publicKey.rawData));

    expect((await admin().certificates(created.body.id)).body.items).toEqual([issued.currentCertificate]);
    expect((await admin().list()).body.items.map((m: any) => m.id)).toEqual([created.body.id]);

    // The challenge record is gone from DNS again.
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
  });
});

describe("key algorithms and names", () => {
  for (const algorithm of Object.keys(KEYS) as (keyof typeof KEYS)[]) {
    test(`a Managed Certificate with ${algorithm} keys is issued`, async () => {
      await readyToIssue();
      const name = host();
      const created = await admin().create(await request([name], algorithm));
      expect(created.status).toBe(201);
      expect(created.body.keyAlgorithm).toBe(algorithm);
      const issued = await ended(created.body.id);
      expect(issued.issuance.status).toBe("succeeded");
      const leaf = new X509Certificate(pemBlocks(await (await admin().download(created.body.id)).text())[0]!);
      expect(leaf.publicKey.asymmetricKeyType).toBe(algorithm.startsWith("rsa") ? "rsa" : "ec");
    });
  }

  test("a wildcard and its base name are issued together, and both challenge records are removed", async () => {
    await readyToIssue();
    const name = host();
    // Both are challenged at the same record name, with two different values.
    const created = await admin().create(await request([`*.${name}`, name]));
    expect(created.status).toBe(201);
    const issued = await ended(created.body.id);
    expect(issued.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(issued.names).toEqual([`*.${name}`, name]);
    expect(issued.currentCertificate.names.sort()).toEqual([`*.${name}`, name].sort());
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
  });

  test("names are kept in lower case, without a trailing dot or repeats, and a CSR for them matches whatever the case", async () => {
    await readyToIssue();
    const name = host();
    const body = await request([name]);
    const created = await admin().create({ ...body, names: [`${name.toUpperCase()}.`, name] });
    expect(created.status).toBe(201);
    expect(created.body.names).toEqual([name]);
    expect((await ended(created.body.id)).issuance.status).toBe("succeeded");
  });

  test("production is a choice of the request; with no production account there is nothing to issue through", async () => {
    await readyToIssue();
    const created = await admin().create(await request([host()], "ecdsa-p256", { environment: "production" }));
    expect(created.status).toBe(201);
    expect(created.body.environment).toBe("production");
    expect((await ended(created.body.id)).issuance.failure).toMatchObject({ code: "no_acme_account", message: expect.stringContaining("production") });
  });
});

describe("a CSR must match the Managed Certificate", () => {
  /** Whether anything came of it: nothing is created, and nothing is issued or audited. */
  const nothingCreated = async () => {
    expect((await admin().list()).body.items).toEqual([]);
    expect((await auditOf()).filter((e) => e.action.startsWith("managed_certificate.") || e.action.startsWith("issuance."))).toEqual([]);
  };

  test("is rejected when its key algorithm differs from the one given", async () => {
    const [p256, p384, rsa] = [await request([host()], "ecdsa-p256"), await request([host()], "ecdsa-p384"), await request([host()], "rsa-2048")];
    const mismatches = [
      await admin().create({ ...p256, keyAlgorithm: "ecdsa-p384" }),
      await admin().create({ ...p384, keyAlgorithm: "ecdsa-p256" }),
      await admin().create({ ...rsa, keyAlgorithm: "ecdsa-p256" }),
      await admin().create({ ...p256, keyAlgorithm: "rsa-2048" }),
    ];
    for (const res of mismatches) {
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("key algorithm");
    }
    expect(mismatches[0]!.body.error).toContain("ecdsa-p256");
    await nothingCreated();
  });

  test("is rejected when its names are not exactly the names being issued", async () => {
    const [a, b] = [host(), host()];
    const refused = [
      await admin().create(await request([a, b], "ecdsa-p256", { csrNames: [a] })), // a name missing
      await admin().create(await request([a], "ecdsa-p256", { csrNames: [a, b] })), // a name too many
      await admin().create(await request([a], "ecdsa-p256", { csrNames: [b] })), // a different name
      await admin().create(await request([`*.${a}`], "ecdsa-p256", { csrNames: [a] })), // a wildcard is not its base name
    ];
    for (const res of refused) {
      expect(res.status).toBe(422);
      expect(res.body.error).toContain("exactly the names");
    }
    await nothingCreated();
  });

  test("is rejected when it is not a CSR, is for an unsupported key, or is not signed by its own key", async () => {
    const good = await request([host()]);
    const der = Buffer.from(good.csr.replace(/-----[^-]+-----|\s/g, ""), "base64");
    der.writeUInt8(der.readUInt8(der.length - 1) ^ 0xff, der.length - 1); // the last byte of the signature
    const forged = `-----BEGIN CERTIFICATE REQUEST-----\n${der.toString("base64")}\n-----END CERTIFICATE REQUEST-----\n`;
    const p521 = await (async () => {
      const [, csr] = await acme.crypto.createCsr({ commonName: host() }, await acme.crypto.createPrivateEcdsaKey("P-521"));
      return csr.toString();
    })();

    const notACsr = await admin().create({ ...good, csr: "hello" });
    const wrongPem = await admin().create({ ...good, csr: (await acme.crypto.createPrivateEcdsaKey("P-256")).toString() });
    const badSignature = await admin().create({ ...good, csr: forged });
    const unsupportedKey = await admin().create({ ...good, csr: p521 });
    for (const res of [notACsr, wrongPem, badSignature, unsupportedKey]) expect(res.status).toBe(400);
    expect(badSignature.body.error).toContain("signature");
    expect(unsupportedKey.body.error).toContain("P-256 and P-384");
    await nothingCreated();
  });

  test("is rejected when a name cannot be one to issue for", async () => {
    for (const name of ["10.0.0.1", "bad_name.example.com", "*.*.example.com", "example", "-a.example.com", "a b.example.com", "foo.*.example.com"]) {
      const res = await admin().create(await request([name]));
      expect(res.status).toBe(400);
      expect(res.body.error).toContain(name);
    }
    expect((await admin().create({ ...(await request([host()])), names: [] })).status).toBe(400);
    await nothingCreated();
  });
});

describe("who may create and see Managed Certificates", () => {
  async function join(email: string, role: string, org = acmeOrg) {
    const invited = await h.api("/api/auth/organization/invite-member", { cookie: org.cookie, body: { email, role, organizationId: org.orgId } });
    const cookie = await h.signUp(email, PASSWORD);
    await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
    return h.signIn(email, PASSWORD);
  }

  test("only an Organization Administrator creates one, and others see none", async () => {
    await readyToIssue();
    const created = await admin().create(await request([host()]));
    await ended(created.body.id);
    for (const role of ["member", "approver"]) {
      const cookie = await join(`${role}@acme.test`, role);
      const who = certs(cookie, acmeOrg.orgId);
      expect((await who.create(await request([host()]))).status).toBe(403);
      expect(await who.list().then((r) => [r.status, r.body.items])).toEqual([200, []]);
      expect((await who.get(created.body.id)).status).toBe(403);
      expect((await who.certificates(created.body.id)).status).toBe(403);
      expect((await who.download(created.body.id)).status).toBe(403);
      expect((await who.retry(created.body.id)).status).toBe(403);
    }
    expect((await admin().list()).body.items).toHaveLength(1);
  });

  test("an Organization never sees another's Managed Certificates, and a stranger sees nothing of the Organization", async () => {
    await readyToIssue();
    const created = await admin().create(await request([host()]));
    await ended(created.body.id);
    const other = certs(globex.cookie, globex.orgId);

    expect((await other.list()).body.items).toEqual([]);
    for (const res of [await other.get(created.body.id), await other.certificates(created.body.id), await other.retry(created.body.id)]) {
      expect(res.status).toBe(404);
    }
    expect((await other.download(created.body.id)).status).toBe(404);
    // Through the other Organization's own path or through ours, nobody reaches it.
    const viaOurs = certs(globex.cookie, acmeOrg.orgId);
    expect((await viaOurs.list()).status).toBe(404);
    expect((await viaOurs.create(await request([host()]))).status).toBe(404);
    expect((await viaOurs.download(created.body.id)).status).toBe(404);
    expect((await certs(operator, acmeOrg.orgId).list()).status).toBe(404);
  });
});

describe("failures say what went wrong", () => {
  /** Creates a Managed Certificate for `names` and returns it when its Issuance has ended. */
  const issueAndEnd = async (names: string[]) => {
    const created = await admin().create(await request(names));
    expect(created.status).toBe(201);
    return ended(created.body.id);
  };

  test("with no ACME account in the environment", async () => {
    await addBind();
    const failed = await issueAndEnd([host()]);
    expect(failed.issuance).toMatchObject({ status: "failed", certificateId: null, failure: { code: "no_acme_account", message: expect.stringContaining("staging") } });
    expect(failed.currentCertificate).toBeNull();
  });

  test("when no DNS Provider covers a name", async () => {
    await readyToIssue();
    const failed = await issueAndEnd([host(), "www.elsewhere.example"]);
    expect(failed.issuance.failure).toMatchObject({ code: "no_dns_provider", message: expect.stringContaining("_acme-challenge.www.elsewhere.example") });
  });

  test("when the DNS Provider refuses the update", async () => {
    const account = await h.api(`/api/organizations/${acmeOrg.orgId}/acme-accounts`, { cookie: acmeOrg.cookie, body: { termsOfServiceAgreed: true } });
    expect(account.status).toBe(201);
    await addBind(acmeOrg, { name: "Read-only", zone: BIND.readonlyZone }); // the server takes no updates for this zone
    const name = host(BIND.readonlyZone);
    const failed = await issueAndEnd([name]);
    const { failure } = failed.issuance;
    expect(failure.code).toBe("dns_update_rejected");
    expect(failure.message).toContain(`_acme-challenge.${name}`);
    expect(failure.message).toContain('"Read-only"');
  });

  test("when the DNS Provider cannot be reached", async () => {
    await h.api(`/api/organizations/${acmeOrg.orgId}/acme-accounts`, { cookie: acmeOrg.cookie, body: { termsOfServiceAgreed: true } });
    await addBind(acmeOrg, { port: 1 });
    const failed = await issueAndEnd([host()]);
    expect(failed.issuance.failure).toMatchObject({ code: "dns_provider_unreachable" });
  });

  test("when the published record never shows in DNS, and it is removed again", async () => {
    await readyToIssue();
    h.dcvResolver.current = { lookupTxt: async () => [] };
    const name = host();
    const failed = await issueAndEnd([name]);
    expect(failed.issuance.failure).toMatchObject({ code: "record_not_visible", message: expect.stringContaining(`_acme-challenge.${name}`) });
    expect(await h.bindTxt.lookupTxt(`_acme-challenge.${name}`)).toEqual([]);
  });

  test("when the CA refuses the order", async () => {
    await addBind(acmeOrg, { zone: "blocked-domain.example" });
    await h.api(`/api/organizations/${acmeOrg.orgId}/acme-accounts`, { cookie: acmeOrg.cookie, body: { termsOfServiceAgreed: true } });
    const failed = await issueAndEnd(["www.blocked-domain.example"]);
    expect(failed.issuance.failure).toMatchObject({ code: "ca_rejected", message: expect.stringContaining("blocked-domain.example") });
  });

  test("when the CA cannot be reached", async () => {
    await readyToIssue();
    h.caDirectories.staging = "https://localhost:1/dir";
    const failed = await issueAndEnd([host()]);
    expect(failed.issuance.failure).toMatchObject({ code: "ca_unreachable" });
  });

  test("and asking again issues it once the cause is gone", async () => {
    await h.api(`/api/organizations/${acmeOrg.orgId}/acme-accounts`, { cookie: acmeOrg.cookie, body: { termsOfServiceAgreed: true } });
    const name = host();
    const failed = await issueAndEnd([name]);
    expect(failed.issuance.failure.code).toBe("no_dns_provider");

    await addBind();
    const retried = await admin().retry(failed.id);
    expect(retried.status).toBe(202);
    expect(retried.body).toMatchObject({ status: "running", failure: null });
    expect(retried.body.id).not.toBe(failed.issuance.id);
    const issued = await ended(failed.id);
    expect(issued.issuance).toMatchObject({ id: retried.body.id, status: "succeeded" });
    expect(issued.currentCertificate.names).toEqual([name]);
  });

  test("and only one Issuance of a Managed Certificate runs at a time", async () => {
    await readyToIssue();
    h.dcvResolver.current = { lookupTxt: async () => [] }; // keeps the first one waiting for its record
    const created = await admin().create(await request([host()]));
    const again = await admin().retry(created.body.id);
    expect(again.status).toBe(409);
    expect(again.body.error).toContain("already running");
    expect((await ended(created.body.id)).issuance.failure.code).toBe("record_not_visible");
  });

  test("an Issuance the platform was stopped in the middle of ends as failed, once", async () => {
    await readyToIssue();
    h.dcvResolver.current = { lookupTxt: async () => [] }; // keeps it running while the platform "restarts"
    const created = await admin().create(await request([host()]));
    expect((await admin().get(created.body.id)).body.issuance.status).toBe("running");

    await h.failInterruptedIssuances();
    expect((await admin().get(created.body.id)).body.issuance).toMatchObject({ status: "failed", failure: { code: "interrupted" } });
    // The run that was cut short, had the platform really stopped, would not have gone on to record anything more.
    await h.settleIssuances();
    expect((await admin().get(created.body.id)).body.issuance.failure.code).toBe("interrupted");
    expect((await auditOf()).filter((e) => e.action === "issuance.failed")).toHaveLength(1);
    // And a new one can be asked for.
    h.dcvResolver.current = h.bindTxt;
    expect((await admin().retry(created.body.id)).status).toBe(202);
    expect((await ended(created.body.id)).issuance.status).toBe("succeeded");
  });

  test("a stored Certificate is immutable", async () => {
    await readyToIssue();
    const created = await admin().create(await request([host()]));
    await ended(created.body.id);
    await expect(h.pool.query("update certificate set names = '{}'")).rejects.toThrow("immutable");
    await expect(h.pool.query("delete from certificate")).rejects.toThrow("immutable");
    expect((await admin().certificates(created.body.id)).body.items).toHaveLength(1);
  });
});

describe("downloading", () => {
  test("there is nothing to download until a Certificate has been issued, and the newest Certificate is the current one", async () => {
    await readyToIssue();
    h.dcvResolver.current = { lookupTxt: async () => [] };
    const created = await admin().create(await request([host()]));
    await ended(created.body.id);
    const before = await admin().download(created.body.id);
    expect(before.status).toBe(404);
    expect((await admin().get(created.body.id)).body.currentCertificate).toBeNull();

    h.dcvResolver.current = h.bindTxt;
    await admin().retry(created.body.id);
    const first = await ended(created.body.id);
    await admin().retry(created.body.id);
    const second = await ended(created.body.id);
    expect(second.currentCertificate.fingerprint).not.toBe(first.currentCertificate.fingerprint);
    const all = (await admin().certificates(created.body.id)).body.items;
    expect(all.map((c: any) => c.fingerprint)).toEqual([second.currentCertificate.fingerprint, first.currentCertificate.fingerprint]);
    const leaf = new X509Certificate(pemBlocks(await (await admin().download(created.body.id)).text())[0]!);
    expect(sha256(leaf)).toBe(second.currentCertificate.fingerprint);
  });

  test("the download is named for the first name", async () => {
    await readyToIssue();
    const name = host();
    const created = await admin().create(await request([`*.${name}`, name]));
    await ended(created.body.id);
    const res = await admin().download(created.body.id);
    expect(res.headers.get("content-disposition")).toBe(`attachment; filename="wildcard.${name}.pem"`);
  });
});

describe("audit", () => {
  test("creation, the start of issuance and its outcome are audited, and a failed one says why", async () => {
    await readyToIssue();
    h.setNow(new Date("2026-02-01T09:00:00Z"));
    const name = host();
    const created = await admin().create(await request([name]));
    const issued = await ended(created.body.id);

    h.dcvResolver.current = { lookupTxt: async () => [] };
    h.setNow(new Date("2026-02-02T09:00:00Z"));
    await admin().retry(created.body.id);
    const retried = await ended(created.body.id);

    const events = (await auditOf()).filter((e) => e.target.id === created.body.id);
    const actor = { id: expect.any(String), email: "admin@acme.test" };
    expect(events.map((e) => e.action)).toEqual(["managed_certificate.created", "issuance.started", "issuance.succeeded", "issuance.started", "issuance.failed"]);
    expect(events[0]).toMatchObject({
      actor,
      target: { type: "managed_certificate" },
      detail: { names: [name], keyAlgorithm: "ecdsa-p256", keyCustody: "owner", environment: "staging", csrFingerprint: expect.stringMatching(/^[0-9a-f]{64}$/) },
    });
    expect(events[1]!.detail).toEqual({ issuanceId: issued.issuance.id });
    expect(events[2]).toMatchObject({
      actor,
      detail: {
        issuanceId: issued.issuance.id,
        certificateId: issued.currentCertificate.id,
        fingerprint: issued.currentCertificate.fingerprint,
        serial: issued.currentCertificate.serial,
        names: [name],
        notAfter: issued.currentCertificate.notAfter,
      },
    });
    expect(events[4]).toMatchObject({ actor, detail: { issuanceId: retried.issuance.id, code: "record_not_visible", message: expect.stringContaining(name) } });
    expect(JSON.stringify(events)).not.toContain("REQUEST");
  });

  test("another Organization does not see them", async () => {
    await readyToIssue();
    await ended((await admin().create(await request([host()]))).body.id);
    expect((await auditOf(globex.cookie, globex.orgId)).filter((e) => /^(managed_certificate|issuance)\./.test(e.action))).toEqual([]);
  });
});
