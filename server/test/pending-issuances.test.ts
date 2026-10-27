// Pending Issuances: an issuer kind may answer that its CA will issue later, as a CA reached through an Agent does. The
// Issuance stays running with the handle the kind keeps the request by, holds off any other Issuance of its Managed
// Certificate, and ends when the kind reports the result, as one that ended at once would have, or as timed out when
// its deadline passes. The kind here is the test-only held issuer, in front of a Private CA, which issues what it reports.
// No Pebble and no DNS; time is the harness's clock.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import acme from "acme-client";
import { CertificateAuthorityError } from "../src/issuance/acme/certificate-authority";
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

const JAN_1 = Date.parse("2026-01-01T00:00:00Z");
const DAY = 86_400_000;
const days = (n: number) => new Date(JAN_1 + n * DAY);

const api = (path: string, opts: { body?: unknown; method?: string } = {}) => h.api(`/api/organizations/${org.orgId}${path}`, { cookie: org.cookie, ...opts });
const auditOf = async () => (await api("/audit-events")).body.items as { action: string; target: any; detail: any }[];

const NEW_CA = { name: "Internal TLS", subject: "CN=Acme Internal TLS, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["internal.acme"] } };

async function createCa() {
  const res = await api("/private-cas", { body: NEW_CA });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, issuingCaId: res.body.issuingCas[0].id as string };
}

async function request(names: string[]) {
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  return { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString() };
}

/** A Managed Certificate created on the Private CA, once its Issuance has been answered (at once, or pending). */
async function created(names = ["app.internal.acme"]) {
  const ca = await createCa();
  const res = await api("/managed-certificates", { body: { ...(await request(names)), issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId } } });
  expect(res.status).toBe(201);
  await h.settleIssuances();
  return { ca, mc: await managedCertificate(res.body.id) };
}

const managedCertificate = async (id: string) => (await api(`/managed-certificates/${id}`)).body;
const issuancesOf = async (id: string) => (await api(`/managed-certificates/${id}/issuances`)).body.items as any[];

describe("an Issuance whose CA answers that it will issue later", () => {
  test("stays running with the kind's handle and deadline, and has no Certificate yet", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    expect(mc.issuance).toMatchObject({ status: "running", failure: null, certificateId: null, awaitingKey: false, pending: { handle: "held-1", deadline: days(7).toISOString() } });
    expect(mc.currentCertificate).toBeNull();
    expect((await auditOf()).map((e) => e.action)).not.toContain("issuance.succeeded");
    expect((await auditOf()).map((e) => e.action)).not.toContain("issuance.failed");
  });

  test("an Issuance answered at once is never pending", async () => {
    const { mc } = await created();

    expect(mc.issuance).toMatchObject({ status: "succeeded", pending: null });
  });

  test("holds off another Issuance of its Managed Certificate, however it is asked for", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    const again = await api(`/managed-certificates/${mc.id}/issuances`, { body: {} });
    expect(again.status).toBe(409);
    expect(again.body.error).toContain("already running");
    h.setNow(days(80));
    expect(await h.runRenewalScheduler()).toBe(0);
    expect(await issuancesOf(mc.id)).toHaveLength(1);
  });

  test("ends with the Certificate the CA issued once the kind reports it, with the Audit Events of one that ended at once", async () => {
    h.heldIssuer.holding = true;
    const { ca, mc } = await created(["app.internal.acme", "api.internal.acme"]);
    h.setNow(days(1));

    expect(await h.heldIssuer.release(mc.issuance.id)).toBe(true);

    const after = await managedCertificate(mc.id);
    expect(after.issuance).toMatchObject({ id: mc.issuance.id, status: "succeeded", failure: null, finishedAt: days(1).toISOString(), pending: { handle: "held-1" } });
    expect(after.currentCertificate).toMatchObject({ id: after.issuance.certificateId, ca: "Internal TLS", issuingCaId: ca.issuingCaId, names: ["app.internal.acme", "api.internal.acme"] });
    const events = (await auditOf()).filter((e) => e.action.startsWith("issuance."));
    expect(events.map((e) => e.action).sort()).toEqual(["issuance.started", "issuance.succeeded"]);
    expect(events.find((e) => e.action === "issuance.succeeded")!.detail).toMatchObject({
      issuanceId: mc.issuance.id,
      certificateId: after.currentCertificate.id,
      names: ["app.internal.acme", "api.internal.acme"],
      issuer: { kind: "private_ca", issuingCaId: ca.issuingCaId },
    });

    const res = await h.app.request(`http://localhost/api/organizations/${org.orgId}/managed-certificates/${mc.id}/certificate?chain=leaf`, { headers: { cookie: org.cookie } });
    const leaf = new x509.X509Certificate(await res.text());
    expect(leaf.serialNumber.toUpperCase()).toBe(after.currentCertificate.serial);
  });

  test("stores the Certificate once when the kind reports it twice", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    const issued = await h.heldIssuer.issue(mc.issuance.id);
    const reported = await Promise.all([h.issuances.report(mc.issuance.id, issued), h.issuances.report(mc.issuance.id, issued)]);

    expect(reported.sort()).toEqual([false, true]);
    expect((await api(`/managed-certificates/${mc.id}/certificates`)).body.items).toHaveLength(1);
    expect((await auditOf()).filter((e) => e.action === "issuance.succeeded")).toHaveLength(1);
  });

  test("fails with the cause the kind reports", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();
    h.setNow(days(2));

    expect(await h.heldIssuer.fail(mc.issuance.id, new CertificateAuthorityError("rejected", "the CA denied the request: not allowed"))).toBe(true);

    const after = await managedCertificate(mc.id);
    expect(after.issuance).toMatchObject({ status: "failed", finishedAt: days(2).toISOString(), failure: { code: "ca_rejected", message: "the CA denied the request: not allowed" } });
    expect(after.currentCertificate).toBeNull();
    const failed = (await auditOf()).filter((e) => e.action === "issuance.failed");
    expect(failed).toMatchObject([{ target: { type: "managed_certificate", id: mc.id }, detail: { issuanceId: mc.issuance.id, code: "ca_rejected" } }]);
    // It has ended: a later report changes nothing.
    expect(await h.heldIssuer.fail(mc.issuance.id, new CertificateAuthorityError("unreachable", "gone"))).toBe(false);
    expect((await managedCertificate(mc.id)).issuance.failure.code).toBe("ca_rejected");
  });

  test("a CA that could not be reached fails it as unreachable", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    await h.heldIssuer.fail(mc.issuance.id, new CertificateAuthorityError("unreachable", "no Agent could reach the CA"));

    expect((await managedCertificate(mc.id)).issuance.failure).toEqual({ code: "ca_unreachable", message: "no Agent could reach the CA" });
  });

  test("keeps the handle and deadline the kind reports while it is pending still", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    expect(await h.heldIssuer.stillPending(mc.issuance.id, "request-42", days(5))).toBe(true);

    expect((await managedCertificate(mc.id)).issuance).toMatchObject({ status: "running", pending: { handle: "request-42", deadline: days(5).toISOString() } });
  });

  test("a Renewal that was pending tells the Managed Certificate's Subscribers how it ended, as one that ended at once does", async () => {
    const { mc } = await created();
    const channel = await api("/notification-channels", { body: { name: "SIEM", kind: "webhook", url: "https://hooks.example.test/T000/B000/s3cr3t" } });
    expect((await api(`/managed-certificates/${mc.id}/subscribers`, { body: { type: "channel", id: channel.body.id } })).status).toBe(200);
    h.heldIssuer.holding = true;

    const renewal = await api(`/managed-certificates/${mc.id}/renewals`, { body: {} });
    expect(renewal.status).toBe(202);
    await h.settleIssuances();
    expect(await h.deliverNotices()).toBe(0);
    await h.heldIssuer.release(renewal.body.id);

    expect(await h.deliverNotices()).toBe(1);
    expect(h.webhooks.sent.map((w) => w.body.event)).toEqual(["renewal.succeeded"]);
    expect((await managedCertificate(mc.id)).issuance).toMatchObject({ id: renewal.body.id, kind: "renewal", status: "succeeded" });
  });
});

describe("a pending Issuance whose deadline passes", () => {
  test("fails as timed out once it has passed, and not before", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    h.setNow(new Date(days(7).getTime() - 1));
    expect(await h.timeOutIssuances()).toBe(0);
    expect((await managedCertificate(mc.id)).issuance.status).toBe("running");

    h.setNow(days(7));
    expect(await h.timeOutIssuances()).toBe(1);
    const after = await managedCertificate(mc.id);
    expect(after.issuance).toMatchObject({ status: "failed", finishedAt: days(7).toISOString(), failure: { code: "timed_out" } });
    expect((await auditOf()).filter((e) => e.action === "issuance.failed")).toMatchObject([{ detail: { issuanceId: mc.issuance.id, code: "timed_out" } }]);
    expect(await h.timeOutIssuances()).toBe(0);
  });

  test("lets another Issuance begin once it has timed out", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();
    h.setNow(days(8));
    await h.timeOutIssuances();
    h.heldIssuer.holding = false;

    const again = await api(`/managed-certificates/${mc.id}/issuances`, { body: {} });
    expect(again.status).toBe(202);
    await h.settleIssuances();
    expect((await managedCertificate(mc.id)).issuance).toMatchObject({ id: again.body.id, status: "succeeded" });
  });

  test("still keeps a Certificate the CA issued after all, after the deadline", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();
    h.setNow(days(8));
    await h.timeOutIssuances();

    expect(await h.heldIssuer.release(mc.issuance.id)).toBe(true);

    const after = await managedCertificate(mc.id);
    expect(after.issuance).toMatchObject({ status: "succeeded", failure: null });
    expect(after.currentCertificate).not.toBeNull();
  });
});

describe("a platform restart", () => {
  test("leaves a pending Issuance running, and the kind's report still ends it", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();

    await h.failInterruptedIssuances();

    expect((await managedCertificate(mc.id)).issuance).toMatchObject({ status: "running", pending: { handle: "held-1" } });
    expect(await h.heldIssuer.release(mc.issuance.id)).toBe(true);
    expect((await managedCertificate(mc.id)).issuance.status).toBe("succeeded");
  });

  test("leaves a pending Issuance to time out", async () => {
    h.heldIssuer.holding = true;
    const { mc } = await created();
    await h.failInterruptedIssuances();

    h.setNow(days(7));
    expect(await h.timeOutIssuances()).toBe(1);
    expect((await managedCertificate(mc.id)).issuance.failure.code).toBe("timed_out");
  });
});
