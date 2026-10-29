// What the Private CAs page says of each CA, of either kind (web/src/lib/private-ca-list.ts): its row, its health, and
// what needs an Organization Administrator. It decides nothing: the server says what each CA is and holds.
import { describe, expect, test } from "bun:test";
import type { AdcsCa, AdcsTemplate, IssuingCa, PrivateCa } from "../../web/src/lib/api";
import { adcsRow, allAttention, caRows, platformRow, rolloverOf, templateGroups } from "../../web/src/lib/private-ca-list";

const NOW = new Date("2026-10-29T12:00:00Z");
const inDays = (days: number) => new Date(NOW.getTime() + days * 24 * 60 * 60 * 1000).toISOString();

const issuing = (over: Partial<IssuingCa> = {}): IssuingCa => ({
  id: "i1",
  subject: "CN=Corp G1, O=Corp",
  status: "active",
  notAfter: inDays(1000),
  permittedNames: { exact: [], zones: ["corp.example"] },
  validity: { maximumDays: 397, defaultDays: 397 },
  nameConstraints: null,
  ...over,
});
const platformCa = (over: Partial<PrivateCa> = {}): PrivateCa => ({
  id: "p1",
  name: "Corp Internal",
  kind: "platform_root",
  status: "active",
  keyAlgorithm: "ecdsa-p256",
  certificateKeyAlgorithms: ["ecdsa-p256"],
  enrollmentProfileRefusal: null,
  root: { subject: "CN=Corp Internal Root", notAfter: inDays(3000) },
  issuingCas: [issuing()],
  createdAt: NOW.toISOString(),
  ...over,
});
const template = (over: Partial<AdcsTemplate> = {}) => ({ id: "t1", available: true, hidden: false, ...over }) as AdcsTemplate;
const adcsCa = (over: Partial<AdcsCa> = {}) =>
  ({
    id: "a1",
    name: "Corp Issuing CA 01",
    configString: "ca01\\Corp Issuing CA 01",
    agentIds: ["agent1", "agent2"],
    caCertificate: { subject: "CN=Corp Issuing CA 01", issuer: "CN=Root", notBefore: NOW.toISOString(), notAfter: inDays(1500), fingerprint: "aa" },
    permittedNames: { exact: ["portal.example.com"], zones: [] },
    templates: [template({ id: "t1" }), template({ id: "t2" }), template({ id: "t3", hidden: true })],
    offered: { tls: ["t1"], devices: ["t1", "t2"] },
    discoveryFailure: null,
    ...over,
  }) as AdcsCa;

describe("the Private CAs page", () => {
  test("an active Issuing CA is due to roll over once it ends sooner than its maximum validity, and has ended at its end", () => {
    expect(rolloverOf(issuing({ notAfter: inDays(400) }), NOW)).toBeNull();
    expect(rolloverOf(issuing({ notAfter: inDays(100) }), NOW)).toEqual({ daysLeft: 100, ended: false });
    expect(rolloverOf(issuing({ notAfter: inDays(-1) }), NOW)?.ended).toBe(true);
    expect(rolloverOf(issuing({ notAfter: inDays(100), status: "retired" }), NOW)).toBeNull();
    expect(rolloverOf(issuing({ notAfter: null, status: "awaiting_signature" }), NOW)).toBeNull();
  });

  test("a CA the platform runs counts its Issuing CAs by status, names their rules, and is healthy with nothing to do", () => {
    const row = platformRow(platformCa({ issuingCas: [issuing(), issuing({ id: "i2", status: "retired", permittedNames: { exact: ["old.example"], zones: [] } })] }), NOW);
    expect(row).toMatchObject({ kind: "platform", identity: "CN=Corp Internal Root", issuesThrough: "2 Issuing CAs", issuesThroughDetail: "1 active · 1 retired", health: { tone: "ok", label: "Healthy" } });
    // The retired one's rules no longer bear on anything.
    expect(row.permittedNames).toBe("anything in corp.example");
    expect(platformRow(platformCa({ issuingCas: [issuing(), issuing({ id: "i2", permittedNames: { exact: ["b.example"], zones: [] } })] }), NOW).permittedNames).toBe("Set per Issuing CA");
  });

  test("an Issuing CA that has ended comes before one due to roll over, and a revoked root needs nothing more", () => {
    const ca = platformCa({ issuingCas: [issuing({ id: "i1", notAfter: inDays(30) }), issuing({ id: "i2", subject: "CN=Corp G0", notAfter: inDays(-2) }), issuing({ id: "i3", status: "awaiting_signature", notAfter: null })] });
    expect(allAttention([ca], [], NOW).map((a) => [a.tone, a.title])).toEqual([
      ["bad", "Issuing CA ended"],
      ["warn", "Rollover due"],
      ["warn", "Awaiting signature"],
    ]);
    expect(platformRow(ca, NOW).health).toEqual({ tone: "bad", label: "Issuing CA ended" });
    expect(allAttention([{ ...ca, status: "revoked" }], [], NOW)).toEqual([]);
    expect(platformRow({ ...ca, status: "revoked" }, NOW).health).toEqual({ tone: "neutral", label: "Revoked" });
  });

  test("an ADCS CA counts the templates offered for anything, and needs attention for a failed discovery or no Permitted Name Rules", () => {
    expect(adcsRow(adcsCa())).toMatchObject({ kind: "adcs", issuesThrough: "3 templates", issuesThroughDetail: "2 offered · through 2 Agents", permittedNames: "portal.example.com", health: { tone: "ok" } });
    const failing = adcsCa({ permittedNames: null, discoveryFailure: { at: NOW.toISOString(), error: "No Agent was online." } });
    expect(allAttention([], [failing], NOW).map((a) => a.title)).toEqual(["Discovery failed", "No Permitted Name Rules"]);
    expect(adcsRow(failing)).toMatchObject({ permittedNames: "None: Approval alone decides", health: { tone: "bad", label: "Discovery failed" } });
  });

  test("the rows list the CAs the platform runs, then the ADCS CAs, each by name; across both, the worst comes first", () => {
    const rows = caRows([platformCa({ id: "p2", name: "Zeta" }), platformCa({ id: "p1", name: "Alpha" })], [adcsCa({ id: "a2", name: "Beta" })], NOW);
    expect(rows.map((r) => `${r.kind}:${r.name}`)).toEqual(["platform:Alpha", "platform:Zeta", "adcs:Beta"]);
    const attention = allAttention([platformCa({ issuingCas: [issuing({ notAfter: inDays(30) })] })], [adcsCa({ discoveryFailure: { at: NOW.toISOString(), error: "x" } })], NOW);
    expect(attention.map((a) => a.kind)).toEqual(["adcs", "platform"]);
  });

  test("an ADCS CA's templates are grouped as available, hidden (whether or not available), and unavailable", () => {
    const groups = templateGroups([template({ id: "ok" }), template({ id: "hid", hidden: true }), template({ id: "gone", available: false }), template({ id: "both", hidden: true, available: false })]);
    expect({ available: groups.available.map((t) => t.id), hidden: groups.hidden.map((t) => t.id), unavailable: groups.unavailable.map((t) => t.id) }).toEqual({
      available: ["ok"],
      hidden: ["hid", "both"],
      unavailable: ["gone"],
    });
  });
});
