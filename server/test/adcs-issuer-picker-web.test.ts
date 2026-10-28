// The issuer picker's ADCS CAs, as the new Managed Certificate and Deployment dialogs list them (web/src/lib/adcs-ca.ts).
// It decides nothing: the server refuses a template not offered for TLS, and a key the template does not take.
import { describe, expect, test } from "bun:test";
import { MANAGER_APPROVAL_NOTE, adcsIssuerTitle, adcsRequestState, adcsTemplateTitle, adcsTlsChoices, templateApprovalLabel, templateKeysLabel, templateUnavailableWarning } from "../../web/src/lib/adcs-ca";
import { templateKeyAlgorithms as keyAlgorithmsTakenBy } from "../src/adcs/adcs-kinds";
import type { AdcsCa, AdcsRequest, AdcsTemplate } from "../../web/src/lib/api";

const template = (id: string, over: Partial<AdcsTemplate> = {}) =>
  ({ id, name: id, displayName: `${id} display`, validityDays: 365, minimumKeySize: 2048, keyAlgorithms: ["rsa", "ecdsa-p256"], ...over }) as AdcsTemplate;
const ca = (id: string, templates: AdcsTemplate[], tls: string[]) => ({ id, name: id, templates, offered: { tls, devices: [] }, permittedNames: null }) as unknown as AdcsCa;

describe("the ADCS CAs in the issuer picker", () => {
  test("each CA is listed with the templates it offers for TLS, and a CA offering none is not listed", () => {
    const web = template("Web");
    const device = template("Device");
    const corp = ca("Corp", [device, web], ["Web"]);
    const lab = ca("Lab", [template("Other")], []);
    expect(adcsTlsChoices([corp, lab]).map(({ ca, templates }) => [ca.id, templates.map((t) => t.id)])).toEqual([["Corp", ["Web"]]]);
  });

  test("a template takes the keys its algorithms allow, RSA of at least its minimum size", () => {
    const classical = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
    expect(keyAlgorithmsTakenBy(template("Web"), classical)).toEqual(["ecdsa-p256", "rsa-2048", "rsa-3072", "rsa-4096"]);
    expect(keyAlgorithmsTakenBy(template("Big", { minimumKeySize: 3072, keyAlgorithms: ["rsa"] }), classical)).toEqual(["rsa-3072", "rsa-4096"]);
    expect(keyAlgorithmsTakenBy(template("Web"), ["ml-dsa-65"] as const)).toEqual([]);
    expect(templateKeysLabel(template("Web"))).toBe("RSA of 2048 bits or more, ECDSA P-256");
  });

  test("a template is named with its CA, by its display name when it has one", () => {
    expect(adcsTemplateTitle("Corp", { name: "CorpWebServer", displayName: "Corp Web Server" })).toBe("Corp Web Server · Corp");
    expect(adcsTemplateTitle("Corp", { name: "CorpWebServer", displayName: "" })).toBe("CorpWebServer · Corp");
  });

  test("a template that needs CA manager approval says so, in the template table and the picker", () => {
    expect(templateApprovalLabel(template("Web", { managerApproval: true }))).toBe("Needs CA manager approval");
    expect(templateApprovalLabel(template("Web", { managerApproval: false }))).toBe("None");
    expect(MANAGER_APPROVAL_NOTE).toContain("waits at ADCS until a CA manager issues or denies it");
  });
});

describe("a Certificate Profile on an ADCS CA", () => {
  test("names its template with its CA, even while the template is no longer offered", () => {
    const corp = ca("Corp", [template("Web"), template("Gone")], ["Web"]);
    expect(adcsIssuerTitle([corp], { adcsCaId: "Corp", templateId: "Gone" })).toBe("Gone display · Corp");
    expect(adcsIssuerTitle([corp], { adcsCaId: "Corp", templateId: "Other" })).toBeUndefined();
    expect(adcsIssuerTitle([], { adcsCaId: "Corp", templateId: "Web" })).toBeUndefined();
  });

  test("warns, while its template is unavailable, that it stays enabled but issues nothing until the template is back", () => {
    expect(templateUnavailableWarning("The CA no longer reports it.")).toBe(
      "The CA no longer reports it. The profile stays enabled, but requests through it are refused and its Issuances fail until ADCS makes the Certificate Template available again; nothing needs reconfiguring.",
    );
  });
});

describe("where an Issuance's request to an ADCS CA stands", () => {
  const request = (over: Partial<AdcsRequest>): AdcsRequest => ({ status: "waiting", agent: null, requestId: null, pendingUntil: null, ...over });
  test("waiting for an Agent, submitted through one, or pending at ADCS with its request ID", () => {
    expect(adcsRequestState(request({}))).toBe("waiting for an Agent of the ADCS CA to be online");
    expect(adcsRequestState(request({ status: "submitted", agent: { id: "a", hostName: "win-1" } }))).toBe("submitted to ADCS through the Agent on win-1");
    expect(adcsRequestState(request({ status: "pending", requestId: "101", pendingUntil: "2026-01-08T00:00:00.000Z" }))).toBe("pending at ADCS for a CA manager's approval (request 101)");
    expect(adcsRequestState(request({ status: "issued", requestId: "101" }))).toBeUndefined();
    expect(adcsRequestState(null)).toBeUndefined();
  });
});
