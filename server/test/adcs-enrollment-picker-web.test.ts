// The ADCS CAs in the new Enrollment Profile dialog (web/src/lib/adcs-ca.ts): its templates for devices, those its RA
// certificate may be issued under, and where a profile stands with its RA certificate. It decides nothing: the server
// refuses a template not offered for devices, an unavailable RA template, and a device key the template does not take.
import { describe, expect, test } from "bun:test";
import { adcsDeviceChoices, adcsRaTemplates, raCertificateState } from "../../web/src/lib/adcs-ca";
import type { AdcsCa, AdcsTemplate } from "../../web/src/lib/api";

const template = (id: string, over: Partial<AdcsTemplate> = {}) => ({ id, name: id, displayName: `${id} display`, available: true, hidden: false, keyAlgorithms: ["rsa"], minimumKeySize: 2048, ...over }) as AdcsTemplate;
const ca = (id: string, templates: AdcsTemplate[], devices: string[]) => ({ id, name: id, templates, offered: { tls: [], devices } }) as unknown as AdcsCa;

describe("the ADCS CAs in the Enrollment Profile dialog", () => {
  test("each CA is listed with the templates it offers for devices, and a CA offering none is not listed", () => {
    const corp = ca("Corp", [template("Web"), template("Device")], ["Device"]);
    const lab = ca("Lab", [template("Web")], []);
    expect(adcsDeviceChoices([corp, lab]).map(({ ca, templates }) => [ca.id, templates.map((t) => t.id)])).toEqual([["Corp", ["Device"]]]);
  });

  test("the RA certificate may be issued under any available template that is not hidden and takes the RA's key, whatever it is offered for", () => {
    const corp = ca("Corp", [template("Ra"), template("Device"), template("Gone", { available: false }), template("Hidden", { hidden: true }), template("Big", { minimumKeySize: 4096 })], ["Device"]);
    expect(adcsRaTemplates(corp).map((t) => t.id)).toEqual(["Ra", "Device"]);
  });
});

describe("where a profile on an ADCS CA stands with its RA certificate", () => {
  const ra = { subject: "CN=SCEP RA", serial: "01", notAfter: "2027-01-01T00:00:00.000Z" };
  test("waiting for ADCS, refused by it, being replaced, or nothing to say", () => {
    expect(raCertificateState({ raCertificate: null, raRequested: true })).toContain("serves no SCEP until then");
    expect(raCertificateState({ raCertificate: null, raRequested: false })).toContain("did not issue its RA certificate");
    expect(raCertificateState({ raCertificate: ra, raRequested: true })).toContain("the current one serves until it is issued");
    expect(raCertificateState({ raCertificate: ra, raRequested: false })).toBeUndefined();
  });
});
