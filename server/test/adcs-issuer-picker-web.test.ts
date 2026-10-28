// The issuer picker's ADCS CAs, as the new Managed Certificate and Deployment dialogs list them (web/src/lib/adcs-ca.ts).
// It decides nothing: the server refuses a template not offered for TLS, and a key the template does not take.
import { describe, expect, test } from "bun:test";
import { adcsTemplateTitle, adcsTlsChoices, keyAlgorithmsTakenBy, templateKeysLabel } from "../../web/src/lib/adcs-ca";
import type { AdcsCa, AdcsTemplate } from "../../web/src/lib/api";

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
});
