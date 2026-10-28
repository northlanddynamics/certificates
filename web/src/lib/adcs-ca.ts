// What the ADCS CAs page says of a CA, its templates and the Agents it may be assigned. Pure and free of the app's imports,
// so the server's tests can run it.
import type { AdcsCa, AdcsTemplate, Agent } from "./api";
// The server's own EKUs and config-string pattern, from a module that imports nothing, so the console sorts templates as the API does.
import { CLIENT_AUTHENTICATION, CONFIG_STRING, SERVER_AUTHENTICATION, TEMPLATE_KEY_LABELS, purposesOf } from "../../../server/src/adcs/adcs-kinds";

/** Whether `text` is a config string as the server takes one: the CA's host, a backslash, and the CA's name. */
export const isConfigString = (text: string) => CONFIG_STRING.test(text.trim());

const EKU_NAMES: Record<string, string> = {
  [SERVER_AUTHENTICATION]: "Server Authentication",
  [CLIENT_AUTHENTICATION]: "Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Secure Email",
  "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
};

/** An EKU by its name, or by its OID when it has none here. */
export const ekuLabel = (oid: string) => EKU_NAMES[oid] ?? oid;

const PURPOSE_LABELS = { tls: "TLS", devices: "Devices" } as const;

/** What a template could serve: TLS with Server Authentication, devices with Client Authentication, both with both. */
export const templatePurposes = (template: Pick<AdcsTemplate, "extendedKeyUsages">) => purposesOf(template).map((purpose) => PURPOSE_LABELS[purpose]);

/** The Agents an ADCS CA may be assigned, as the server allows: Windows ones that are not revoked, and those it already has. */
export const assignableAgents = (agents: Agent[], chosen: string[]) => agents.filter((a) => chosen.includes(a.id) || (a.os === "windows" && a.status !== "revoked"));

/** The ADCS CAs as the issuer pickers offer them for TLS: each with those of its templates offered for TLS (available, not hidden, with Server Authentication), and none without any. */
export const adcsTlsChoices = (cas: AdcsCa[]) =>
  cas.map((ca) => ({ ca, templates: ca.templates.filter((t) => ca.offered.tls.includes(t.id)) })).filter((choice) => choice.templates.length > 0);


/** What keys a template takes, in words: its algorithms, RSA with its minimum size. */
export const templateKeysLabel = (template: Pick<AdcsTemplate, "keyAlgorithms" | "minimumKeySize">) =>
  template.keyAlgorithms.map((a) => (a === "rsa" ? `RSA of ${template.minimumKeySize} bits or more` : TEMPLATE_KEY_LABELS[a])).join(", ") || "none the platform makes";

/** A template in a few words, with its CA: "<template> · <ADCS CA>". */
export const adcsTemplateTitle = (caName: string, template: Pick<AdcsTemplate, "displayName" | "name">) => `${template.displayName || template.name} · ${caName}`;
