// What the ADCS CAs page says of a CA, its templates and the Agents it may be assigned. Pure and free of the app's imports,
// so the server's tests can run it.
import type { AdcsCa, AdcsRequest, AdcsTemplate, Agent } from "./api";
// The server's own EKUs and config-string pattern, from a module that imports nothing, so the console sorts templates as the API does.
import { CLIENT_AUTHENTICATION, CONFIG_STRING, SERVER_AUTHENTICATION, TEMPLATE_KEY_LABELS, purposesOf, templateKeyAlgorithms } from "../../../server/src/adcs/adcs-kinds";
// The key the platform makes for an RA, which the server checks an RA template takes.
import { RA_KEY_TYPE } from "../../../server/src/enrollment/enrollment-profile-kinds";

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

/** The ADCS CAs as an Enrollment Profile's issuer picker offers them: each with those of its templates offered for devices (with Client Authentication), and none without any. */
export const adcsDeviceChoices = (cas: AdcsCa[]) =>
  cas.map((ca) => ({ ca, templates: ca.templates.filter((t) => ca.offered.devices.includes(t.id)) })).filter((choice) => choice.templates.length > 0);

/** The templates of the ADCS CA an Enrollment Profile's RA certificate may be issued under: any available one not hidden that takes the RA's key, whatever its EKUs. */
export const adcsRaTemplates = (ca: Pick<AdcsCa, "templates">) => ca.templates.filter((t) => t.available && !t.hidden && templateKeyAlgorithms(t, [RA_KEY_TYPE]).length > 0);

/** Where a profile on an ADCS CA stands with its RA certificate, as a phrase; none once it has one and none is asked for. */
export function raCertificateState(profile: { raCertificate: unknown; raRequested: boolean }) {
  if (profile.raCertificate === null)
    return profile.raRequested
      ? "Waiting for ADCS to issue its RA certificate, through an Agent: it serves no SCEP until then."
      : "ADCS did not issue its RA certificate, so it serves no SCEP: ask for it again with Rotate RA certificate, or wait for the daily retry.";
  return profile.raRequested ? "A new RA certificate is asked of ADCS; the current one serves until it is issued." : undefined;
}


/** What keys a template takes, in words: its algorithms, RSA with its minimum size. */
export const templateKeysLabel = (template: Pick<AdcsTemplate, "keyAlgorithms" | "minimumKeySize">) =>
  template.keyAlgorithms.map((a) => (a === "rsa" ? `RSA of ${template.minimumKeySize} bits or more` : TEMPLATE_KEY_LABELS[a])).join(", ") || "none the platform makes";

/** Whether a request under the template waits at ADCS for a CA manager's approval, in words. */
export const templateApprovalLabel = (template: Pick<AdcsTemplate, "managerApproval">) => (template.managerApproval ? "Needs CA manager approval" : "None");

/** What a request under a template that needs CA manager approval goes through, for whoever picks it. */
export const MANAGER_APPROVAL_NOTE = "Needs CA manager approval: each request waits at ADCS until a CA manager issues or denies it, and fails after 7 days.";

/** Where an Issuance's running request to an ADCS CA stands, as a phrase; none when it is not with ADCS or its Agents. */
export function adcsRequestState(request: AdcsRequest | null) {
  if (request?.status === "waiting") return "waiting for an Agent of the ADCS CA to be online";
  if (request?.status === "submitted" && request.agent) return `submitted to ADCS through the Agent on ${request.agent.hostName}`;
  if (request?.status === "pending") return `pending at ADCS for a CA manager's approval${request.requestId ? ` (request ${request.requestId})` : ""}`;
  return undefined;
}

/** A template in a few words, with its CA: "<template> · <ADCS CA>". */
export const adcsTemplateTitle = (caName: string, template: Pick<AdcsTemplate, "displayName" | "name">) => `${template.displayName || template.name} · ${caName}`;

/** The template an ADCS issuer names, with its CA, whether or not it is offered now; none while the CA is not listed or has no such template. */
export function adcsIssuerTitle(cas: Pick<AdcsCa, "id" | "name" | "templates">[], issuer: { adcsCaId: string; templateId: string }) {
  const ca = cas.find((c) => c.id === issuer.adcsCaId);
  const template = ca?.templates.find((t) => t.id === issuer.templateId);
  return ca && template ? adcsTemplateTitle(ca.name, template) : undefined;
}

/** What a Certificate Profile whose template is unavailable warns of, given why (as the server says it). */
export const templateUnavailableWarning = (reason: string) =>
  `${reason} The profile stays enabled, but requests through it are refused and its Issuances fail until ADCS makes the Certificate Template available again; nothing needs reconfiguring.`;
