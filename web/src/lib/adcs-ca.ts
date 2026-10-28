// What the ADCS CAs page says of a CA, its templates and the Agents it may be assigned. Pure and free of the app's imports,
// so the server's tests can run it.
import type { AdcsTemplate, Agent } from "./api";
// The server's own EKUs, from a module that imports nothing, so the console sorts templates as the API does.
import { CLIENT_AUTHENTICATION, SERVER_AUTHENTICATION } from "../../../server/src/adcs/adcs-kinds";

/** Whether `text` is a config string as the server takes one: the CA's host, a backslash, and the CA's name. */
export const isConfigString = (text: string) => /^[^\\\s][^\\]*\\[^\\]*[^\\\s]$/.test(text.trim());

const EKU_NAMES: Record<string, string> = {
  [SERVER_AUTHENTICATION]: "Server Authentication",
  [CLIENT_AUTHENTICATION]: "Client Authentication",
  "1.3.6.1.5.5.7.3.3": "Code Signing",
  "1.3.6.1.5.5.7.3.4": "Secure Email",
  "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
};

/** An EKU by its name, or by its OID when it has none here. */
export const ekuLabel = (oid: string) => EKU_NAMES[oid] ?? oid;

/** What a template could serve: TLS with Server Authentication, devices with Client Authentication, both with both. */
export function templatePurposes(template: Pick<AdcsTemplate, "extendedKeyUsages">): ("TLS" | "Devices")[] {
  return [...(template.extendedKeyUsages.includes(SERVER_AUTHENTICATION) ? ["TLS" as const] : []), ...(template.extendedKeyUsages.includes(CLIENT_AUTHENTICATION) ? ["Devices" as const] : [])];
}

/** Why the platform cannot issue under a template, or none when it can. */
export function unavailableReason(template: Pick<AdcsTemplate, "published" | "enrollable" | "subjectFromRequest">): string | null {
  if (!template.published) return "The CA does not publish it.";
  if (!template.enrollable) return "The Agents' account may not enroll on it.";
  if (!template.subjectFromRequest) return "It builds the subject from Active Directory, not from the request.";
  return null;
}

/** The Agents an ADCS CA may be assigned, as the server allows: Windows ones that are not revoked, and those it already has. */
export const assignableAgents = (agents: Agent[], chosen: string[]) => agents.filter((a) => chosen.includes(a.id) || (a.os === "windows" && a.status !== "revoked"));
