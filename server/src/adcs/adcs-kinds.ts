// What the platform knows of an ADCS CA's Certificate Templates, from a module that imports nothing, so that the web
// console shows what the API reports.

/** The key algorithms a Certificate Template may allow, as an Agent reports them. */
export const TEMPLATE_KEY_ALGORITHMS = ["rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"] as const;
export type TemplateKeyAlgorithm = (typeof TEMPLATE_KEY_ALGORITHMS)[number];

/** A config string, as ADCS names a CA: its host, a backslash and the CA's name, `host\\CA Name`. */
export const CONFIG_STRING = /^[^\\\s][^\\]*\\[^\\]*[^\\\s]$/;

/** The EKUs that decide what a Certificate Template is offered for. */
export const SERVER_AUTHENTICATION = "1.3.6.1.5.5.7.3.1";
export const CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2";

/** A Certificate Template's facts, as discovery reports them. */
export interface TemplateFacts {
  /** Its ADCS name (its common name), which requests name it by. */
  name: string;
  oid: string;
  displayName: string;
  /** Its EKUs, as OIDs. */
  extendedKeyUsages: string[];
  /** How long what it issues is valid for, in days. */
  validityDays: number;
  /** The smallest key it takes, in bits. */
  minimumKeySize: number;
  keyAlgorithms: TemplateKeyAlgorithm[];
  /** Whether a request under it waits for a CA manager's approval. */
  managerApproval: boolean;
  /** Whether it takes the subject from the request ("Supply in the request"), rather than building it from Active Directory. */
  subjectFromRequest: boolean;
  /** Whether the Agent's account (its gMSA) may enroll on it. */
  enrollable: boolean;
  /** Whether the CA publishes it. */
  published: boolean;
}

/** A template as the platform keeps it: whether its last discovery reported it at all, as one no longer reported is kept. */
type Kept = Pick<TemplateFacts, "published" | "enrollable" | "subjectFromRequest"> & { reported?: boolean };

/** Why the platform cannot issue under a template, or none when it can: it must be reported, published, enrollable by the gMSA, and take the subject from the request. */
export function unavailableReason(t: Kept): string | null {
  if (t.reported === false) return "The CA no longer reports it.";
  if (!t.published) return "The CA does not publish it.";
  if (!t.enrollable) return "The Agents' account may not enroll on it.";
  if (!t.subjectFromRequest) return "It builds the subject from Active Directory, not from the request.";
  return null;
}

/** Whether the platform can issue under the template. */
export const isAvailable = (t: Kept) => unavailableReason(t) === null;

/** What a template may be offered for: TLS with Server Authentication, devices with Client Authentication. */
export const TEMPLATE_PURPOSES = ["tls", "devices"] as const;
export type TemplatePurpose = (typeof TEMPLATE_PURPOSES)[number];

/** What its EKUs suit a template for, whether or not it is offered: both with both. */
export function purposesOf(t: Pick<TemplateFacts, "extendedKeyUsages">): TemplatePurpose[] {
  return TEMPLATE_PURPOSES.filter((purpose) => t.extendedKeyUsages.includes(purpose === "tls" ? SERVER_AUTHENTICATION : CLIENT_AUTHENTICATION));
}

/** What the platform offers a template for: what it suits, while it is available and not hidden. */
export const offeredFor = (t: Kept & Pick<TemplateFacts, "extendedKeyUsages"> & { hidden: boolean }): TemplatePurpose[] => (t.hidden || !isAvailable(t) ? [] : purposesOf(t));
