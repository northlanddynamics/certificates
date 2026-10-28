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

/** A template's facts, and, for one the platform keeps, whether its last discovery reported it (one just discovered was). */
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

/** What a template may be offered for, and the EKU it needs for each: TLS with Server Authentication, devices with Client Authentication. */
const PURPOSE_EKUS = { tls: SERVER_AUTHENTICATION, devices: CLIENT_AUTHENTICATION } as const;
export type TemplatePurpose = keyof typeof PURPOSE_EKUS;
export const TEMPLATE_PURPOSES = Object.keys(PURPOSE_EKUS) as TemplatePurpose[];

/** What its EKUs suit a template for, whether or not it is offered: both with both. */
export function purposesOf(t: Pick<TemplateFacts, "extendedKeyUsages">): TemplatePurpose[] {
  return TEMPLATE_PURPOSES.filter((purpose) => t.extendedKeyUsages.includes(PURPOSE_EKUS[purpose]));
}

/** What the platform offers a template for: what it suits, while it is available and not hidden. */
export const offeredFor = (t: Kept & Pick<TemplateFacts, "extendedKeyUsages"> & { hidden: boolean }): TemplatePurpose[] => (t.hidden || !isAvailable(t) ? [] : purposesOf(t));

/** The key algorithms a template may allow, in words. */
export const TEMPLATE_KEY_LABELS: Record<TemplateKeyAlgorithm, string> = { rsa: "RSA", "ecdsa-p256": "ECDSA P-256", "ecdsa-p384": "ECDSA P-384", "ecdsa-p521": "ECDSA P-521" };

/**
 * Why a template refuses a key of `keyAlgorithm`, as the platform names keys (`rsa-2048`, `ecdsa-p256`, `ml-dsa-65`...),
 * or none when it takes it. An RSA key must be of a size at least its minimum key size; an ECDSA key's curve must be one it
 * allows, since a curve is its own size. ADCS takes no ML-DSA key.
 */
export function templateKeyRefusal(t: Pick<TemplateFacts, "name" | "minimumKeySize" | "keyAlgorithms">, keyAlgorithm: string): string | null {
  const rsa = /^rsa-(\d+)$/.exec(keyAlgorithm);
  const family = rsa ? "rsa" : keyAlgorithm;
  if (!(t.keyAlgorithms as string[]).includes(family)) {
    const takes = t.keyAlgorithms.map((a) => TEMPLATE_KEY_LABELS[a]).join(", ") || "no key the platform makes";
    return `the Certificate Template ${t.name} takes keys of ${takes}, not ${keyAlgorithm}`;
  }
  if (rsa && Number(rsa[1]) < t.minimumKeySize) return `the Certificate Template ${t.name} takes RSA keys of at least ${t.minimumKeySize} bits, not ${keyAlgorithm}`;
  return null;
}

/** Those of `keyAlgorithms` (as the platform names keys) the template takes. */
export const templateKeyAlgorithms = <K extends string>(t: Pick<TemplateFacts, "name" | "minimumKeySize" | "keyAlgorithms">, keyAlgorithms: readonly K[]) =>
  keyAlgorithms.filter((k) => templateKeyRefusal(t, k) === null);
