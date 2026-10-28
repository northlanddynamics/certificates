// What the platform knows of an ADCS CA's Certificate Templates, from a module that imports nothing, so that the web
// console shows what the API reports.

/** The key algorithms a Certificate Template may allow, as an Agent reports them. */
export const TEMPLATE_KEY_ALGORITHMS = ["rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"] as const;
export type TemplateKeyAlgorithm = (typeof TEMPLATE_KEY_ALGORITHMS)[number];

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

/** Whether the platform can issue under the template: it is published, the gMSA may enroll on it, and it takes the subject from the request. */
export const isAvailable = (t: Pick<TemplateFacts, "published" | "enrollable" | "subjectFromRequest">) => t.published && t.enrollable && t.subjectFromRequest;
