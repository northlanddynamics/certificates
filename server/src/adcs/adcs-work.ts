// The work items by which Agents carry out an ADCS CA's operations, and what they report. None carries a secret: the Agent
// reaches ADCS as its own account (its gMSA), so the platform holds no credential to give it.
import { z } from "@hono/zod-openapi";
import { TEMPLATE_KEY_ALGORITHMS } from "./adcs-kinds";

export const ADCS_WORK_TYPES = { discover: "adcs.discover", submit: "adcs.submit", check: "adcs.check", revoke: "adcs.revoke" } as const;

/** The longest PEM certificate an Agent may report, and how many certificates a chain may have. */
const MAX_CERTIFICATE_PEM = 32_768;
const MAX_CHAIN = 10;
/** The most templates one discovery may report. */
export const MAX_TEMPLATES = 500;

export const TemplateFactsResult = z.object({
  name: z.string().min(1).max(255).openapi({ description: "Its ADCS name (common name), which requests name it by." }),
  oid: z.string().regex(/^\d+(\.\d+)+$/).max(255),
  displayName: z.string().max(255),
  extendedKeyUsages: z.array(z.string().regex(/^\d+(\.\d+)+$/).max(255)).max(50).openapi({ description: "Its EKUs, as OIDs." }),
  validityDays: z.number().int().min(1).max(36_500).openapi({ description: "How long what it issues is valid for, in days." }),
  minimumKeySize: z.number().int().min(0).max(16_384).openapi({ description: "The smallest key it takes, in bits." }),
  keyAlgorithms: z.array(z.enum(TEMPLATE_KEY_ALGORITHMS)).max(TEMPLATE_KEY_ALGORITHMS.length).openapi({ description: "The key algorithms it allows." }),
  managerApproval: z.boolean().openapi({ description: "Whether a request under it waits for a CA manager's approval." }),
  subjectFromRequest: z.boolean().openapi({ description: "Whether it is set to \"Supply in the request\", rather than building the subject from Active Directory." }),
  enrollable: z.boolean().openapi({ description: "Whether the Agent's account may enroll on it." }),
  published: z.boolean().openapi({ description: "Whether the CA publishes it." }),
});

export const DiscoveryResult = z
  .object({
    chain: z
      .array(z.string().max(MAX_CERTIFICATE_PEM))
      .min(1)
      .max(MAX_CHAIN)
      .openapi({ description: "The CA certificate (PEM), then each certificate above it up to its root, the one that signs it first." }),
    templates: z.array(TemplateFactsResult).max(MAX_TEMPLATES).openapi({ description: "Each Certificate Template the CA publishes, with its facts." }),
  })
  .openapi({ description: "For `adcs.discover`: what the Agent found at the ADCS CA." });
export type DiscoveryResult = z.infer<typeof DiscoveryResult>;

const RequestId = z.string().min(1).max(64).openapi({ description: "ADCS's ID of the request." });

export const SubmissionResult = z
  .discriminatedUnion("status", [
    z.object({
      status: z.literal("issued").openapi({ description: "`issued`: ADCS issued the Certificate." }),
      requestId: RequestId,
      certificate: z.string().max(MAX_CERTIFICATE_PEM).openapi({ description: "The Certificate ADCS issued, PEM." }),
    }),
    z.object({
      status: z.literal("pending").openapi({ description: "`pending`: ADCS holds the request for a CA manager's approval; the platform asks again with `adcs.check`." }),
      requestId: RequestId,
    }),
    z.object({
      status: z.literal("denied").openapi({ description: "`denied`: ADCS denied the request, a CA manager or its policy." }),
      requestId: RequestId,
      message: z.string().max(1024).openapi({ description: "ADCS's disposition message: why it denied the request." }),
    }),
  ])
  .openapi({ description: "For `adcs.submit` and `adcs.check`: what ADCS answered the request with, or holds it as now." });
export type SubmissionResult = z.infer<typeof SubmissionResult>;

export const RevocationResult = z
  .object({ status: z.literal("revoked").openapi({ description: "`revoked`: ADCS revoked the Certificate, or had already." }) })
  .openapi({ description: "For `adcs.revoke`: that ADCS revoked the Certificate. A refusal or a CA that does not answer is reported as a failure, `rejected` or `unreachable`." });
export type RevocationResult = z.infer<typeof RevocationResult>;
