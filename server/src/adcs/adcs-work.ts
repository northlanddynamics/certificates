// The work items by which Agents carry out an ADCS CA's operations, and what they report. None carries a secret: the Agent
// reaches ADCS as its own account (its gMSA), so the platform holds no credential to give it.
import { z } from "@hono/zod-openapi";
import { TEMPLATE_KEY_ALGORITHMS } from "./adcs-kinds";

export const ADCS_WORK_TYPES = { discover: "adcs.discover" } as const;

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
