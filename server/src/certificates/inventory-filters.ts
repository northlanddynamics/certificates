// The inventory's filters, each a query parameter that narrows the Managed Certificates listed. A filter is one entry
// here: how its value is read, and the condition it adds. Filters combine (all must hold), and apply within what the
// caller may see.
import { z } from "@hono/zod-openapi";
import { and, eq, inArray, isNotNull, isNull, sql, type SQL } from "drizzle-orm";
import { ACME_ENVIRONMENTS, type AcmeEnvironment } from "../issuance/acme/certificate-authority";
import { KEY_ALGORITHMS, KEY_CUSTODIES, type KeyAlgorithm } from "../pki/csr";
import { agent, certificate, deployment, issuance, managedCertificate } from "../platform/db/schema";
import { agentOffline } from "../agents/agents";
import { anyOf } from "../platform/http";
import { hasNoOwners } from "./owners";

/** How close to the end of its current Certificate a Managed Certificate is "expiring soon". */
const EXPIRING_SOON_DAYS = 30;

/** What the filters are applied as of: the time, and since when an Agent that has not been in touch is offline. */
export interface InventoryContext {
  now: Date;
  agentsSilentSince: Date;
}

type Filter = {
  schema: z.ZodType;
  /** The condition when the parameter is given. */
  where(value: unknown, at: InventoryContext): SQL;
  /** The condition when it is not, for a filter that also decides what is shown by default. */
  whenAbsent?(at: InventoryContext): SQL;
};
const filter = <S extends z.ZodType>(schema: S, where: (value: z.output<S>, at: InventoryContext) => SQL, whenAbsent?: (at: InventoryContext) => SQL): Filter => ({
  schema,
  where: where as Filter["where"],
  whenAbsent,
});

/** A switch: given as `true`, it applies; anything else is refused. */
const on = z.literal("true");

const currentCertificateEnds = sql`(select ${certificate.notAfter} from ${certificate} where ${certificate.managedCertificateId} = ${managedCertificate.id} order by ${certificate.createdAt} desc, ${certificate.id} desc limit 1)`;

/** Has a Certificate, and an Issuance has failed since the last that succeeded, which is then a Renewal: what `renewal.failing` on the Managed Certificate says. */
const renewalFailing = sql`exists (select 1 from ${certificate} where ${certificate.managedCertificateId} = ${managedCertificate.id}) and exists (select 1 from ${issuance} where ${issuance.managedCertificateId} = ${managedCertificate.id} and ${issuance.status} = 'failed' and ${issuance.createdAt} > coalesce((select max(s.created_at) from ${issuance} as s where s.managed_certificate_id = ${managedCertificate.id} and s.status = 'succeeded'), '-infinity'::timestamptz))`;

export const INVENTORY_FILTERS = {
  expiringSoon: filter(on.meta({ description: `Whose current Certificate ends within ${EXPIRING_SOON_DAYS} days, or has ended.` }), (_, { now }) => {
    const threshold = new Date(now.getTime() + EXPIRING_SOON_DAYS * 86_400_000);
    return sql`${currentCertificateEnds} <= ${threshold}`;
  }),
  renewalFailing: filter(on.meta({ description: "Whose Renewal is failing: one has failed since its last Certificate was issued." }), () => renewalFailing),
  agentOffline: filter(
    on.meta({ description: "Whose key is held by an Agent that is offline, so that its Renewal waits for the Agent to be back." }),
    (_, { agentsSilentSince }) =>
      sql`exists (select 1 from ${deployment} inner join ${agent} on ${agent.id} = ${deployment.agentId} where ${deployment.managedCertificateId} = ${managedCertificate.id} and ${agentOffline(agentsSilentSince)})`,
  ),
  pendingApproval: filter(on.meta({ description: "Proposals waiting for Approval." }), () => eq(managedCertificate.approvalStatus, "pending")),
  noOwners: filter(on.meta({ description: "Managed Certificates with no Owners." }), () => hasNoOwners()),
  keyCustody: filter(z.enum(KEY_CUSTODIES).meta({ description: "Whose private key is held this way." }), (value) => eq(managedCertificate.keyCustody, value)),
  environment: filter(anyOf(ACME_ENVIRONMENTS).meta({ description: "Issued through one of these ACME environments, comma-separated." }), (value) => inArray(managedCertificate.environment, value.split(",") as unknown as AcmeEnvironment[])),
  keyAlgorithm: filter(anyOf(KEY_ALGORITHMS).meta({ description: "Whose key is of one of these algorithms, comma-separated." }), (value) => inArray(managedCertificate.keyAlgorithm, value.split(",") as unknown as KeyAlgorithm[])),
  archived: filter(
    on.meta({ description: "Only archived Managed Certificates, which are otherwise left out." }),
    () => isNotNull(managedCertificate.archivedAt),
    () => isNull(managedCertificate.archivedAt),
  ),
} satisfies Record<string, Filter>;

export const InventoryQuery = z.object(
  Object.fromEntries(Object.entries(INVENTORY_FILTERS).map(([name, f]) => [name, f.schema.optional()])) as {
    [K in keyof typeof INVENTORY_FILTERS]: z.ZodOptional<(typeof INVENTORY_FILTERS)[K]["schema"]>;
  },
);

/** The condition the filters given in `query` add to the inventory, as of `at`. */
export function inventoryCondition(query: Record<string, unknown>, at: InventoryContext): SQL {
  const conditions = Object.entries(INVENTORY_FILTERS).map(([name, f]) => {
    const value = query[name];
    return value === undefined ? f.whenAbsent?.(at) : f.where(value, at);
  });
  return and(...conditions) ?? sql`true`;
}
