// The Dashboard: what needs doing across the Managed Certificates the caller sees, in one answer. Its counts are the
// inventory's own filters (inventory-filters.ts), so each matches the inventory narrowed by that filter; what it adds is
// the list of those needing someone now, when Certificates end in the weeks ahead, and which CAs they come from.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, eq, or, sql } from "drizzle-orm";
import { silentSince } from "../agents/agents";
import type { Authorizer } from "../tenancy/authorization";
import type { Db } from "../platform/db/client";
import { adcsCa, certificate, issuance, issuingCa, managedCertificate, privateCa } from "../platform/db/schema";
import { OrgParam, errors, json } from "../platform/http";
import { ISSUER_KINDS } from "../issuance/issuer-kinds";
import { INVENTORY_FILTERS, currentCertificateEnds, inventoryCondition, type InventoryContext } from "./inventory-filters";
import { ManagedCertificate, type ManagedCertificateReader } from "./managed-certificate-reader";
import type { Actor } from "../platform/unit-of-work";

const DAY = 86_400_000;
/** How many weeks ahead the expiry outlook looks. */
export const EXPIRY_WEEKS = 13;
/** How many of those needing attention are listed; `total` says how many there are. */
const ATTENTION_LISTED = 10;

/** The inventory's filters the Dashboard counts. */
const COUNTED = ["expiringSoon", "renewalFailing", "agentOffline", "pendingApproval"] as const;
type Counts = Record<"managed" | (typeof COUNTED)[number], number>;

/** Never issued: it has no Certificate, and its latest Issuance failed. */
const firstIssuanceFailed = sql`not exists (select 1 from ${certificate} where ${certificate.managedCertificateId} = ${managedCertificate.id}) and (select ${issuance.status} from ${issuance} where ${issuance.managedCertificateId} = ${managedCertificate.id} order by ${issuance.createdAt} desc, ${issuance.id} desc limit 1) = 'failed'`;

/**
 * What needs someone now: a Renewal failing, an Agent holding its key offline, a first Issuance that failed, a
 * Certificate whose renewal window has opened that only a person renews (its Renewal is manual), or one that has ended.
 * The window is in seconds, as the Renewal scheduler's is, so that a day interval does not follow the session's time zone.
 */
const needsAttention = (at: InventoryContext) =>
  or(
    INVENTORY_FILTERS.renewalFailing.where("true", at),
    INVENTORY_FILTERS.agentOffline.where("true", at),
    firstIssuanceFailed,
    and(eq(managedCertificate.renewalMode, "manual"), sql`${currentCertificateEnds} - make_interval(secs => ${managedCertificate.renewalDaysBeforeExpiry} * 86400) <= ${at.now}`),
    sql`${currentCertificateEnds} <= ${at.now}`,
  )!;

const Dashboard = z.object({
  counts: z
    .object({
      managed: z.number().int().openapi({ description: "Every Managed Certificate the caller sees, archived ones aside." }),
      expiringSoon: z.number().int(),
      renewalFailing: z.number().int(),
      agentOffline: z.number().int(),
      pendingApproval: z.number().int(),
    })
    .openapi({ description: "How many match each of the inventory's filters of the same name, within what the caller sees; archived ones are left out." }),
  attention: z.object({
    items: z.array(ManagedCertificate).openapi({ description: `Up to ${ATTENTION_LISTED} of them, those with no Certificate first, then the soonest to end.` }),
    total: z.number().int(),
  }).openapi({
    description: "The Managed Certificates that need someone now: a Renewal failing, the Agent that holds the key offline, a first Issuance that failed, a Certificate whose renewal window has opened under a manual Renewal Policy, or one that has ended.",
  }),
  expiry: z
    .array(z.object({ start: z.string(), automatic: z.number().int(), manual: z.number().int() }))
    .openapi({ description: `The next ${EXPIRY_WEEKS} weeks from now, each with how many current Certificates end in it, by the Renewal Policy of their Managed Certificate.` }),
  issuers: z
    .array(
      z.object({
        kind: z.enum(ISSUER_KINDS),
        id: z.string().openapi({ description: "The ACME CA's id, the Private CA's or the ADCS CA's." }),
        name: z.string().nullable().openapi({ description: "The Private CA's or ADCS CA's name; none for an ACME CA, which `id` names." }),
        count: z.number().int(),
      }),
    )
    .openapi({ description: "How many Managed Certificates are issued from each CA, the most first; a Private CA's Issuing CAs count as one." }),
});

export function registerDashboard(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  reader: ManagedCertificateReader;
  clock: () => Date;
  agentOfflineAfterSeconds: number;
}) {
  const { app, db, requireUser, authorize, reader, clock, agentOfflineAfterSeconds } = ctx;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/dashboard",
      tags: ["Managed Certificates"],
      summary: "The Dashboard: what needs doing across the Managed Certificates the caller sees",
      description:
        "Everyone in the Organization may ask, and sees it for what they see in the inventory: Organization Administrators and Approvers for every Managed Certificate, anyone else for those they own or proposed. Archived ones are left out.",
      request: { params: OrgParam },
      responses: { 200: json(Dashboard), ...errors(401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const now = clock();
      const at = { now, agentsSilentSince: silentSince(now, agentOfflineAfterSeconds) };
      const visible = reader.visibleTo(role, actor, orgId);
      const live = and(visible, inventoryCondition({}, at))!;
      const attention = and(live, needsAttention(at))!;
      const horizon = new Date(now.getTime() + EXPIRY_WEEKS * 7 * DAY);

      const [managed, counted, attentionTotal, attentionRows, ending, issuers] = await Promise.all([
        db.$count(managedCertificate, live),
        Promise.all(COUNTED.map((name) => db.$count(managedCertificate, and(visible, inventoryCondition({ [name]: "true" }, at))))),
        db.$count(managedCertificate, attention),
        db
          .select()
          .from(managedCertificate)
          .where(attention)
          .orderBy(sql`${currentCertificateEnds} asc nulls first`, asc(managedCertificate.createdAt), asc(managedCertificate.id))
          .limit(ATTENTION_LISTED),
        db
          .select({ mode: managedCertificate.renewalMode, ends: sql<string>`${currentCertificateEnds}` })
          .from(managedCertificate)
          .where(and(live, sql`${currentCertificateEnds} > ${now}`, sql`${currentCertificateEnds} <= ${horizon}`)),
        db
          .select({
            kind: managedCertificate.issuerKind,
            acmeCaId: managedCertificate.acmeCaId,
            privateCaId: issuingCa.privateCaId,
            privateCaName: privateCa.name,
            adcsCaId: managedCertificate.adcsCaId,
            adcsCaName: adcsCa.name,
            count: sql<number>`count(*)::int`,
          })
          .from(managedCertificate)
          .leftJoin(issuingCa, eq(issuingCa.id, managedCertificate.issuingCaId))
          .leftJoin(privateCa, eq(privateCa.id, issuingCa.privateCaId))
          .leftJoin(adcsCa, eq(adcsCa.id, managedCertificate.adcsCaId))
          .where(live)
          .groupBy(managedCertificate.issuerKind, managedCertificate.acmeCaId, issuingCa.privateCaId, privateCa.name, managedCertificate.adcsCaId, adcsCa.name),
      ]);

      const expiry = Array.from({ length: EXPIRY_WEEKS }, (_, week) => ({ start: new Date(now.getTime() + week * 7 * DAY).toISOString(), automatic: 0, manual: 0 }));
      for (const { mode, ends } of ending) {
        const week = Math.min(EXPIRY_WEEKS - 1, Math.floor((new Date(ends).getTime() - now.getTime()) / (7 * DAY)));
        expiry[week]![mode]++;
      }

      return c.json(
        {
          counts: { managed, ...Object.fromEntries(COUNTED.map((name, i) => [name, counted[i]!])) } as Counts,
          attention: { items: await reader.withState(attentionRows), total: attentionTotal },
          expiry,
          // Grouped by Private CA, so its Issuing CAs count as one.
          issuers: issuers
            .map((row) =>
              row.kind === "private_ca"
                ? { kind: row.kind, id: row.privateCaId ?? "", name: row.privateCaName, count: row.count }
                : row.kind === "adcs"
                  ? { kind: row.kind, id: row.adcsCaId ?? "", name: row.adcsCaName, count: row.count }
                  : { kind: row.kind, id: row.acmeCaId ?? "", name: null, count: row.count },
            )
            .sort((a, b) => b.count - a.count),
        },
        200,
      );
    },
  );
}
