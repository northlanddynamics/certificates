// An Organization's Managed Certificates: created by an Organization Administrator with names, a key algorithm and a
// CSR (Key Custody: Owner), issued in the background (issuance.ts) and downloaded once a Certificate exists
// (certificate-export.ts). The platform never sees the private key (ADR 0002): the CSR proves the Owner holds it.
// Anyone else proposes one instead; it waits in the Approval queue (approval.ts) and its Issuance starts when an
// Approver approves it. It may have Owners (owners.ts), who with Approvers and Organization Administrators are the
// ones who see it (see managed-certificate-reader.ts). An Organization may require a Certificate Profile of those who
// propose (certificate-profile-settings.ts). A user's API key may create or propose one as its person may. This module
// serves the inventory and the Managed Certificate itself.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import { and, asc, desc, eq } from "drizzle-orm";
import { silentSince } from "../agents/agents";
import type { ApiKeys } from "../tenancy/api-keys";
import type { Authorizer } from "../tenancy/authorization";
import { AcmeCaId, type AcmeCas } from "../issuance/acme/acme-cas";
import { certificateFacts } from "../pki/certificate-facts";
import { KEY_ALGORITHMS } from "../pki/csr";
import type { Db } from "../platform/db/client";
import { issuance, managedCertificate } from "../platform/db/schema";
import { HttpError, OrgParam, PageQuery, errors, json, pageOf } from "../platform/http";
import { issuerAuditDetail, issuerColumns } from "../issuance/issuer";
import { InventoryQuery, inventoryCondition } from "./inventory-filters";
import { refusalError, type Issuances } from "../issuance/issuance";
import { Certificate, CertificateFacts, Issuance, ManagedCertificate, ManagedCertificateParams, RenewalPolicy, toCertificate, toIssuance, type ManagedCertificateReader } from "./managed-certificate-reader";
import { requestedThrough } from "./certificate-profiles";
import { certificateProfileSettingsOf, profileRequiredRefusal } from "./certificate-profile-settings";
import { profileNamesRefusal } from "./profile-name-rules";
import { checkNamesAndCsr, csrField, namesField } from "./names-and-csr";
import { OwnerRef, addOwner } from "./owners";
import { carries, roleCan, type Permissions } from "../tenancy/permissions";
import { IssuerField, issuerAsked, issuerRefusal, validityDaysField } from "../private-ca/private-ca";
import { revocationsOf } from "../issuance/revocation";
import type { Actor, UnitOfWork } from "../platform/unit-of-work";

const MAX_OWNERS = 50;

export function registerManagedCertificates(ctx: {
  app: OpenAPIHono;
  db: Db;
  requireUser(c: any): Promise<Actor>;
  authorize: Authorizer["authorize"];
  /** Who is asking when a Managed Certificate is created: a person, or an API key (api-keys.ts). */
  apiKeys: ApiKeys;
  unitOfWork: UnitOfWork;
  issuances: Issuances;
  reader: ManagedCertificateReader;
  acmeCas: AcmeCas;
  clock: () => Date;
  /** How long an Agent may be silent before it counts as offline, for the inventory's `agentOffline` filter. */
  agentOfflineAfterSeconds: number;
}) {
  const { app, db, requireUser, authorize, apiKeys, unitOfWork, issuances, reader, acmeCas, clock, agentOfflineAfterSeconds } = ctx;
  const { findManagedCertificate, findReadable, visibleTo, certificatesOf, withState } = reader;

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "The inventory: the Managed Certificates the caller may see",
      description:
        "Everyone in the Organization may ask. Organization Administrators and Approvers see every Managed Certificate; anyone else sees those they own, directly or through a Team, and those they proposed. " +
        "Archived ones are left out unless `archived` is given. The filters combine, and narrow what the caller sees. " +
        "It is listed oldest first, a page at a time; `total` is how many match the filters, whatever the page.",
      request: { params: OrgParam, query: InventoryQuery.extend(PageQuery.shape) },
      responses: { 200: json(pageOf(ManagedCertificate)), ...errors(400, 401, 404) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const actor = await requireUser(c);
      const { role } = await authorize(actor, orgId);
      const query = c.req.valid("query");
      const now = clock();
      const where = and(visibleTo(role, actor, orgId), inventoryCondition(query, { now, agentsSilentSince: silentSince(now, agentOfflineAfterSeconds) }));
      const [total, rows] = await Promise.all([
        db.$count(managedCertificate, where),
        db
          .select()
          .from(managedCertificate)
          .where(where)
          .orderBy(asc(managedCertificate.createdAt), asc(managedCertificate.id))
          .limit(query.pageSize)
          .offset((query.page - 1) * query.pageSize),
      ]);
      return c.json({ items: await withState(rows), total, page: query.page, pageSize: query.pageSize }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates",
      tags: ["Managed Certificates"],
      summary: "Create a Managed Certificate and start issuing its first Certificate, or propose one for Approval",
      description:
        "The Owner keeps the private key and submits a CSR for it. The CSR must be for the key algorithm given and ask for exactly the names given. " +
        "An Organization Administrator creates it outright and Issuance starts at once; anyone else proposes it, and it waits for an Approver to approve it, which starts Issuance. " +
        "Issuance runs in the background: the response shows it running, and the Managed Certificate shows the Certificate or the cause of the failure when it ends. " +
        "Its issuer is an ACME CA (Let's Encrypt Staging unless `acmeCaId` says otherwise; 422 for one the Organization cannot use) or, given `issuer`, an active Issuing CA of one of the Organization's Private CAs, which issues with no DCV. " +
          "Names outside the Issuing CA's permitted name rules are refused with 422, which names them, as is a `validityDays` above its maximum; `validityDays` with an ACME CA is refused with 400. " +
        "Given `profileId`, a Certificate Profile of the Organization fixes its issuer, validity and Renewal Policy, which are copied onto it, so giving `issuer`, `acmeCaId`, `validityDays` or `renewalPolicy` too is refused with 400. " +
        "The key algorithm must be one the profile allows, and the profile must be enabled and its issuer still usable (an ACME CA the Organization has an ACME Account with, or an active Issuing CA), or it is refused with 422; the issuer's own checks then apply as above. " +
        "A non-administrator's names must keep to the profile's name rules as they are now (422, naming the names that do not); an Organization Administrator is held only to the issuer's limits. " +
        "The requester and the profile's default Team become Owners, with any Owners named. " +
        "While the Organization requires a Certificate Profile, a request without `profileId` from whoever may not create one outright is refused with 403. " +
        "As a person signed in, or with a user's API key in the `x-api-key` header, which may do what both its person may now and it carries; an Organization's key may not.",
      request: {
        params: OrgParam,
        body: {
          content: {
            "application/json": {
              schema: z.object({
                names: namesField("The DNS names to issue for."),
                keyAlgorithm: z.enum(KEY_ALGORITHMS).openapi({
                  description: "The algorithm of the Owner's key, which the CSR is for. ML-DSA ones only on an ML-DSA Private CA, and only those there (422 otherwise): a chain is all ML-DSA or none of it. A Private CA's `certificateKeyAlgorithms` lists what it takes.",
                }),
                csr: csrField,
                acmeCaId: AcmeCaId.optional().openapi({ description: "Which ACME CA to issue from, through the Organization's ACME account with it, when `issuer` is not given; Let's Encrypt Staging unless given." }),
                issuer: IssuerField.optional(),
                validityDays: validityDaysField
                  .optional()
                  .openapi({ description: "For a Private CA issuer only: how many days its Certificates are valid for, at most the Issuing CA's maximum; its default when not given." }),
                owners: z.array(OwnerRef).max(MAX_OWNERS).default([]).openapi({ description: "Users and Teams of the Organization accountable for it; none is allowed." }),
                renewalPolicy: RenewalPolicy.optional().openapi({ description: "The Renewal Policy it starts with: automatic, 30 days before expiry, unless given." }),
                profileId: z.string().optional().openapi({ description: "The Certificate Profile it is requested through, which fixes its issuer, validity and Renewal Policy." }),
              }),
            },
          },
        },
      },
      responses: { 201: json(ManagedCertificate, "Created with its first Issuance running, or proposed and awaiting Approval"), ...errors(400, 401, 403, 404, 422) },
    }),
    async (c) => {
      const { orgId } = c.req.valid("param");
      const body = c.req.valid("json");
      const caller = await apiKeys.callerOf(c);
      const create: Permissions = { managedCertificate: ["create"] };
      // An Organization's key acts as no one, so nobody would propose or own what it made; it carries no `create` either.
      if (!caller.user) {
        await apiKeys.authorizeCaller(caller, orgId, create);
        throw new HttpError(403, "not permitted");
      }
      const actor = caller.user;
      const { role } = await authorize(actor, orgId);
      // Who may create outright needs no Approval; everyone else must be allowed to propose. A key may only what its person may and it carries.
      const needsApproval = !roleCan(role, create) || (caller.apiKey !== null && !carries(caller.apiKey.permissions, create));
      await apiKeys.authorizeCaller(caller, orgId, needsApproval ? { managedCertificate: ["propose"] } : create);
      if (needsApproval && body.profileId === undefined && (await certificateProfileSettingsOf(db, orgId)).requireProfile) throw profileRequiredRefusal();

      // A profile fixes what it is issued with, so a request through one may not choose any of it too.
      const chosen = (["issuer", "acmeCaId", "validityDays", "renewalPolicy"] as const).filter((field) => body[field] !== undefined);
      if (body.profileId !== undefined && chosen.length > 0) throw new HttpError(400, `a Certificate Profile fixes ${chosen.map((field) => `\`${field}\``).join(", ")}; give none with \`profileId\``);
      const through = body.profileId === undefined ? undefined : await requestedThrough(db, acmeCas, orgId, body.profileId, body.keyAlgorithm);

      const { names, csr } = await checkNamesAndCsr(body);
      let issuer;
      if (through) {
        // A non-administrator keeps to the profile's name rules as they are now; everyone to the issuer's limits after them.
        const outside = needsApproval ? profileNamesRefusal(through.profile.name, through.nameRules, names) : undefined;
        if (outside) throw new HttpError(422, outside);
        const refusal = await issuerRefusal(db, orgId, through.issuer, { names, validityDays: through.validityDays, keyAlgorithm: body.keyAlgorithm });
        if (refusal) throw new HttpError(refusal.status, refusal.message);
        issuer = through.issuer;
      } else {
        issuer = await issuerAsked(db, acmeCas, orgId, body, names);
      }
      const validityDays = through ? through.validityDays : (body.validityDays ?? null);
      const renewalPolicy = through?.renewalPolicy ?? body.renewalPolicy;

      const created = await unitOfWork.run(actor, async (tx, change) => {
        const [row] = await tx
          .insert(managedCertificate)
          .values({
            organizationId: orgId,
            names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            ...issuerColumns(issuer),
            validityDays,
            csr: body.csr,
            ...(renewalPolicy && { renewalMode: renewalPolicy.mode, renewalDaysBeforeExpiry: renewalPolicy.daysBeforeExpiry }),
            certificateProfileId: through?.profile.id ?? null,
            ...(needsApproval && { approvalStatus: "pending", proposedById: actor.id, proposedByEmail: actor.email }),
          })
          .returning();
        await change.audit({
          organizationId: orgId,
          action: needsApproval ? "managed_certificate.proposed" : "managed_certificate.created",
          target: { type: "managed_certificate", id: row!.id },
          detail: {
            names,
            keyAlgorithm: body.keyAlgorithm,
            keyCustody: "owner",
            ...issuerAuditDetail(issuer, validityDays ?? undefined),
            csrFingerprint: csr.fingerprint,
            ...(renewalPolicy && { renewalPolicy }),
            ...(through && { certificateProfile: through.profile }),
          },
        });
        // Whoever requests through a profile owns what they asked for, with the profile's default Team.
        const owners: OwnerRef[] = [
          ...(through ? [{ type: "user" as const, id: actor.id }] : []),
          ...(through?.defaultTeamId ? [{ type: "team" as const, id: through.defaultTeamId }] : []),
          ...body.owners,
        ];
        // Whoever creates or proposes may name the Owners at the same time; each is audited as added (naming one twice adds it once).
        for (const ref of owners) await addOwner(tx, change, orgId, row!.id, ref);
        // A proposal is issued only once approved.
        if (!needsApproval) {
          const begun = await issuances.begin(tx, change, actor, row!, "issue");
          // Its Certificate Profile may have been disabled since it was checked.
          if ("refused" in begun) throw begun.refused === "profile_disabled" ? refusalError(begun, "issue") : new Error(`the Issuance of a Managed Certificate just created was refused: ${begun.refused}`);
        }
        return row!;
      });
      return c.json((await withState([created]))[0]!, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}",
      tags: ["Managed Certificates"],
      request: { params: ManagedCertificateParams },
      responses: { 200: json(ManagedCertificate), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      return c.json((await withState([await findReadable(await requireUser(c), orgId, id)]))[0]!, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuances",
      tags: ["Managed Certificates"],
      summary: "Every attempt to issue a Certificate for the Managed Certificate, the newest first",
      description: "Each with its kind (first issue, Renewal, Name Change), status and failure, so a failure a later attempt cleared can still be explained.",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(Issuance) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const rows = await db
        .select()
        .from(issuance)
        .where(and(eq(issuance.organizationId, orgId), eq(issuance.managedCertificateId, mc.id)))
        .orderBy(desc(issuance.startedAt), desc(issuance.createdAt));
      return c.json({ items: rows.map(toIssuance) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/issuances",
      tags: ["Managed Certificates"],
      summary: "Try issuing a Certificate again",
      description: "For when the last Issuance failed. It reuses the Managed Certificate's CSR. Only one runs at a time. Refused (422) while the Certificate Profile it was made from is disabled.",
      request: { params: ManagedCertificateParams },
      responses: { 202: json(Issuance, "Started"), ...errors(401, 403, 404, 409, 422) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const actor = await requireUser(c);
      await authorize(actor, orgId, { managedCertificate: ["issue"] });
      const mc = await findManagedCertificate(orgId, id);
      const begun = await unitOfWork.run(actor, (tx, change) => issuances.begin(tx, change, actor, mc, "issue"));
      if ("refused" in begun) throw refusalError(begun, "issue");
      const [row] = await db.select().from(issuance).where(eq(issuance.id, begun.issuanceId));
      return c.json(toIssuance(row!), 202);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates",
      tags: ["Managed Certificates"],
      summary: "Every Certificate issued for the Managed Certificate, the newest first",
      request: { params: ManagedCertificateParams },
      responses: { 200: json(z.object({ items: z.array(Certificate) })), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const rows = await certificatesOf(orgId, mc.id);
      const revocations = await revocationsOf(db, rows.map((row) => row.id));
      return c.json({ items: rows.map((row) => toCertificate(row, revocations.get(row.id))) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/api/organizations/{orgId}/managed-certificates/{id}/certificates/{certificateId}",
      tags: ["Managed Certificates"],
      summary: "One Certificate of the Managed Certificate, with everything it says about itself",
      description:
        "Its subject and names, issuer, serial, signature algorithm, the chain the CA served (leaf first), the CA and ACME Account it was issued through, and its revocation if any. " +
        "Whoever may see the Managed Certificate may see its Certificates; a Certificate of another Managed Certificate is not found.",
      request: { params: ManagedCertificateParams.extend({ certificateId: z.string().openapi({ param: { name: "certificateId", in: "path" } }) }) },
      responses: { 200: json(CertificateFacts), ...errors(401, 403, 404) },
    }),
    async (c) => {
      const { orgId, id, certificateId } = c.req.valid("param");
      const mc = await findReadable(await requireUser(c), orgId, id);
      const row = (await certificatesOf(orgId, mc.id)).find((r) => r.id === certificateId);
      if (!row) throw new HttpError(404, "Certificate not found");
      const revocations = await revocationsOf(db, [row.id]);
      return c.json({ ...toCertificate(row, revocations.get(row.id)), ...certificateFacts(row.chainPem), acmeAccount: row.acmeAccountId && row.acmeCaId ? { id: row.acmeAccountId, acmeCaId: row.acmeCaId } : null }, 200);
    },
  );
}
