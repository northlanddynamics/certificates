// What a Private CA publishes for relying parties: the CRL and certificate of each of its Issuing CAs and of its
// platform-made root, at public, unauthenticated routes under their ids on the platform's public base URL, which the
// certificates they sign name in their CRL Distribution Point and AIA caIssuers. An Issuing CA's CRL lists the
// Certificates it signed that were revoked and have not expired yet; the root's, its Issuing CAs that were revoked and
// have not expired yet. Each is a full CRL signed by its own CA's key in the KMS, with the next CRL number each time and `nextUpdate`
// 7 days after `thisUpdate`, kept on the CA's own row. It is reissued in the Unit of Work that revokes a Certificate, and
// by a scheduled pass (`tick`) at least 3 days before its `nextUpdate`. The routes are served over plain HTTP as well as
// HTTPS, never redirecting: a relying party must be able to check revocation without TLS, which would itself need a
// revocation check.
import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import * as x509 from "@peculiar/x509";
import { and, eq, exists, gt, isNotNull, isNull, or, sql } from "drizzle-orm";
import { makeCrl, type CrlEntry, type Publication, type Signer } from "./ca-certificates";
import { CertificateAuthorityError } from "./certificate-authority";
import type { Db, Tx } from "./db/client";
import { certificate, certificateRevocation, issuingCa, privateCa } from "./db/schema";
import type { Kms } from "./kms";
import type { CrlSigner } from "./private-ca-kinds";
import { REVOCATION_REASONS } from "./revocation-reasons";
import type { Change, UnitOfWork } from "./unit-of-work";

const DAY_MS = 24 * 60 * 60 * 1000;
/** How long a CRL is current for: its `nextUpdate` is this long after its `thisUpdate`. */
export const CRL_LIFETIME_DAYS = 7;
/** How long before its `nextUpdate` the scheduled pass reissues a CRL, at the latest. */
export const CRL_REISSUE_BEFORE_DAYS = 3;

/** A CA that publishes a CRL: one of a Private CA's Issuing CAs, by its id, or a Private CA's platform-made root, by the Private CA's. */
export type CrlIssuer = { signer: CrlSigner; id: string };

/** Where a CA publishes, under its id on the platform's public base URL: its CRL and its certificate (DER). */
export function publicationUrls(pkiBaseURL: string, { signer, id }: CrlIssuer) {
  const base = `${pkiBaseURL.replace(/\/+$/, "")}/pki/${signer === "issuing" ? "issuing-cas" : "roots"}/${id}`;
  return { crl: `${base}/ca.crl`, certificate: `${base}/ca.crt` };
}

/** What a certificate the CA signs names: where that CA's CRL and certificate are. */
export function publicationOf(pkiBaseURL: string, by: CrlIssuer): Publication {
  const urls = publicationUrls(pkiBaseURL, by);
  return { crl: urls.crl, caIssuers: urls.certificate };
}

/** A CA's latest CRL, as its row keeps it. */
type CrlColumns = { crlNumber: number | null; crlNextUpdate: Date | null; crlFailingSince: Date | null };

/** Whether a CRL whose `nextUpdate` is this is due to be reissued at `now`; one never published is. */
const isDue = (nextUpdate: Date | null, now: Date) => !nextUpdate || nextUpdate.getTime() - CRL_REISSUE_BEFORE_DAYS * DAY_MS <= now.getTime();

export interface Crls {
  /**
   * Publishes the CA's next CRL on the transaction, so that it is published if and only if the change commits: for a
   * new Private CA (its root's and its first Issuing CA's), a new Issuing CA, and a Certificate's revocation (recorded
   * first, on the same transaction), which publishes its Issuing CA's. Throws a CertificateAuthorityError
   * ("unreachable") when the KMS does not sign it.
   */
  publish(tx: Tx, change: Change, organizationId: string, by: CrlIssuer): Promise<void>;
  /**
   * One pass at the clock's time: reissues each CRL that is due (at least 3 days before its `nextUpdate`, or never
   * published) and returns how many it reissued; a retired Issuing CA's only until its last Certificate expires. It never throws for one CRL's trouble: a CRL that cannot be reissued
   * is noted as failing, and tried again on the next pass.
   */
  tick(): Promise<number>;
}

export function createCrls({ db, unitOfWork, kms, clock }: { db: Db; unitOfWork: UnitOfWork; kms: Kms; clock: () => Date }): Crls {
  /**
   * The CA, locked, so that its CRLs are numbered one at a time: what signs its CRL, what that CRL lists at `at`, its
   * latest CRL, and how to store the next; none when it publishes none (an Issuing CA without a certificate yet, a root
   * the platform does not hold).
   */
  async function lockCa(tx: Tx, organizationId: string, { signer, id }: CrlIssuer, at: Date) {
    if (signer === "root") {
      const [ca] = await tx
        .select()
        .from(privateCa)
        .where(and(eq(privateCa.organizationId, organizationId), eq(privateCa.id, id)))
        .for("update");
      if (!ca) throw new Error("the Private CA is gone");
      if (!ca.rootKey || !ca.rootCertificatePem) return undefined;
      return {
        name: `the root of the Private CA ${ca.name}`,
        privateCaId: ca.id,
        latest: ca as CrlColumns,
        signer: { key: ca.rootKey, context: organizationId, algorithm: ca.keyAlgorithm, certificate: new x509.X509Certificate(ca.rootCertificatePem) } satisfies Signer,
        // Its Issuing CAs that are revoked and not expired.
        async entries(): Promise<CrlEntry[]> {
          const rows = await tx
            .select({ certificatePem: issuingCa.certificatePem, revokedAt: issuingCa.revokedAt, reason: issuingCa.revocationReason })
            .from(issuingCa)
            .where(and(eq(issuingCa.privateCaId, ca.id), eq(issuingCa.status, "revoked")))
            .orderBy(issuingCa.revokedAt, issuingCa.id);
          return rows
            .map((r) => ({ certificate: new x509.X509Certificate(r.certificatePem!), revokedAt: r.revokedAt!, reason: REVOCATION_REASONS[r.reason!] }))
            .filter((r) => r.certificate.notAfter > at)
            .map(({ certificate, revokedAt, reason }) => ({ serial: certificate.serialNumber, revokedAt, reason }));
        },
        store: (values: Partial<typeof privateCa.$inferInsert>) => tx.update(privateCa).set(values).where(eq(privateCa.id, ca.id)),
      };
    }
    const [row] = await tx
      .select({ issuing: issuingCa, ca: privateCa })
      .from(issuingCa)
      .innerJoin(privateCa, eq(privateCa.id, issuingCa.privateCaId))
      .where(and(eq(issuingCa.organizationId, organizationId), eq(issuingCa.id, id)))
      .for("update", { of: issuingCa });
    if (!row) throw new Error("the Issuing CA is gone");
    const { issuing, ca } = row;
    if (!issuing.certificatePem) return undefined;
    return {
      name: `an Issuing CA of the Private CA ${ca.name}`,
      privateCaId: ca.id,
      latest: issuing as CrlColumns,
      signer: { key: issuing.key, context: organizationId, algorithm: ca.keyAlgorithm, certificate: new x509.X509Certificate(issuing.certificatePem) } satisfies Signer,
      // The Certificates it signed that are revoked and not expired.
      async entries(): Promise<CrlEntry[]> {
        const rows = await tx
          .select({ serial: certificate.serial, revokedAt: certificateRevocation.revokedAt, reason: certificateRevocation.reason })
          .from(certificateRevocation)
          .innerJoin(certificate, eq(certificate.id, certificateRevocation.certificateId))
          .where(and(eq(certificate.organizationId, organizationId), eq(certificate.issuingCaId, issuing.id), gt(certificate.notAfter, at)))
          .orderBy(certificateRevocation.revokedAt, certificate.serial);
        return rows.map((r) => ({ serial: r.serial, revokedAt: r.revokedAt, reason: REVOCATION_REASONS[r.reason] }));
      },
      store: (values: Partial<typeof issuingCa.$inferInsert>) => tx.update(issuingCa).set(values).where(eq(issuingCa.id, issuing.id)),
    };
  }

  /**
   * Signs and stores the CA's next CRL, unless `onlyIfDueAt` is given and it is not due then (another pass reissued it
   * meanwhile). Whether it was. When its scheduled reissue had been failing, that it is published again is an Audit Event.
   */
  async function reissue(tx: Tx, change: Change, organizationId: string, by: CrlIssuer, onlyIfDueAt?: Date) {
    const thisUpdate = clock();
    const ca = await lockCa(tx, organizationId, by, thisUpdate);
    if (!ca || (onlyIfDueAt && !isDue(ca.latest.crlNextUpdate, onlyIfDueAt))) return false;
    const nextUpdate = new Date(thisUpdate.getTime() + CRL_LIFETIME_DAYS * DAY_MS);
    const number = (ca.latest.crlNumber ?? 0) + 1;
    let crl: x509.X509Crl;
    try {
      crl = await makeCrl(kms, ca.signer, { number, thisUpdate, nextUpdate, entries: await ca.entries() });
    } catch (err) {
      throw new CertificateAuthorityError("unreachable", `the KMS did not sign the CRL of ${ca.name}: ${err instanceof Error ? err.message : String(err)}`);
    }
    await ca.store({ crlNumber: number, crlThisUpdate: thisUpdate, crlNextUpdate: nextUpdate, crlDer: Buffer.from(crl.rawData), crlFailingSince: null });
    if (ca.latest.crlFailingSince) {
      await change.audit({
        organizationId,
        action: "private_ca.crl_published",
        target: { type: "private_ca", id: ca.privateCaId },
        detail: { crl: by.signer, ...(by.signer === "issuing" && { issuingCaId: by.id }), number, failingSince: ca.latest.crlFailingSince.toISOString() },
      });
    }
    return true;
  }

  /** Notes that the CA's scheduled reissue failed at `at`, unless it was failing already. A CRL never published has none to note it on, and is simply tried again. */
  const noteFailing = ({ signer, id }: CrlIssuer, at: Date) =>
    unitOfWork.run(null, async (tx) => {
      if (signer === "root") await tx.update(privateCa).set({ crlFailingSince: at }).where(and(eq(privateCa.id, id), isNotNull(privateCa.crlNumber), isNull(privateCa.crlFailingSince)));
      else await tx.update(issuingCa).set({ crlFailingSince: at }).where(and(eq(issuingCa.id, id), isNotNull(issuingCa.crlNumber), isNull(issuingCa.crlFailingSince)));
    });

  return {
    async publish(tx, change, organizationId, by) {
      await reissue(tx, change, organizationId, by);
    },

    async tick() {
      const now = clock();
      // Every Organization's: the pass is the platform's own, and publishes each CRL under its own CA's Organization.
      const roots = await db
        .select({ id: privateCa.id, organizationId: privateCa.organizationId, nextUpdate: privateCa.crlNextUpdate })
        .from(privateCa)
        .where(isNotNull(privateCa.rootKey));
      // A retired Issuing CA publishes until its last Certificate expires, when there is nothing left for its CRL to cover.
      const unexpired = db
        .select({ one: sql`1` })
        .from(certificate)
        .where(and(eq(certificate.issuingCaId, issuingCa.id), gt(certificate.notAfter, now)));
      const issuings = await db
        .select({ id: issuingCa.id, organizationId: issuingCa.organizationId, nextUpdate: issuingCa.crlNextUpdate })
        .from(issuingCa)
        .where(and(isNotNull(issuingCa.certificatePem), or(eq(issuingCa.status, "active"), and(eq(issuingCa.status, "retired"), exists(unexpired)))));
      const due = [...roots.map((r) => ({ ...r, signer: "root" as const })), ...issuings.map((r) => ({ ...r, signer: "issuing" as const }))].filter((r) => isDue(r.nextUpdate, now));

      let reissued = 0;
      for (const { signer, id, organizationId } of due) {
        try {
          if (await unitOfWork.run(null, (tx, change) => reissue(tx, change, organizationId, { signer, id }, now))) reissued++;
        } catch (err) {
          console.error(`could not reissue the CRL of the ${signer} CA`, id, err);
          await noteFailing({ signer, id }, now).catch((noted) => console.error("could not note the failing CRL", noted));
        }
      }
      return reissued;
    },
  };
}

const PublicParams = z.object({ id: z.string().openapi({ param: { name: "id", in: "path" } }) });

/** The public, unauthenticated routes of what Private CAs publish. */
export function registerPkiRoutes({ app, db }: { app: OpenAPIHono; db: Db }) {
  /**
   * The CA with this id, whatever its Organization: these routes are public, and its id, unguessable, is all a relying
   * party has. Its certificate and CRL, either of which it may not have yet; none for what cannot be an id.
   */
  async function findPublished({ signer, id }: CrlIssuer): Promise<{ certificatePem: string | null; crlDer: Buffer | null } | undefined> {
    if (!z.uuid().safeParse(id).success) return undefined;
    if (signer === "root") {
      const [row] = await db.select({ certificatePem: privateCa.rootCertificatePem, crlDer: privateCa.crlDer }).from(privateCa).where(eq(privateCa.id, id));
      return row;
    }
    const [row] = await db.select({ certificatePem: issuingCa.certificatePem, crlDer: issuingCa.crlDer }).from(issuingCa).where(eq(issuingCa.id, id));
    return row;
  }

  for (const [signer, segment, which] of [
    ["issuing", "issuing-cas", "An Issuing CA"],
    ["root", "roots", "A Private CA's platform-made root"],
  ] as const) {
    app.openapi(
      createRoute({
        method: "get",
        path: `/pki/${segment}/{id}/ca.crl`,
        tags: ["PKI"],
        summary: `${which}'s CRL, DER`,
        description:
          "Public and unauthenticated, for relying parties: the URL is in the CRL Distribution Point of each certificate the CA signs. Served over plain HTTP as well as HTTPS, never redirecting. " +
          "A full CRL, reissued whenever a Certificate is revoked and at least 3 days before its `nextUpdate`.",
        request: { params: PublicParams },
        responses: { 200: { description: "The CRL", content: { "application/pkix-crl": { schema: z.string().openapi({ format: "binary" }) } } }, 404: { description: "No such CRL" } },
      }),
      async (c) => {
        const crl = (await findPublished({ signer, id: c.req.valid("param").id }))?.crlDer;
        if (!crl) return c.body("not found", 404);
        return c.body(new Uint8Array(crl), 200, { "content-type": "application/pkix-crl" });
      },
    );

    app.openapi(
      createRoute({
        method: "get",
        path: `/pki/${segment}/{id}/ca.crt`,
        tags: ["PKI"],
        summary: `${which}'s certificate, DER`,
        description: "Public and unauthenticated, for relying parties: the URL is in the AIA caIssuers of each certificate the CA signs. Served over plain HTTP as well as HTTPS, never redirecting.",
        request: { params: PublicParams },
        responses: { 200: { description: "The certificate", content: { "application/pkix-cert": { schema: z.string().openapi({ format: "binary" }) } } }, 404: { description: "No such certificate" } },
      }),
      async (c) => {
        const pem = (await findPublished({ signer, id: c.req.valid("param").id }))?.certificatePem;
        if (!pem) return c.body("not found", 404);
        return c.body(new Uint8Array(new x509.X509Certificate(pem).rawData), 200, { "content-type": "application/pkix-cert" });
      },
    );
  }
}
