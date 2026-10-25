import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { can, type AcmeCa, type Issuer, type Me } from "@/lib/api";
import { acmeCaName } from "@/lib/acme-cas";
import { commonNameOf } from "@/lib/private-ca";

/**
 * Where a Managed Certificate is issued from, named as `issuerLabel` names it ("<Issuing CA> · <Private CA>", or the ACME
 * CA), with the CA a link to its page for those who may open that page.
 */
export function IssuerName({ org, issuer, acmeCas }: { org: Me["organizations"][number]; issuer: Issuer; acmeCas: AcmeCa[] | undefined }) {
  if (issuer.kind === "acme") {
    return <CaLink show={can(org, "acmeAccount", "read")} to={`/organizations/${org.id}/acme-accounts`}>{acmeCaName(acmeCas, issuer.acmeCaId)}</CaLink>;
  }
  return (
    <>
      {commonNameOf(issuer.issuingCa.subject)} ·{" "}
      <CaLink show={can(org, "privateCa", "create")} to={`/organizations/${org.id}/private-cas`}>
        {issuer.privateCa.name}
      </CaLink>
    </>
  );
}

function CaLink({ show, to, children }: { show: boolean; to: string; children: ReactNode }) {
  if (!show) return <>{children}</>;
  return (
    <Link to={to} className="underline decoration-muted-foreground/40 underline-offset-4 hover:text-foreground hover:decoration-current">
      {children}
    </Link>
  );
}
