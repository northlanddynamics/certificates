import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ClockIcon } from "lucide-react";
import { useState } from "react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/page-header";
import { type ManagedCertificate } from "@/lib/api";
import { useOrg } from "@/lib/use-org";
import { ManagedCertificates } from "./managed-certificates";
import { NewManagedCertificateDialog } from "./new-managed-certificate-dialog";

export function CertificatesPage() {
  const { orgId } = useParams({ from: "/app/organizations/$orgId/certificates" });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  // A Proposal is not opened on creation: it waits for Approval, so the inventory says so, with the way to it.
  const [proposed, setProposed] = useState<ManagedCertificate | null>(null);
  const org = useOrg(orgId);
  if (!org) return <p className="text-muted-foreground">You do not belong to this Organization.</p>;
  // A proposal joins the Approval queue as well as the inventory.
  const created = async (m: ManagedCertificate) => {
    void queryClient.invalidateQueries({ queryKey: ["approvals", org.id] });
    await queryClient.invalidateQueries({ queryKey: ["inventory", org.id] });
    if (m.approval.status === "pending") setProposed(m);
    else await navigate({ to: "/organizations/$orgId/certificates/$id", params: { orgId: org.id, id: m.id } });
  };
  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Managed Certificates" action={<NewManagedCertificateDialog org={org} onCreated={created} />} />
      {proposed && (
        <Alert>
          <ClockIcon />
          <AlertTitle>Proposed {proposed.names.join(", ")}</AlertTitle>
          <AlertDescription>
            An Approver must approve it before any Certificate is issued.{" "}
            <Link to="/organizations/$orgId/certificates/$id" params={{ orgId: org.id, id: proposed.id }}>
              View the Proposal
            </Link>
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="ghost" onClick={() => setProposed(null)}>
              Dismiss
            </Button>
          </AlertAction>
        </Alert>
      )}
      <ManagedCertificates org={org} />
    </div>
  );
}
