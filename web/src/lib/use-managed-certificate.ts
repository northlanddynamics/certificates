import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "@/lib/api";

/** Everything that is read for one Managed Certificate's page starts with this key, so one refresh covers its tabs. */
const managedCertificateKey = (orgId: string, id: string) => ["managed-certificate", orgId, id] as const;

/** What a Managed Certificate's page needs from the platform: who is looking, at which Organization, and the Managed Certificate itself. */
export function useManagedCertificatePage(orgId: string, id: string) {
  const queryClient = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const certificate = useQuery({
    queryKey: managedCertificateKey(orgId, id),
    queryFn: () => api.managedCertificate(orgId, id),
    // Issuance runs in the background: look again until none is running.
    refetchInterval: (query) => (query.state.data?.issuance?.status === "running" ? 2000 : false),
    // A missing one, or one that may not be seen, is the same answer: asking again does not change it.
    retry: (count, error) => !(error instanceof ApiError) && count < 2,
  });
  // A change to one may change the others: a proposal joins the queue, a decision leaves it, and the inventory shows the same facts.
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["approvals", orgId] });
    void queryClient.invalidateQueries({ queryKey: ["inventory", orgId] });
    return queryClient.invalidateQueries({ queryKey: managedCertificateKey(orgId, id) });
  };
  return { org: me.data?.organizations.find((o) => o.id === orgId), userId: me.data?.user.id, me, certificate, refresh };
}

/**
 * Every Certificate of the Managed Certificate, the newest first. `currentId` is its current Certificate as last read:
 * when an Issuance ends with a new one, the list is read again.
 */
export const useCertificates = (orgId: string, id: string, currentId: string | undefined) =>
  useQuery({ queryKey: [...managedCertificateKey(orgId, id), "certificates", { currentId }], queryFn: () => api.certificates(orgId, id) });

/** One Certificate with everything it says about itself; none is asked for until `certificateId` is given. */
export const useCertificateFacts = (orgId: string, id: string, certificateId: string | undefined) =>
  useQuery({
    queryKey: [...managedCertificateKey(orgId, id), "certificates", certificateId],
    queryFn: () => api.certificate(orgId, id, certificateId!),
    enabled: Boolean(certificateId),
  });
