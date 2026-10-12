import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import type { ManagedCertificate } from "@/lib/api";

/** Whether `userId` is one of the Managed Certificate's Owners directly (a Team's members may be Owners too, which the server decides). */
export const isOwner = (m: ManagedCertificate, userId?: string) => m.owners.some((o) => o.type === "user" && o.id === userId);

export const keyAlgorithmLabel = (value: string) => KEY_ALGORITHM_LABELS[value as KeyAlgorithm] ?? value;

/** What a Managed Certificate's latest Issuance has come to, in a word, and how loudly to say it. */
export function status(m: ManagedCertificate): { label: string; variant: "default" | "secondary" | "destructive" | "outline" } {
  if (m.archivedAt) return { label: "Archived", variant: "secondary" };
  if (m.approval.status === "pending") return { label: "Awaiting Approval", variant: "outline" };
  if (m.approval.status === "rejected") return { label: "Rejected", variant: "destructive" };
  if (m.issuance?.status === "running") return { label: m.currentCertificate ? "Renewing…" : "Issuing…", variant: "secondary" };
  if (m.renewal.failing) return { label: "Renewal failing", variant: "destructive" };
  if (m.issuance?.status === "failed") return { label: "Issuance failed", variant: "destructive" };
  return m.currentCertificate ? { label: "Issued", variant: "default" } : { label: "Not issued", variant: "outline" };
}
