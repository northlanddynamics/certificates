import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "@/lib/csr-generator";
import type { AcmeCa, Issuance, Issuer, ManagedCertificate } from "@/lib/api";
import { acmeCaName } from "@/lib/acme-cas";
import { issuingCaTitle } from "@/lib/private-ca";
import { expiryTone } from "@/lib/renewal-urgency";

/** A status badge's variant: well, wanting attention soon, at fault, or of no concern. */
export type StatusVariant = "success" | "warning" | "destructive" | "neutral";

/** Whether `userId` is one of the Managed Certificate's Owners directly (a Team's members may be Owners too, which the server decides). */
export const isOwner = (m: ManagedCertificate, userId?: string) => m.owners.some((o) => o.type === "user" && o.id === userId);

export const keyAlgorithmLabel = (value: string) => KEY_ALGORITHM_LABELS[value as KeyAlgorithm] ?? value;

/** What a Managed Certificate's latest Issuance has come to, in a word, and how loudly to say it. */
export function status(m: ManagedCertificate, now = new Date()): { label: string; variant: StatusVariant } {
  if (m.archivedAt) return { label: "Archived", variant: "neutral" };
  if (m.approval.status === "pending") return { label: "Awaiting Approval", variant: "warning" };
  if (m.approval.status === "rejected") return { label: "Rejected", variant: "destructive" };
  // A Renewal waiting for an Agent that is away is held up until it is back.
  if (m.issuance?.awaitingKey && m.agent?.status === "offline") return { label: "Agent offline", variant: "destructive" };
  if (m.issuance?.status === "running") return { label: m.currentCertificate ? "Renewing…" : "Issuing…", variant: "warning" };
  if (m.renewal.blocked) return { label: "Renewal blocked", variant: "destructive" };
  if (m.renewal.failing) return { label: "Renewal failing", variant: "destructive" };
  if (m.issuance?.status === "failed") return { label: "Issuance failed", variant: "destructive" };
  if (m.agent?.status === "revoked") return { label: "Agent revoked", variant: "destructive" };
  if (m.agent?.status === "offline") return { label: "Agent offline", variant: "warning" };
  if (!m.currentCertificate) return { label: "Not issued", variant: "neutral" };
  // Issued: well until its renewal window opens, then wanting attention, and at fault once it has ended or been revoked.
  const tone = expiryTone(m, now);
  if (tone === "danger") return { label: m.currentCertificate.revocation ? "Revoked" : "Expired", variant: "destructive" };
  return { label: "Issued", variant: tone === "warning" ? "warning" : "success" };
}

const CA_LABELS: Record<string, string> = { "lets-encrypt": "Let's Encrypt" };
/** A CA by the name people know it by, from its name in the API. */
export const caLabel = (ca: string) => CA_LABELS[ca] ?? ca;

/** The Certificate Profile it was requested through, by name, and whether it is disabled. */
export const profileLabel = (profile: NonNullable<ManagedCertificate["profile"]>) => (profile.enabled ? profile.name : `${profile.name} (disabled)`);

/** Where a Managed Certificate is issued from, in a few words: an ACME CA by name (from `acmeCas`, the Organization's), or an Issuing CA with its Private CA. */
export const issuerLabel = (issuer: Issuer, acmeCas: AcmeCa[] | undefined) =>
  issuer.kind === "acme" ? acmeCaName(acmeCas, issuer.acmeCaId) : issuingCaTitle(issuer.privateCa.name, issuer.issuingCa.subject);

/** What an Issuance attempt was for, as a sentence starts. */
export const ISSUANCE_KIND_WORDS: Record<Issuance["kind"], string> = {
  first_issue: "First Issuance",
  renewal: "Renewal",
  name_change: "Issuance of the new names",
};

/** The name a Managed Certificate goes by: its current Certificate's common name, or else its first name. */
export const primaryName = (m: ManagedCertificate) => m.commonName ?? m.names[0];

const DAY = 24 * 60 * 60 * 1000;

/** A Certificate's life in whole days: how long it is valid for, and how much of that is left (rounded down, as the PEM Parser counts it; none once it has ended). */
export function lifeOf({ notBefore, notAfter }: { notBefore: string; notAfter: string }, now = Date.now()) {
  const total = Math.round((Date.parse(notAfter) - Date.parse(notBefore)) / DAY);
  const remaining = Date.parse(notAfter) - now;
  return { total, left: remaining <= 0 ? null : Math.floor(remaining / DAY) };
}

/** When the current Certificate ends, in a few words for beside the status: "expires in 38 days", "expired" or "revoked". */
export function expiryPhrase(certificate: ManagedCertificate["currentCertificate"], now = Date.now()) {
  if (!certificate) return null;
  if (certificate.revocation) return "revoked";
  const { left } = lifeOf(certificate, now);
  if (left === null) return "expired";
  if (left === 0) return "expires today";
  return `expires in ${left} day${left === 1 ? "" : "s"}`;
}
