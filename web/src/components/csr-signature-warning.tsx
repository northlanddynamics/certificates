import { TriangleAlertIcon } from "lucide-react";
import { weakSignatureWarning } from "@/lib/csr-signature";

/**
 * Under a textarea that takes a pasted CSR: says so when it is signed with SHA-1, MD5 or RSA-PSS, which a CA is likely
 * to refuse. It never blocks the submit and shows nothing else about the CSR.
 */
export function CsrSignatureWarning({ pem }: { pem: string }) {
  const warning = weakSignatureWarning(pem);
  if (!warning) return null;
  return (
    <p role="note" className="flex items-start gap-2 text-sm text-warning">
      <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" />
      {warning}
    </p>
  );
}
