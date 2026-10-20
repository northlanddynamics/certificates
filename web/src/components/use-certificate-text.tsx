import { useState } from "react";
import { containsPrivateKey } from "@/lib/pki-input";

/**
 * For a box that takes a certificate to send to the platform, typed, pasted or read from a file: `accept` passes the text
 * on, except a private key (picked up by mistake in place of the certificate), which is cleared instead, and `notice` says so.
 */
export function useCertificateText(onChange: (text: string) => void) {
  const [refused, setRefused] = useState(false);
  const accept = (text: string) => {
    const isKey = containsPrivateKey(text);
    setRefused(isKey);
    onChange(isKey ? "" : text);
  };
  const notice = refused ? (
    <p role="alert" className="text-sm text-destructive">
      That is a private key, which the platform never takes, so it has been cleared. Use the certificate, not the key.
    </p>
  ) : null;
  return { accept, notice };
}
