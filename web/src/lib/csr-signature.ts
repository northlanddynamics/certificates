// Reads the signature algorithm of a pasted CSR and nothing else, to warn when a CA is likely to refuse it. It never
// decides anything: the server checks only that the signature verifies. Pure, with no fetch, so a pasted CSR goes nowhere.
import * as x509 from "@peculiar/x509";

const REFUSED = "the CA is likely to refuse it. You can still submit it.";

// md5WithRSAEncryption: the X.509 library does not name it, so it comes back as its OID.
const MD5_WITH_RSA = "1.2.840.113549.1.1.4";

/**
 * A warning in words when the CSR is signed with SHA-1, MD5 or RSA-PSS; null when it is signed with anything else, or
 * when the text is not (yet) a CSR that can be read.
 */
export function weakSignatureWarning(pem: string): string | null {
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem.trim());
  } catch {
    return null;
  }
  const algorithm: { name: string; hash?: { name: string } } = csr.signatureAlgorithm;
  if (algorithm.name === MD5_WITH_RSA) return `This CSR is signed with MD5; ${REFUSED}`;
  if (algorithm.name === "RSA-PSS") return `This CSR is signed with RSA-PSS; ${REFUSED}`;
  if (algorithm.hash?.name === "SHA-1") return `This CSR is signed with SHA-1; ${REFUSED}`;
  return null;
}
