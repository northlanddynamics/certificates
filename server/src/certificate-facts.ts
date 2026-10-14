// What a stored Certificate says about itself, read from the chain the CA served: its subject and issuer, how it is
// signed, and each certificate of the chain, leaf first. A stored Certificate never changes, so these are
// read from it when asked for rather than stored beside it.
import * as x509 from "@peculiar/x509";
import { createHash, webcrypto } from "node:crypto";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const SIGNATURE_SCHEMES: Record<string, string> = { ECDSA: "ECDSA", "RSASSA-PKCS1-v1_5": "RSA", "RSA-PSS": "RSA-PSS", Ed25519: "Ed25519" };

/** "ECDSA with SHA-256", "RSA with SHA-384": the scheme and hash a certificate is signed with, as people say them. */
function signatureAlgorithmOf(cert: x509.X509Certificate) {
  const algorithm = cert.signatureAlgorithm as Algorithm & { hash?: Algorithm };
  const scheme = SIGNATURE_SCHEMES[algorithm.name] ?? algorithm.name;
  return algorithm.hash ? `${scheme} with ${algorithm.hash.name}` : scheme;
}

export function certificateFacts(chainPem: string) {
  const chain = (chainPem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((pem) => new x509.X509Certificate(pem));
  const [leaf] = chain;
  if (!leaf) throw new Error("the stored chain has no certificate");
  return {
    subject: leaf.subject,
    issuer: leaf.issuer,
    signatureAlgorithm: signatureAlgorithmOf(leaf),
    chain: chain.map((cert) => ({
      subject: cert.subject,
      issuer: cert.issuer,
      serial: cert.serialNumber.toUpperCase(),
      fingerprint: createHash("sha256").update(new Uint8Array(cert.rawData)).digest("hex"),
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
    })),
  };
}
