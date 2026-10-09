// Export: encodes a Certificate, with as much of its chain as is asked for, as PEM, DER or PKCS#7 (P7B). It never
// produces PFX or JKS: those carry a private key, and the platform holds none (ADR 0002).
import { X509Certificate as PeculiarCertificate, X509Certificates } from "@peculiar/x509";
import { X509Certificate } from "node:crypto";

export const EXPORT_FORMATS = ["pem", "der", "p7b"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** How much of the chain goes with the Certificate: itself only, with the intermediates the CA served, or with the root too. */
export const EXPORT_CHAINS = ["leaf", "with-intermediates", "with-root"] as const;
export type ExportChain = (typeof EXPORT_CHAINS)[number];

/** The root of a chain cannot be added: no root the platform knows signed its last intermediate. */
export class RootNotKnownError extends Error {}

export interface Encoded {
  body: string | Uint8Array;
  contentType: string;
  extension: string;
}

const isSelfSigned = (cert: X509Certificate) => cert.checkIssued(cert) && cert.verify(cert.publicKey);

/**
 * The certificates to export, leaf first. `chainPem` is what the CA served, the leaf and its intermediates (a CA that
 * also served the root has it left out of "with-intermediates"). The root, when asked for, is the one the CA served or
 * else one of `roots` that signed the last intermediate.
 */
export async function select(chainPem: string, chain: ExportChain, roots: () => Promise<string[]>): Promise<X509Certificate[]> {
  const served = (chainPem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? []).map((pem) => new X509Certificate(pem));
  const [leaf, ...rest] = served;
  if (!leaf) throw new Error("the stored chain has no certificate");
  const servedRoot = rest.find(isSelfSigned);
  const intermediates = rest.filter((cert) => cert !== servedRoot);
  if (chain === "leaf") return [leaf];
  if (chain === "with-intermediates") return [leaf, ...intermediates];

  if (servedRoot) return [leaf, ...intermediates, servedRoot];
  const top = intermediates.at(-1) ?? leaf;
  for (const pem of await roots()) {
    const root = new X509Certificate(pem);
    if (top.checkIssued(root) && top.verify(root.publicKey)) return [leaf, ...intermediates, root];
  }
  throw new RootNotKnownError("the root of this Certificate's chain is not one the platform knows, so it cannot be added");
}

/** The certificates-only PKCS#7 `der` in the PEM armor of RFC 7468; the library's own armor says CMS, which tools that read P7B do not look for. */
const pkcs7Pem = (der: Uint8Array) => `-----BEGIN PKCS7-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END PKCS7-----\n`;

/**
 * PEM is the certificates one after the other. DER is the certificates' DER encodings one after the other (the one
 * Certificate, for the leaf only). P7B is a PKCS#7 bundle of certificates, PEM-armored as CAs hand them out.
 */
export function encode(certs: X509Certificate[], format: ExportFormat): Encoded {
  switch (format) {
    case "pem":
      return { body: certs.map((cert) => cert.toString().trim()).join("\n") + "\n", contentType: "application/x-pem-file", extension: "pem" };
    case "der":
      return { body: Buffer.concat(certs.map((cert) => cert.raw)), contentType: "application/pkix-cert", extension: "der" };
    case "p7b":
      return {
        body: pkcs7Pem(new Uint8Array(new X509Certificates(certs.map((cert) => new PeculiarCertificate(cert.raw))).export("raw"))),
        contentType: "application/x-pkcs7-certificates",
        extension: "p7b",
      };
  }
}
