// What reading a CSR and reading a certificate have in common: a name (the subject, the issuer), a public key, a
// signature algorithm, and extensions, put into words, and the digests that name them. Pure, with no fetch, so what is
// read goes nowhere.
import * as x509 from "@peculiar/x509";
import { type KeyAlgorithm } from "./csr-generator";
import { keyOf } from "./csr-inspect";

// By OID: looked up by class, an extension is not found when two copies of the library are loaded.
export const SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";

export type SignatureCheck = "valid" | "invalid" | "unchecked";

export interface SubjectField {
  /** As the library names it: CN, O, or an OID it does not know. */
  type: string;
  /** In words, where it is known; else the type again. */
  label: string;
  value: string;
}

/** A name a CSR or certificate is for. */
export interface PkiName {
  /** In words: DNS, IP, Email. */
  type: string;
  value: string;
  wildcard: boolean;
}

export interface PkiExtension {
  oid: string;
  label: string;
  critical: boolean;
  /** What it says, in words. */
  summary: string;
}

export interface KeySummary {
  /** One the platform accepts, or null for any other. */
  algorithm: KeyAlgorithm | null;
  /** In words, such as "RSA 2048" or "ECDSA P-521". */
  label: string;
  /** SHA-256 of the public key's DER SubjectPublicKeyInfo, lower-case hex: what a CSR, a certificate or a private key made for the same key also has, so it tells them together. */
  sha256: string;
  publicKeyPem: string;
}

const SUBJECT_LABELS: Record<string, string> = {
  CN: "Common name",
  O: "Organization",
  OU: "Organizational unit",
  C: "Country",
  ST: "State or province",
  L: "Locality",
  E: "Email",
  DC: "Domain component",
  SERIALNUMBER: "Serial number",
  STREET: "Street",
  T: "Title",
};

export const NAME_TYPE_LABELS: Record<string, string> = { dns: "DNS", ip: "IP", email: "Email", url: "URI", dn: "Directory name", guid: "GUID", upn: "UPN", id: "Registered ID" };

const EXTENSION_LABELS: Record<string, string> = {
  "2.5.29.14": "Subject key identifier",
  "2.5.29.15": "Key usage",
  "2.5.29.17": "Subject alternative names",
  "2.5.29.19": "Basic constraints",
  "2.5.29.31": "CRL distribution points",
  "2.5.29.32": "Certificate policies",
  "2.5.29.35": "Authority key identifier",
  "2.5.29.37": "Extended key usage",
  "1.3.6.1.5.5.7.1.1": "Authority information access",
  "1.3.6.1.5.5.7.1.24": "TLS feature",
  "1.3.6.1.4.1.11129.2.4.2": "Certificate transparency",
  "1.3.6.1.4.1.311.20.2": "Microsoft certificate template name",
  "1.3.6.1.4.1.311.21.7": "Microsoft certificate template",
};

const EXTENDED_KEY_USAGE_LABELS: Record<string, string> = {
  "1.3.6.1.5.5.7.3.1": "TLS server authentication",
  "1.3.6.1.5.5.7.3.2": "TLS client authentication",
  "1.3.6.1.5.5.7.3.3": "Code signing",
  "1.3.6.1.5.5.7.3.4": "Email protection",
  "1.3.6.1.5.5.7.3.8": "Time stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP signing",
};

const KEY_USAGE_LABELS: [x509.KeyUsageFlags, string][] = [
  [x509.KeyUsageFlags.digitalSignature, "Digital signature"],
  [x509.KeyUsageFlags.nonRepudiation, "Non-repudiation"],
  [x509.KeyUsageFlags.keyEncipherment, "Key encipherment"],
  [x509.KeyUsageFlags.dataEncipherment, "Data encipherment"],
  [x509.KeyUsageFlags.keyAgreement, "Key agreement"],
  [x509.KeyUsageFlags.keyCertSign, "Certificate signing"],
  [x509.KeyUsageFlags.cRLSign, "CRL signing"],
  [x509.KeyUsageFlags.encipherOnly, "Encipher only"],
  [x509.KeyUsageFlags.decipherOnly, "Decipher only"],
];

export const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
export const digest = async (algorithm: "SHA-1" | "SHA-256", data: ArrayBuffer) => hex(await crypto.subtle.digest(algorithm, data));

/** A name's fields, one to a row, in the order they are in. */
export const subjectFields = (name: x509.Name): SubjectField[] =>
  name.toJSON().flatMap((rdn) => Object.entries(rdn).flatMap(([type, values]) => values.map((value) => ({ type, label: SUBJECT_LABELS[type] ?? type, value }))));

/** The alternative names of a CSR or certificate; empty when it has none. */
export function alternativeNames(extension: x509.Extension | null): PkiName[] {
  if (!extension) return [];
  return new x509.SubjectAlternativeNameExtension(extension.rawData).names.items.map((item) => ({
    type: NAME_TYPE_LABELS[item.type] ?? item.type,
    value: item.value,
    wildcard: item.value.startsWith("*."),
  }));
}

export function signatureLabel(algorithm: { name: string; hash?: { name: string } }): string {
  const { name, hash } = algorithm;
  if (name === "1.2.840.113549.1.1.4") return "RSA PKCS#1 v1.5 with MD5";
  if (name === "RSASSA-PKCS1-v1_5") return `RSA PKCS#1 v1.5 with ${hash?.name ?? "an unknown hash"}`;
  if (name === "ECDSA") return `ECDSA with ${hash?.name ?? "an unknown hash"}`;
  return name;
}

/** A key the platform does not accept, in words: its curve or size where WebCrypto can name it. */
async function otherKeyLabel(publicKey: x509.PublicKey): Promise<string> {
  const p521 = await crypto.subtle.importKey("spki", publicKey.rawData, { name: "ECDSA", namedCurve: "P-521" }, true, ["verify"]).then(() => true, () => false);
  if (p521) return "ECDSA P-521";
  const name = publicKey.algorithm.name;
  return name ? `${name} key` : "an unrecognised key";
}

export async function summarizeKey(publicKey: x509.PublicKey): Promise<KeySummary> {
  const [key, sha256] = await Promise.all([keyOf(publicKey), digest("SHA-256", publicKey.rawData)]);
  return {
    algorithm: key.keyAlgorithm,
    label: key.keyAlgorithm || key.keyLabel.startsWith("RSA ") ? key.keyLabel : await otherKeyLabel(publicKey),
    sha256,
    publicKeyPem: x509.PemConverter.encode(publicKey.rawData, "PUBLIC KEY"),
  };
}

const urls = (names: readonly { value: string }[]) => names.map((name) => name.value).join(", ");

function extensionSummary(extension: x509.Extension): string {
  switch (extension.type) {
    case SUBJECT_ALTERNATIVE_NAME: {
      const items = new x509.SubjectAlternativeNameExtension(extension.rawData).names.items;
      return `${items.length} ${items.length === 1 ? "name" : "names"}, listed above`;
    }
    case "2.5.29.15": {
      const flags = new x509.KeyUsagesExtension(extension.rawData).usages;
      return KEY_USAGE_LABELS.filter(([flag]) => (flags & flag) !== 0).map(([, label]) => label).join(", ") || "None";
    }
    case "2.5.29.37":
      return new x509.ExtendedKeyUsageExtension(extension.rawData).usages.map((usage) => EXTENDED_KEY_USAGE_LABELS[String(usage)] ?? String(usage)).join(", ") || "None";
    case "2.5.29.19": {
      const { ca, pathLength } = new x509.BasicConstraintsExtension(extension.rawData);
      return ca ? `CA${pathLength === undefined ? "" : `, path length ${pathLength}`}` : "Not a CA";
    }
    case "2.5.29.14":
      return new x509.SubjectKeyIdentifierExtension(extension.rawData).keyId;
    case "2.5.29.35":
      return new x509.AuthorityKeyIdentifierExtension(extension.rawData).keyId ?? `${extension.value.byteLength} bytes`;
    case "2.5.29.31":
      return (
        new x509.CRLDistributionPointsExtension(extension.rawData).distributionPoints
          .flatMap((point) => point.distributionPoint?.fullName?.map((name) => name.uniformResourceIdentifier ?? "") ?? [])
          .filter(Boolean)
          .join(", ") || `${extension.value.byteLength} bytes`
      );
    case "2.5.29.32":
      return new x509.CertificatePolicyExtension(extension.rawData).policies.join(", ");
    case "1.3.6.1.5.5.7.1.1": {
      const { ocsp, caIssuers } = new x509.AuthorityInfoAccessExtension(extension.rawData);
      return [ocsp.length > 0 && `OCSP ${urls(ocsp)}`, caIssuers.length > 0 && `CA issuers ${urls(caIssuers)}`].filter(Boolean).join("; ") || `${extension.value.byteLength} bytes`;
    }
    case "1.3.6.1.4.1.11129.2.4.2":
      return "Signed certificate timestamps are embedded";
    default:
      return `${extension.value.byteLength} bytes`;
  }
}

export const extensionsOf = (extensions: x509.Extension[]): PkiExtension[] =>
  extensions.map((extension) => {
    let summary: string;
    try {
      summary = extensionSummary(extension);
    } catch {
      summary = `${extension.value.byteLength} bytes, which could not be read`;
    }
    return { oid: extension.type, label: EXTENSION_LABELS[extension.type] ?? extension.type, critical: extension.critical, summary };
  });

/** Whether the extensions ask for, or say, a CA: basic constraints CA:TRUE. */
export const isCaExtension = (extension: PkiExtension) => extension.oid === "2.5.29.19" && extension.summary.startsWith("CA");
