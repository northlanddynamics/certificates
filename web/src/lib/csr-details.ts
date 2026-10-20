// Reads everything a CSR says, for the CSR Viewer: its subject, names, key, signature, requested extensions and
// attributes, and whether the platform would take it. It decides nothing: the server's parseCsr does, and the rules in
// `fit` are a copy of that function's, which server/test/csr-generator.test.ts holds the two to. Pure, with no fetch, so a
// pasted CSR goes nowhere (ADR 0002 keeps keys off the platform; this keeps CSRs off it too until they are submitted).
import * as x509 from "@peculiar/x509";
import { KEY_ALGORITHM_LABELS, type KeyAlgorithm } from "./csr-generator";
import { keyOf } from "./csr-inspect";
import { MAX_NAMES, normalizeName } from "./csr-names";
import { weakSignatureWarning } from "./csr-signature";

// By OID: looked up by class, an extension is not found when two copies of the library are loaded.
const SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";
const EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

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

const NAME_TYPE_LABELS: Record<string, string> = { dns: "DNS", ip: "IP", email: "Email", url: "URI", dn: "Directory name", guid: "GUID", upn: "UPN", id: "Registered ID" };

const EXTENSION_LABELS: Record<string, string> = {
  "2.5.29.14": "Subject key identifier",
  "2.5.29.15": "Key usage",
  "2.5.29.17": "Subject alternative names",
  "2.5.29.19": "Basic constraints",
  "2.5.29.32": "Certificate policies",
  "2.5.29.37": "Extended key usage",
  "1.3.6.1.5.5.7.1.24": "TLS feature",
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

const ATTRIBUTE_LABELS: Record<string, string> = {
  "1.2.840.113549.1.9.2": "Unstructured name",
  "1.2.840.113549.1.9.7": "Challenge password",
  "1.2.840.113549.1.9.8": "Unstructured address",
};
const CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7";

/** The platform's key algorithms in words, for a refusal; a copy of the server's SUPPORTED. */
const SUPPORTED = "ECDSA (P-256, P-384), RSA (2048, 3072, 4096) and ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87)";

export type SignatureCheck = "valid" | "invalid" | "unchecked";

export interface CsrSubjectField {
  /** As the library names it: CN, O, or an OID it does not know. */
  type: string;
  /** In words, where it is known; else the type again. */
  label: string;
  value: string;
}

export interface CsrName {
  /** Where it was asked for: a subject alternative name, or the subject's CN. */
  source: "san" | "cn";
  /** In words: DNS, IP, Email. */
  type: string;
  value: string;
  /** As the platform keeps it; null when it cannot be a name to issue for, which `problem` then says. */
  normalized: string | null;
  wildcard: boolean;
  /** The CN repeats a name already asked for. */
  repeat: boolean;
  problem: string | null;
}

export interface CsrExtension {
  oid: string;
  label: string;
  critical: boolean;
  /** What it asks for, in words. */
  summary: string;
}

export interface CsrAttribute {
  oid: string;
  label: string;
  /** What is shown of it. A secret is never shown. */
  summary: string;
}

/** One thing the platform checks; `ok` is null when this browser cannot tell and the server will. */
export interface CsrFitCheck {
  id: "signature" | "key" | "names";
  ok: boolean | null;
  text: string;
}

export interface CsrDetails {
  subject: CsrSubjectField[];
  names: CsrName[];
  /** The platform's view of the names: DNS only, normalised, without repeats. Empty when any name is refused. */
  distinctNames: string[];
  key: {
    /** One the platform accepts, or null for any other. */
    algorithm: KeyAlgorithm | null;
    /** In words, such as "RSA 2048" or "ECDSA P-521". */
    label: string;
    /** SHA-256 of the public key's DER SubjectPublicKeyInfo, lower-case hex: what a certificate or private key made for it also has. */
    sha256: string;
    publicKeyPem: string;
  };
  signature: { algorithm: string; check: SignatureCheck };
  extensions: CsrExtension[];
  attributes: CsrAttribute[];
  /** Things worth knowing that do not stop the platform taking it. */
  warnings: string[];
  fit: CsrFitCheck[];
  /** Whether every check is passed or left to the server: nothing here says the platform would refuse it. */
  acceptable: boolean;
  /** SHA-256 of the CSR's DER, lower-case hex: as the server names a CSR. */
  fingerprint: string;
  derLength: number;
  /** The CSR as one clean PEM block. */
  pem: string;
}

export type CsrReading = { ok: true; details: CsrDetails } | { ok: false; error: string };

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (data: ArrayBuffer) => hex(await crypto.subtle.digest("SHA-256", data));

/** An ML-DSA signature is checked by the browser's WebCrypto where it can, and otherwise by noble, loaded only then. */
async function checkSignature(csr: x509.Pkcs10CertificateRequest, mlDsa: boolean): Promise<SignatureCheck> {
  if (await csr.verify().catch(() => false)) return "valid";
  if (!mlDsa) return "invalid";
  try {
    return (await import("./csr-ml-dsa")).verifyMlDsaCsr(csr.rawData) ? "valid" : "invalid";
  } catch {
    return "unchecked";
  }
}

/** A key the platform does not accept, in words: its curve or size where WebCrypto can name it. */
async function otherKeyLabel(publicKey: x509.PublicKey): Promise<string> {
  const p521 = await crypto.subtle.importKey("spki", publicKey.rawData, { name: "ECDSA", namedCurve: "P-521" }, true, ["verify"]).then(() => true, () => false);
  if (p521) return "ECDSA P-521";
  const name = publicKey.algorithm.name;
  return name ? `${name} key` : "an unrecognised key";
}

function signatureLabel(csr: x509.Pkcs10CertificateRequest): string {
  const { name, hash } = csr.signatureAlgorithm as { name: string; hash?: { name: string } };
  if (name === "1.2.840.113549.1.1.4") return "RSA PKCS#1 v1.5 with MD5";
  if (name === "RSASSA-PKCS1-v1_5") return `RSA PKCS#1 v1.5 with ${hash?.name ?? "an unknown hash"}`;
  if (name === "ECDSA") return `ECDSA with ${hash?.name ?? "an unknown hash"}`;
  return name;
}

function namesOf(csr: x509.Pkcs10CertificateRequest): CsrName[] {
  const alternativeNames = csr.getExtension(SUBJECT_ALTERNATIVE_NAME) as x509.SubjectAlternativeNameExtension | null;
  const asked = [
    ...(alternativeNames?.names.items.map((item) => ({ source: "san" as const, type: item.type, value: item.value })) ?? []),
    ...csr.subjectName.getField("CN").map((value) => ({ source: "cn" as const, type: "dns", value })),
  ];
  const seen = new Set<string>();
  return asked.map(({ source, type, value }) => {
    const normalized = type === "dns" ? normalizeName(value) : null;
    const problem = type !== "dns" ? "only DNS names are supported" : normalized === null ? "cannot be a name to issue for" : null;
    const repeat = normalized !== null && seen.has(normalized);
    if (normalized !== null) seen.add(normalized);
    return { source, type: NAME_TYPE_LABELS[type] ?? type, value, normalized, wildcard: normalized?.startsWith("*.") ?? value.startsWith("*."), repeat, problem };
  });
}

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
    default:
      return `${extension.value.byteLength} bytes`;
  }
}

function extensionsOf(csr: x509.Pkcs10CertificateRequest): CsrExtension[] {
  return csr.extensions.map((extension) => {
    let summary: string;
    try {
      summary = extensionSummary(extension);
    } catch {
      summary = `${extension.value.byteLength} bytes, which could not be read`;
    }
    return { oid: extension.type, label: EXTENSION_LABELS[extension.type] ?? extension.type, critical: extension.critical, summary };
  });
}

// The extensions are shown on their own, so the attribute that carries them is not.
function attributesOf(csr: x509.Pkcs10CertificateRequest): CsrAttribute[] {
  return csr.attributes
    .filter((attribute) => attribute.type !== EXTENSION_REQUEST)
    .map((attribute) => ({
      oid: attribute.type,
      label: ATTRIBUTE_LABELS[attribute.type] ?? attribute.type,
      summary: attribute.type === CHALLENGE_PASSWORD ? "Present; its value is not shown" : `${attribute.values.length} ${attribute.values.length === 1 ? "value" : "values"}`,
    }));
}

function fitOf(check: SignatureCheck, key: CsrDetails["key"], names: CsrName[], distinctNames: string[]): CsrFitCheck[] {
  const refused = names.filter((name) => name.problem);
  const namesText =
    names.length === 0
      ? "The CSR asks for no names."
      : refused.length > 0
        ? `${refused.length === 1 ? "A name" : `${refused.length} names`} cannot be issued for: ${refused.map((name) => `${name.value} (${name.problem})`).join("; ")}.`
        : distinctNames.length > MAX_NAMES
          ? `${distinctNames.length} names, and a certificate may have at most ${MAX_NAMES}.`
          : `${distinctNames.length} DNS ${distinctNames.length === 1 ? "name" : "names"}, all of which can be issued for.`;
  return [
    {
      id: "signature",
      ok: check === "valid" ? true : check === "invalid" ? false : null,
      text:
        check === "valid"
          ? "Signed with the key it carries, so whoever sent it holds that key."
          : check === "invalid"
            ? "The signature does not verify against its own public key; the CSR may have been damaged in copying."
            : "This browser cannot check the signature; the platform will.",
    },
    { id: "key", ok: key.algorithm !== null, text: key.algorithm ? `${key.label} is a key the platform takes.` : `${key.label}: the platform takes only ${SUPPORTED}.` },
    { id: "names", ok: names.length > 0 && refused.length === 0 && distinctNames.length <= MAX_NAMES, text: namesText },
  ];
}

/** Everything a PEM CSR says, or why it cannot be read, in words. */
export async function parseCsrDetails(pem: string): Promise<CsrReading> {
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem.trim());
  } catch {
    return { ok: false, error: "This looks like a CSR but cannot be read as one. It may be cut short or damaged in copying." };
  }
  try {
    const mlDsa = csr.publicKey.algorithm.name.startsWith("ML-DSA");
    const [check, key, fingerprint, keySha256] = await Promise.all([checkSignature(csr, mlDsa), keyOf(csr.publicKey), sha256(csr.rawData), sha256(csr.publicKey.rawData)]);
    const names = namesOf(csr);
    const distinctNames = [...new Set(names.map((name) => name.normalized).filter((name): name is string => name !== null))];
    const details: Omit<CsrDetails, "fit" | "acceptable" | "warnings"> = {
      subject: csr.subjectName.toJSON().flatMap((rdn) => Object.entries(rdn).flatMap(([type, values]) => values.map((value) => ({ type, label: SUBJECT_LABELS[type] ?? type, value })))),
      names,
      distinctNames,
      key: {
        algorithm: key.keyAlgorithm,
        label: key.keyAlgorithm ? key.keyLabel : key.keyLabel.startsWith("RSA ") ? key.keyLabel : await otherKeyLabel(csr.publicKey),
        sha256: keySha256,
        publicKeyPem: x509.PemConverter.encode(csr.publicKey.rawData, "PUBLIC KEY"),
      },
      signature: { algorithm: signatureLabel(csr), check },
      extensions: extensionsOf(csr),
      attributes: attributesOf(csr),
      fingerprint,
      derLength: csr.rawData.byteLength,
      pem: csr.toString("pem"),
    };
    const fit = fitOf(check, details.key, names, distinctNames);
    const warnings: string[] = [];
    const weak = weakSignatureWarning(details.pem);
    if (weak) warnings.push(weak);
    if (names.length > 0 && !names.some((name) => name.source === "san"))
      warnings.push("It has no subject alternative names, only a common name. Browsers ignore the common name, so a certificate issued for it would not work for them.");
    if (details.extensions.some((extension) => extension.oid === "2.5.29.19" && extension.summary.startsWith("CA")))
      warnings.push("It asks for a CA certificate (basic constraints CA:TRUE). A certificate authority would normally refuse that for a TLS certificate.");
    return { ok: true, details: { ...details, fit, warnings, acceptable: fit.every((check) => check.ok !== false) } };
  } catch {
    return { ok: false, error: "This CSR is well formed but something in it could not be read." };
  }
}
