// Reads everything a CSR says, for the Viewer: its subject, names, key, signature, requested extensions and
// attributes, and whether the platform would take it. It decides nothing: the server's parseCsr does, and the rules in
// `fit` are a copy of that function's, which server/test/csr-viewer.test.ts holds the two to. Pure, with no fetch, so a
// pasted CSR goes nowhere (ADR 0002 keeps keys off the platform; this keeps CSRs off it too until they are submitted).
import * as x509 from "@peculiar/x509";
import { MAX_NAMES, normalizeName } from "./csr-names";
import { weakSignatureWarning } from "./csr-signature";
import {
  NAME_TYPE_LABELS,
  SUBJECT_ALTERNATIVE_NAME,
  digest,
  extensionsOf,
  isCaExtension,
  signatureLabel,
  subjectFields,
  summarizeKey,
  type KeySummary,
  type PkiExtension,
  type SignatureCheck,
  type SubjectField,
} from "./pki-common";

export type { SignatureCheck } from "./pki-common";

const EXTENSION_REQUEST = "1.2.840.113549.1.9.14";

const ATTRIBUTE_LABELS: Record<string, string> = {
  "1.2.840.113549.1.9.2": "Unstructured name",
  "1.2.840.113549.1.9.7": "Challenge password",
  "1.2.840.113549.1.9.8": "Unstructured address",
};
const CHALLENGE_PASSWORD = "1.2.840.113549.1.9.7";

/** The platform's key algorithms in words, for a refusal; a copy of the server's SUPPORTED. */
const SUPPORTED = "ECDSA (P-256, P-384), RSA (2048, 3072, 4096) and ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87)";

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
  subject: SubjectField[];
  names: CsrName[];
  /** The platform's view of the names: DNS only, normalised, without repeats. Empty when any name is refused. */
  distinctNames: string[];
  key: KeySummary;
  signature: { algorithm: string; check: SignatureCheck };
  extensions: PkiExtension[];
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

function fitOf(check: SignatureCheck, key: KeySummary, names: CsrName[], distinctNames: string[]): CsrFitCheck[] {
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
    const [check, key, fingerprint] = await Promise.all([checkSignature(csr, mlDsa), summarizeKey(csr.publicKey), digest("SHA-256", csr.rawData)]);
    const names = namesOf(csr);
    const distinctNames = [...new Set(names.map((name) => name.normalized).filter((name): name is string => name !== null))];
    const extensions = extensionsOf(csr.extensions);
    const fit = fitOf(check, key, names, distinctNames);
    const warnings: string[] = [];
    const pemText = csr.toString("pem");
    const weak = weakSignatureWarning(pemText);
    if (weak) warnings.push(weak);
    if (names.length > 0 && !names.some((name) => name.source === "san"))
      warnings.push("It has no subject alternative names, only a common name. Browsers ignore the common name, so a certificate issued for it would not work for them.");
    if (extensions.some(isCaExtension)) warnings.push("It asks for a CA certificate (basic constraints CA:TRUE). A certificate authority would normally refuse that for a TLS certificate.");
    return {
      ok: true,
      details: {
        subject: subjectFields(csr.subjectName),
        names,
        distinctNames,
        key,
        signature: { algorithm: signatureLabel(csr.signatureAlgorithm), check },
        extensions,
        attributes: attributesOf(csr),
        warnings,
        fit,
        acceptable: fit.every((item) => item.ok !== false),
        fingerprint,
        derLength: csr.rawData.byteLength,
        pem: pemText,
      },
    };
  } catch {
    return { ok: false, error: "This CSR is well formed but something in it could not be read." };
  }
}
