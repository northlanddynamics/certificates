// The CA module: builds the X.509 certificates a Private CA signs, with @peculiar/x509, and has the KMS sign them with
// the CA's key, which never leaves it (ADR 0007). It owns the certificate profiles (a self-signed root, an Issuing CA
// under it, a TLS server certificate), their serial numbers, the CRL Distribution Point and AIA they name, and the CRLs
// a CA signs.
import * as x509 from "@peculiar/x509";
import { randomBytes, webcrypto } from "node:crypto";
import { isMlDsa, type ClassicalKeyAlgorithm, type SigningKeyAlgorithm } from "./csr";
import { SIGNATURE_HASH, type Kms } from "../platform/crypto/kms";

/** A CA key in the KMS: its reference, the context (an Organization's id) it was made for, and its algorithm. */
export interface CaKey {
  key: string;
  context: string;
  algorithm: SigningKeyAlgorithm;
}

/** A CA that signs: its key, and its certificate, whose subject is the issuer of what it signs. */
export interface Signer extends CaKey {
  certificate: x509.X509Certificate;
}

/** How each key algorithm appears to @peculiar/x509 as a signing key: what tells it how to name the signature. */
const SIGNING_ALGORITHMS: Record<ClassicalKeyAlgorithm, Algorithm & { hash: string }> = {
  // The curve tells it how long r and s are.
  "ecdsa-p256": { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as Algorithm & { hash: string },
  "ecdsa-p384": { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" } as Algorithm & { hash: string },
  "rsa-2048": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  "rsa-3072": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  "rsa-4096": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
};

/**
 * What @peculiar/x509 is given to sign with: a WebCrypto whose `sign` hashes what is to be signed and has the KMS sign
 * the digest, and a stand-in for the private key, which the platform does not have. The KMS gives ECDSA signatures as
 * r ‖ s, as WebCrypto does, which the library encodes for X.509 itself.
 */
function kmsSigning(kms: Kms, { key, context, algorithm }: CaKey) {
  // The API makes no ML-DSA Private CA yet, so no ML-DSA key reaches here.
  if (isMlDsa(algorithm)) throw new Error(`a ${algorithm} CA key cannot sign yet`);
  const hash = SIGNATURE_HASH[algorithm];
  const subtle = {
    // What a CSR is made with asks for the public key this way; the stand-in for it is its DER SubjectPublicKeyInfo.
    exportKey: async (_format: "spki", publicKey: { spki: ArrayBuffer }) => publicKey.spki,
    digest: (alg: AlgorithmIdentifier, data: ArrayBuffer) => webcrypto.subtle.digest(alg, data),
    async sign(_alg: unknown, _key: unknown, data: ArrayBuffer) {
      const digest = new Uint8Array(await webcrypto.subtle.digest(hash, data));
      return (await kms.sign(key, context, digest)).slice().buffer;
    },
  };
  const crypto = { subtle, getRandomValues: <T extends ArrayBufferView>(array: T) => webcrypto.getRandomValues(array as any) as T } as unknown as Crypto;
  const signingAlgorithm = SIGNING_ALGORITHMS[algorithm];
  const signingKey = { algorithm: signingAlgorithm, type: "private", extractable: false, usages: ["sign"] } as unknown as CryptoKey;
  return { crypto, signingKey, signingAlgorithm };
}

/**
 * Where relying parties find what a certificate's issuer publishes (crl.ts): the issuer's CRL, named in the CRL
 * Distribution Point, and the issuer's own certificate, named in the AIA caIssuers.
 */
export interface Publication {
  crl: string;
  caIssuers: string;
}

const publicationExtensions = ({ crl, caIssuers }: Publication) => [new x509.CRLDistributionPointsExtension([crl]), new x509.AuthorityInfoAccessExtension({ caIssuers })];

// By OID: looked up by class, an extension is not found when two copies of the library are loaded.
const EXTENDED_KEY_USAGE = "2.5.29.37";
const BASIC_CONSTRAINTS = "2.5.29.19";
const KEY_USAGE = "2.5.29.15";
const CRL_NUMBER = "2.5.29.20";
const NAME_CONSTRAINTS = "2.5.29.30";
/** RFC 5280's upper bound on a common name. */
const MAX_COMMON_NAME = 64;

/** A serial number: 20 random bytes, positive (the top bit clear) and with no leading zero byte, as upper-case hex. */
export function newSerial(): string {
  const bytes = randomBytes(20);
  bytes[0] = bytes[0]! & 0x7f || 1;
  return bytes.toString("hex").toUpperCase();
}

/** The subject as a distinguished name, or null when it is not one, or has no common name. */
export function parseSubject(subject: string): x509.Name | null {
  try {
    const name = new x509.Name(subject);
    return name.getField("CN").length > 0 ? name : null;
  } catch {
    return null;
  }
}

/** The name with " Root" added to its common name: a platform-made root's subject, beside its Issuing CA's. */
export function rootSubjectOf(name: x509.Name): x509.Name {
  return new x509.Name(name.toJSON().map((rdn) => Object.fromEntries(Object.entries(rdn).map(([type, values]) => [type, type === "CN" ? values.map((v) => `${v} Root`) : values]))));
}

const caExtensions = async (publicKey: x509.PublicKey, pathLength: number | undefined) => [
  new x509.BasicConstraintsExtension(true, pathLength, true),
  new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  await x509.SubjectKeyIdentifierExtension.create(publicKey, false, webcrypto as unknown as Crypto),
];

/** A DER element: its tag, its length, its content. */
function der(tag: number, ...content: Uint8Array[]): Buffer<ArrayBuffer> {
  const body = Buffer.concat(content);
  // Short form below 128; otherwise how many octets the length takes, then the length in them.
  const octets: number[] = [];
  for (let n = body.length; n > 0; n >>= 8) octets.unshift(n & 0xff);
  const length = body.length < 0x80 ? [body.length] : [0x80 | octets.length, ...octets];
  return Buffer.concat([Uint8Array.of(tag, ...length), body]);
}

/**
 * Name constraints (RFC 5280, 4.2.1.10), critical, that permit the DNS names `dnsNames` and everything beneath each,
 * and no IP address (every IPv4 and IPv6 address is excluded). @peculiar/x509 has no class for them, so they are
 * encoded here: a GeneralSubtree is a SEQUENCE of its base, a dNSName [2] or an iPAddress [7] (address and mask).
 */
function nameConstraints(dnsNames: string[]) {
  const subtree = (tag: number, value: Uint8Array) => der(0x30, der(tag, value));
  const permitted = dnsNames.map((name) => subtree(0x82, Buffer.from(name, "ascii")));
  const excluded = [subtree(0x87, new Uint8Array(8)), subtree(0x87, new Uint8Array(32))];
  return new x509.Extension(NAME_CONSTRAINTS, true, der(0x30, der(0xa0, ...permitted), der(0xa1, ...excluded)));
}

/** A self-signed root for `key`. */
export async function makeRoot(kms: Kms, key: CaKey, input: { subject: x509.Name; notBefore: Date; notAfter: Date }) {
  const publicKey = new x509.PublicKey(new Uint8Array(await kms.publicKey(key.key, key.context)).buffer);
  const { crypto, signingKey } = kmsSigning(kms, key);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject: input.subject,
      issuer: input.subject,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey,
      signingKey,
      extensions: await caExtensions(publicKey, undefined),
    },
    crypto,
  );
}

/**
 * An Issuing CA for `key`, signed by `by`: it may sign end-entity certificates only (pathLen 0), and only for the DNS
 * names `permittedDnsNames` and those beneath them, as critical name constraints. It names where `by` publishes.
 */
export async function makeIssuingCa(kms: Kms, by: Signer, key: CaKey, input: { subject: x509.Name; notBefore: Date; notAfter: Date; permittedDnsNames: string[]; publication: Publication }) {
  const publicKey = new x509.PublicKey(new Uint8Array(await kms.publicKey(key.key, key.context)).buffer);
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject: input.subject,
      issuer: by.certificate.subjectName,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey,
      signingKey,
      extensions: [
        ...(await caExtensions(publicKey, 0)),
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
        nameConstraints(input.permittedDnsNames),
        ...publicationExtensions(input.publication),
      ],
    },
    crypto,
  );
}

/**
 * A TLS server certificate for the CSR's key and `names`, signed by `by`: serverAuth, and clientAuth too when the CSR
 * asks for it. Its subject is the first name that fits a common name (64 characters), and empty when none does: the
 * names are in its subject alternative names either way. It names where `by` publishes.
 */
export async function makeTlsServer(kms: Kms, by: Signer, input: { csr: string; names: string[]; notBefore: Date; notAfter: Date; publication: Publication }) {
  const csr = new x509.Pkcs10CertificateRequest(input.csr);
  // By OID: looked up by class, an extension is not found when two copies of the library are loaded.
  const asked = (csr.getExtension(EXTENDED_KEY_USAGE) as x509.ExtendedKeyUsageExtension | null)?.usages ?? [];
  const usages: string[] = [x509.ExtendedKeyUsage.serverAuth, ...(asked.includes(x509.ExtendedKeyUsage.clientAuth) ? [x509.ExtendedKeyUsage.clientAuth] : [])];
  const rsa = csr.publicKey.algorithm.name === "RSASSA-PKCS1-v1_5" || csr.publicKey.algorithm.name === "RSA-PSS" || csr.publicKey.algorithm.name === "RSA-OAEP";
  const commonName = input.names.find((name) => name.length <= MAX_COMMON_NAME);
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject: new x509.Name(commonName ? [{ CN: [commonName] }] : []),
      issuer: by.certificate.subjectName,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey: csr.publicKey,
      signingKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | (rsa ? x509.KeyUsageFlags.keyEncipherment : 0), true),
        new x509.ExtendedKeyUsageExtension(usages),
        // Critical when the subject is empty, as RFC 5280 asks.
        new x509.SubjectAlternativeNameExtension(input.names.map((value) => ({ type: "dns" as const, value })), !commonName),
        await x509.SubjectKeyIdentifierExtension.create(csr.publicKey, false, webcrypto as unknown as Crypto),
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
        ...publicationExtensions(input.publication),
      ],
    },
    crypto,
  );
}

const SUBJECT_ALT_NAME = "2.5.29.17";
/** The Microsoft "Certificate Request Agent" EKU, which NDES gives its RA signing certificate. */
const CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1";

/** A certificate's subject alternative names, each as @peculiar/x509 names its type ("dns", "url", "email", "ip", …); none when it has none. */
export function subjectAltNamesOf(source: x509.X509Certificate | x509.Pkcs10CertificateRequest): { type: string; value: string }[] {
  const extension = source.extensions.find((e) => e.type === SUBJECT_ALT_NAME);
  return extension ? new x509.SubjectAlternativeNameExtension(extension.rawData).names.toJSON() : [];
}

/**
 * An Enrollment Profile's SCEP RA certificate for the RA's own (software, RSA) key `publicKey` (DER
 * SubjectPublicKeyInfo), signed by `by`: no CA, its key usage what decrypting requests and signing responses needs, and
 * the request agent EKU that NDES's RA certificate has. It names where `by` publishes.
 */
export async function makeRaCertificate(kms: Kms, by: Signer, input: { publicKey: Uint8Array; subject: x509.Name; notBefore: Date; notAfter: Date; publication: Publication }) {
  const publicKey = new x509.PublicKey(new Uint8Array(input.publicKey).buffer);
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject: input.subject,
      issuer: by.certificate.subjectName,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey,
      signingKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
        new x509.ExtendedKeyUsageExtension([CERTIFICATE_REQUEST_AGENT]),
        await x509.SubjectKeyIdentifierExtension.create(publicKey, false, webcrypto as unknown as Crypto),
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
        ...publicationExtensions(input.publication),
      ],
    },
    crypto,
  );
}

/**
 * A Device Certificate for the CSR (DER) signed by `by`: the CSR's subject and subject alternative names (critical when
 * the subject is empty, as RFC 5280 asks), with the key usage and extended key usages (OIDs) given and nothing else the
 * CSR asks for. It names where `by` publishes.
 */
export async function makeDeviceCertificate(
  kms: Kms,
  by: Signer,
  input: { csr: Uint8Array; keyUsage: (keyof typeof x509.KeyUsageFlags)[]; extendedKeyUsages: string[]; notBefore: Date; notAfter: Date; publication: Publication },
) {
  const csr = new x509.Pkcs10CertificateRequest(new Uint8Array(input.csr));
  const subject = new x509.Name(csr.subjectName.toArrayBuffer());
  const san = csr.extensions.find((e) => e.type === SUBJECT_ALT_NAME);
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject,
      issuer: by.certificate.subjectName,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey: csr.publicKey,
      signingKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(input.keyUsage.reduce<number>((flags, usage) => flags | x509.KeyUsageFlags[usage], 0), true),
        new x509.ExtendedKeyUsageExtension(input.extendedKeyUsages),
        // As the CSR encoded them, so that every kind of name it has (an otherName UPN too) is kept as it was.
        ...(san ? [new x509.Extension(SUBJECT_ALT_NAME, subject.toJSON().length === 0, san.value)] : []),
        await x509.SubjectKeyIdentifierExtension.create(csr.publicKey, false, webcrypto as unknown as Crypto),
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
        ...publicationExtensions(input.publication),
      ],
    },
    crypto,
  );
}

/**
 * A CSR for an Issuing CA of `key` and `subject`, signed with that key, for the Organization's own root to sign. It asks
 * for a CA that signs end-entity certificates only (pathLen 0); what the root puts in what it signs is the root's to decide.
 */
export async function makeCaCsr(kms: Kms, key: CaKey, subject: x509.Name) {
  const spki = new Uint8Array(await kms.publicKey(key.key, key.context)).buffer;
  const publicKey = new x509.PublicKey(spki);
  const { crypto, signingKey, signingAlgorithm } = kmsSigning(kms, key);
  return x509.Pkcs10CertificateRequestGenerator.create(
    {
      name: subject,
      keys: { privateKey: signingKey, publicKey: { spki } as unknown as CryptoKey },
      signingAlgorithm,
      extensions: [...(await caExtensions(publicKey, 0))],
    },
    crypto,
  );
}

/** The DER elements in `bytes`, one after another: each one's tag and content. */
function derElements(bytes: Uint8Array) {
  const elements: { tag: number; content: Uint8Array }[] = [];
  for (let i = 0; i < bytes.length; ) {
    const tag = bytes[i++]!;
    let length = bytes[i++]!;
    if (length & 0x80) {
      const octets = length & 0x7f;
      length = 0;
      for (let k = 0; k < octets; k++) length = length * 256 + bytes[i++]!;
    }
    if (i + length > bytes.length) throw new Error("a DER element runs past its end");
    elements.push({ tag, content: bytes.subarray(i, i + length) });
    i += length;
  }
  return elements;
}

/** An iPAddress subtree's base (address, then mask) as CIDR, such as 10.0.0.0/8 or ::/0. */
function ipRange(bytes: Uint8Array) {
  const half = bytes.length / 2;
  const address = bytes.subarray(0, half);
  const prefix = [...bytes.subarray(half)].reduce((bits, byte) => bits + byte.toString(2).replace(/0/g, "").length, 0);
  const text =
    half === 4
      ? [...address].join(".")
      : (Array.from({ length: 8 }, (_, k) => ((address[2 * k]! << 8) | address[2 * k + 1]!).toString(16)).join(":").replace(/(^|:)0(:0)+(:|$)/, "::") || "::");
  return `${text}/${prefix}`;
}

/** A GeneralName (RFC 5280, 4.2.1.6) in words, such as "dns:example.com" or "ip:10.0.0.0/8". */
function generalNameOf({ tag, content }: { tag: number; content: Uint8Array }) {
  const text = () => Buffer.from(content).toString("latin1");
  switch (tag) {
    case 0x81:
      return `email:${text()}`;
    case 0x82:
      return `dns:${text()}`;
    case 0x86:
      return `uri:${text()}`;
    case 0x87:
      return `ip:${ipRange(content)}`;
    case 0xa4:
      return `dn:${new x509.Name(Buffer.from(content)).toString()}`;
    default:
      return `other:${Buffer.from(content).toString("hex")}`;
  }
}

/**
 * A CA certificate's name constraints (RFC 5280, 4.2.1.10): the subtrees it permits and those it excludes, each as
 * `generalNameOf` gives it; none when it has none, or none that can be read.
 */
export function nameConstraintsOf(certificate: x509.X509Certificate): { permitted: string[]; excluded: string[] } | null {
  const extension = certificate.extensions.find((e) => e.type === NAME_CONSTRAINTS);
  if (!extension) return null;
  try {
    const [sequence] = derElements(new Uint8Array(extension.value));
    const parts = derElements(sequence!.content);
    const subtrees = (tag: number) => derElements(parts.find((p) => p.tag === tag)?.content ?? new Uint8Array()).map((subtree) => generalNameOf(derElements(subtree.content)[0]!));
    return { permitted: subtrees(0xa0), excluded: subtrees(0xa1) };
  } catch {
    return null;
  }
}


/** Whether the certificate is a CA's: basic constraints say so, and its key usage, if any, lets it sign certificates. */
function isCaCertificate(certificate: x509.X509Certificate) {
  const constraints = certificate.getExtension(BASIC_CONSTRAINTS) as x509.BasicConstraintsExtension | null;
  const usage = certificate.getExtension(KEY_USAGE) as x509.KeyUsagesExtension | null;
  return constraints?.ca === true && (!usage || (usage.usages & x509.KeyUsageFlags.keyCertSign) !== 0);
}

/** Whether `cert` names `issuer` as its issuer and is signed by its key. */
const isSignedBy = (cert: x509.X509Certificate, issuer: x509.X509Certificate) => cert.issuer === issuer.subject && cert.verify({ publicKey: issuer.publicKey, signatureOnly: true }).catch(() => false);

/**
 * Why the certificate uploaded for the Issuing CA, whose key's public key is `publicKey` (DER) and whose subject is
 * `subject`, may not make it a CA under `root` through `chain` (the one that signs it first) at `now`: it is not for
 * that key or subject, not a CA certificate, not valid now, or does not verify up to the root, a self-signed CA. None
 * when it may. Only signatures, CA flags and validity are checked along the path, not its path lengths or name constraints.
 */
export async function signedCertificateRefusal(certificate: x509.X509Certificate, { publicKey, subject, root, chain, now }: { publicKey: Uint8Array; subject: string; root: x509.X509Certificate; chain: x509.X509Certificate[]; now: Date }) {
  if (!Buffer.from(certificate.publicKey.rawData).equals(Buffer.from(publicKey))) return "the certificate is not for the Issuing CA's key, the one its CSR is for";
  if (!isCaCertificate(certificate)) return "the certificate is not a CA certificate: its basic constraints must make it a CA, and its key usage, if any, must let it sign certificates";
  if (new x509.Name(certificate.subject).toString() !== subject) return `the certificate's subject is ${certificate.subject}, not the Issuing CA's ${subject}`;
  if (certificate.notBefore > now) return "the certificate is not valid yet";
  if (certificate.notAfter <= now) return "the certificate has ended";
  const above = [...chain, root];
  if (!above.every(isCaCertificate)) return "the root and chain must be CA certificates";
  if (above.some((cert) => cert.notAfter <= now)) return "a certificate of the root and chain has ended";
  if (!(await isSignedBy(root, root))) return "the root is not self-signed";
  const path = [certificate, ...above];
  for (let i = 0; i < path.length - 1; i++) {
    if (!(await isSignedBy(path[i]!, path[i + 1]!))) return `the certificate does not verify against the root and chain: ${path[i]!.subject} is not signed by ${path[i + 1]!.subject}`;
  }
  return undefined;
}

/** A certificate on a CRL: its serial (hex), when it was revoked, and its RFC 5280 CRLReason code. */
export interface CrlEntry {
  serial: string;
  revokedAt: Date;
  reason: number;
}

/** A DER INTEGER of a non-negative number. */
function derInteger(n: number) {
  const hex = n.toString(16);
  const bytes = Buffer.from(hex.length % 2 ? `0${hex}` : hex, "hex");
  // A leading 1 bit would make it negative.
  return der(0x02, bytes[0]! & 0x80 ? Buffer.concat([Uint8Array.of(0), bytes]) : bytes);
}

/**
 * A full CRL (RFC 5280, 5) signed by `by`, numbered `number` (its CRL Number, which @peculiar/x509 has no class for),
 * listing `entries`, each with its reason.
 */
export async function makeCrl(kms: Kms, by: Signer, input: { number: number; thisUpdate: Date; nextUpdate: Date; entries: CrlEntry[] }) {
  const { crypto, signingKey, signingAlgorithm } = kmsSigning(kms, by);
  return x509.X509CrlGenerator.create(
    {
      issuer: by.certificate.subjectName,
      thisUpdate: input.thisUpdate,
      nextUpdate: input.nextUpdate,
      signingAlgorithm,
      signingKey,
      // No reason code for `unspecified` (0), as RFC 5280 (5.3.1) asks.
      entries: input.entries.map((entry) => ({ serialNumber: entry.serial, revocationDate: entry.revokedAt, ...(entry.reason !== 0 && { reason: entry.reason }) })),
      extensions: [
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
        new x509.Extension(CRL_NUMBER, false, derInteger(input.number)),
      ],
    },
    crypto,
  );
}
