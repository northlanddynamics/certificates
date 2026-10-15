// The CA module: builds the X.509 certificates a Private CA signs, with @peculiar/x509, and has the KMS sign them with
// the CA's key, which never leaves it (ADR 0007). It owns the certificate profiles (a self-signed root, an Issuing CA
// under it, a TLS server certificate), their serial numbers, the CRL Distribution Point and AIA they name, and the CRLs
// a CA signs.
import * as x509 from "@peculiar/x509";
import { randomBytes, webcrypto } from "node:crypto";
import type { KeyAlgorithm } from "./csr";
import { SIGNATURE_HASH, type Kms } from "./kms";

/** A CA key in the KMS: its reference, the context (an Organization's id) it was made for, and its algorithm. */
export interface CaKey {
  key: string;
  context: string;
  algorithm: KeyAlgorithm;
}

/** A CA that signs: its key, and its certificate, whose subject is the issuer of what it signs. */
export interface Signer extends CaKey {
  certificate: x509.X509Certificate;
}

/** How each key algorithm appears to @peculiar/x509 as a signing key: what tells it how to name the signature. */
const SIGNING_ALGORITHMS: Record<KeyAlgorithm, Algorithm & { hash: string }> = {
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
  const hash = SIGNATURE_HASH[algorithm];
  const subtle = {
    digest: (alg: AlgorithmIdentifier, data: ArrayBuffer) => webcrypto.subtle.digest(alg, data),
    async sign(_alg: unknown, _key: unknown, data: ArrayBuffer) {
      const digest = new Uint8Array(await webcrypto.subtle.digest(hash, data));
      return (await kms.sign(key, context, digest)).slice().buffer;
    },
  };
  const crypto = { subtle, getRandomValues: <T extends ArrayBufferView>(array: T) => webcrypto.getRandomValues(array as any) as T } as unknown as Crypto;
  const signingKey = { algorithm: SIGNING_ALGORITHMS[algorithm], type: "private", extractable: false, usages: ["sign"] } as unknown as CryptoKey;
  return { crypto, signingKey };
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

const EXTENDED_KEY_USAGE = "2.5.29.37";
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
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CrlGenerator.create(
    {
      issuer: by.certificate.subjectName,
      thisUpdate: input.thisUpdate,
      nextUpdate: input.nextUpdate,
      signingAlgorithm: SIGNING_ALGORITHMS[by.algorithm],
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
