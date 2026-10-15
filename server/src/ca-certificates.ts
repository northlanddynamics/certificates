// The CA module: builds the X.509 certificates a Private CA signs, with @peculiar/x509, and has the KMS sign them with
// the CA's key, which never leaves it (ADR 0007). It owns the certificate profiles (a self-signed root, an Issuing CA
// under it, a TLS server certificate) and their serial numbers.
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

const EXTENDED_KEY_USAGE = "2.5.29.37";

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

/** An Issuing CA for `key`, signed by `by`: it may sign end-entity certificates only (pathLen 0). */
export async function makeIssuingCa(kms: Kms, by: Signer, key: CaKey, input: { subject: x509.Name; notBefore: Date; notAfter: Date }) {
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
      extensions: [...(await caExtensions(publicKey, 0)), await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto)],
    },
    crypto,
  );
}

/**
 * A TLS server certificate for the CSR's key and `names`, signed by `by`: serverAuth, and clientAuth too when the CSR
 * asks for it. Its subject is the first name.
 */
export async function makeTlsServer(kms: Kms, by: Signer, input: { csr: string; names: string[]; notBefore: Date; notAfter: Date }) {
  const csr = new x509.Pkcs10CertificateRequest(input.csr);
  // By OID: looked up by class, an extension is not found when two copies of the library are loaded.
  const asked = (csr.getExtension(EXTENDED_KEY_USAGE) as x509.ExtendedKeyUsageExtension | null)?.usages ?? [];
  const usages: string[] = [x509.ExtendedKeyUsage.serverAuth, ...(asked.includes(x509.ExtendedKeyUsage.clientAuth) ? [x509.ExtendedKeyUsage.clientAuth] : [])];
  const rsa = csr.publicKey.algorithm.name === "RSASSA-PKCS1-v1_5" || csr.publicKey.algorithm.name === "RSA-PSS" || csr.publicKey.algorithm.name === "RSA-OAEP";
  const { crypto, signingKey } = kmsSigning(kms, by);
  return x509.X509CertificateGenerator.create(
    {
      serialNumber: newSerial(),
      subject: new x509.Name([{ CN: [input.names[0]!] }]),
      issuer: by.certificate.subjectName,
      notBefore: input.notBefore,
      notAfter: input.notAfter,
      publicKey: csr.publicKey,
      signingKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | (rsa ? x509.KeyUsageFlags.keyEncipherment : 0), true),
        new x509.ExtendedKeyUsageExtension(usages),
        new x509.SubjectAlternativeNameExtension(input.names.map((value) => ({ type: "dns" as const, value }))),
        await x509.SubjectKeyIdentifierExtension.create(csr.publicKey, false, webcrypto as unknown as Crypto),
        await x509.AuthorityKeyIdentifierExtension.create(by.certificate.publicKey, false, webcrypto as unknown as Crypto),
      ],
    },
    crypto,
  );
}
