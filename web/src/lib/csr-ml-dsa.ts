// Makes an ML-DSA key and a CSR with `@noble/post-quantum`, a pure-JS ML-DSA, for a browser whose WebCrypto has none, and
// checks an ML-DSA CSR's signature for the viewer. Loaded only once an ML-DSA algorithm is chosen or read (csr-generator.ts
// and csr-details.ts import it on demand). Pure, like the generator: it uses no fetch, so there is nowhere in it for a
// key or a CSR to be sent (ADR 0002).
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Attributes, CertificationRequest, CertificationRequestInfo } from "@peculiar/asn1-csr";
import { ExtensionRequest, id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import { AlgorithmIdentifier, Attribute, Extension, Name, SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import { sanExtension, type GeneratedCsr, type MlDsaKeyAlgorithm } from "./csr-generator";

// RFC 9881: pure ML-DSA, identified by these OIDs for the key and the signature alike, with the parameters absent.
const ML_DSA: Record<MlDsaKeyAlgorithm, { oid: string; ml: typeof ml_dsa65 }> = {
  "ml-dsa-44": { oid: "2.16.840.1.101.3.4.3.17", ml: ml_dsa44 },
  "ml-dsa-65": { oid: "2.16.840.1.101.3.4.3.18", ml: ml_dsa65 },
  "ml-dsa-87": { oid: "2.16.840.1.101.3.4.3.19", ml: ml_dsa87 },
};

/**
 * The RFC 9881 seed-form PrivateKeyInfo, which OpenSSL 3.5 and Bun read: version 0, the algorithm with no parameters, and
 * a privateKey OCTET STRING holding `[0] IMPLICIT OCTET STRING` of the 32-byte seed. Its length is the same for all three.
 */
function seedPkcs8(oid: string, seed: Uint8Array): Uint8Array {
  // SEQUENCE { INTEGER 0, SEQUENCE { OID 2.16.840.1.101.3.4.3.<id> }, OCTET STRING { 80 20 <seed> } }; the id is the OID's last arc.
  const id = Number(oid.split(".").at(-1));
  return Uint8Array.from([0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, id, 0x04, 0x22, 0x80, 0x20, ...seed]);
}

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

/** A new ML-DSA key from a random seed, and a CSR for it built as the Agent builds its own: a subject, the key's SPKI, and the SAN in an extensionRequest. */
export async function generateMlDsaCsrWithNoble(keyAlgorithm: MlDsaKeyAlgorithm, name: x509.JsonName, names: string[]): Promise<GeneratedCsr> {
  const { oid, ml } = ML_DSA[keyAlgorithm];
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const { publicKey, secretKey } = ml.keygen(seed);

  const algorithm = new AlgorithmIdentifier({ algorithm: oid });
  const san = sanExtension(names);
  const info = new CertificationRequestInfo({
    version: 0,
    subject: AsnConvert.parse(new x509.Name(name).toArrayBuffer(), Name),
    subjectPKInfo: new SubjectPublicKeyInfo({ algorithm, subjectPublicKey: toArrayBuffer(publicKey) }),
    attributes: new Attributes([
      new Attribute({
        type: id_pkcs9_at_extensionRequest,
        // Extensions is a SEQUENCE of Extension; leaving out that SEQUENCE loses the SAN in Go's parser.
        values: [AsnConvert.serialize(new ExtensionRequest([AsnConvert.parse(san.rawData, Extension)]))],
      }),
    ]),
  });
  // Randomized pure ML-DSA with an empty context.
  const signature = ml.sign(new Uint8Array(AsnConvert.serialize(info)), secretKey);
  const csr = AsnConvert.serialize(new CertificationRequest({ certificationRequestInfo: info, signatureAlgorithm: algorithm, signature: toArrayBuffer(signature) }));
  return { keyPem: x509.PemConverter.encode(toArrayBuffer(seedPkcs8(oid, seed)), "PRIVATE KEY"), csrPem: x509.PemConverter.encode(csr, "CERTIFICATE REQUEST") };
}

/** Whether an ML-DSA CSR's signature verifies against its own public key, for a browser whose WebCrypto cannot check one; false for anything that is not an ML-DSA CSR. */
export function verifyMlDsaCsr(der: ArrayBuffer): boolean {
  const csr = AsnConvert.parse(der, CertificationRequest);
  const entry = Object.values(ML_DSA).find((candidate) => candidate.oid === csr.signatureAlgorithm.algorithm);
  if (!entry) return false;
  const message = new Uint8Array(AsnConvert.serialize(csr.certificationRequestInfo));
  return entry.ml.verify(new Uint8Array(csr.signature), message, new Uint8Array(csr.certificationRequestInfo.subjectPKInfo.subjectPublicKey));
}
