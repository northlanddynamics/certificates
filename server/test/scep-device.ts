// A SCEP device for tests: it enrolls at an Enrollment Profile's SCEP URL as a real device would, through ts-scep's
// client, which builds the GetCACaps, GetCACert and PKCSReq messages (signed and enveloped data) and parses the CertRep.
// It talks to the platform in-process, through the harness's app, with no credentials.
import { X509Certificate } from "node:crypto";
import { ScepClient, createCsr, generateRsaKeyPair, type CreateCsrOptions, type SubjectAltNames } from "ts-scep";
import type { Harness } from "./harness";

export interface DeviceRequest {
  /** RFC 4514, such as "CN=device-01, O=Acme". */
  subject: string;
  subjectAltNames?: SubjectAltNames;
  /** RSA modulus length of the key the device makes; 2048 unless given. */
  keyBits?: number;
  challengePassword?: string;
  /** What else the CSR asks for: extended key usage OIDs, and extensions of any kind. */
  extendedKeyUsage?: string[];
  extensions?: CreateCsrOptions["extensions"];
}

export interface ScepDevice {
  client: ScepClient;
  /** Makes a key and a CSR for `request` and enrolls; resolves with the certificate and the CertRep's chain, or throws ts-scep's ScepFailureError. */
  enroll(request: DeviceRequest): Promise<{ certificate: X509Certificate; certificates: X509Certificate[] }>;
}

/** A device enrolling at `scepUrl`, sending PKIOperation by POST unless `usePost` is false. */
export function scepDevice(h: Harness, scepUrl: string, { usePost }: { usePost?: boolean } = {}): ScepDevice {
  const client = new ScepClient({
    url: scepUrl,
    usePost,
    // What the tracer supports: PKCS#1 v1.5 key transport and AES content encryption.
    keyTransport: "rsa-pkcs1",
    encryptionAlgorithm: "aes-128-cbc",
    fetch: async (input, init) => h.app.request(String(input), init),
  });
  return {
    client,
    async enroll({ subject, subjectAltNames, keyBits = 2048, challengePassword, extendedKeyUsage, extensions }) {
      const { privateKey } = generateRsaKeyPair(keyBits);
      const csr = createCsr({ subject, privateKey, challengePassword, subjectAltNames, extendedKeyUsage, extensions });
      const result = await client.enroll({ csr, privateKey });
      if (result.status !== 0) throw new Error(`the platform answered PENDING, which it never should`);
      return { certificate: result.certificate, certificates: result.certificates };
    },
  };
}
