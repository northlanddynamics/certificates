// A SCEP device for tests: it enrolls at an Enrollment Profile's SCEP URL as a real device would, through ts-scep's
// client, which builds the GetCACaps, GetCACert and PKCSReq messages (signed and enveloped data) and parses the CertRep.
// It talks to the platform in-process, through the harness's app, with no credentials.
import type { KeyObject, X509Certificate } from "node:crypto";
import { ScepClient, certificateSubject, createCsr, createSelfSignedCertificate, generateRsaKeyPair, parseCsr, type CreateCsrOptions, type DigestAlgorithm, type EncryptionAlgorithm, type KeyTransportAlgorithm, type SubjectAltNames } from "ts-scep";
import type { Harness } from "./harness";

export interface DeviceRequest {
  /** RFC 4514, such as "CN=device-01, O=Acme". */
  subject: string;
  subjectAltNames?: SubjectAltNames;
  /** RSA modulus length of the key the device makes; 2048 unless given. */
  keyBits?: number;
  /** A key the device already made, to send the same request again; it makes one unless given. */
  privateKey?: KeyObject;
  challengePassword?: string;
  /** The SCEP transaction ID; ts-scep's (a hash of the device's public key) unless given. */
  transactionId?: string;
  /** What else the CSR asks for: extended key usage OIDs, and extensions of any kind. */
  extendedKeyUsage?: string[];
  extensions?: CreateCsrOptions["extensions"];
}

/** What a device holds once enrolled. */
export interface Enrolled {
  certificate: X509Certificate;
  certificates: X509Certificate[];
  privateKey: KeyObject;
}

export interface ScepDevice {
  client: ScepClient;
  /** Makes a key and a CSR for `request` and enrolls (PKCSReq); resolves with the certificate, the CertRep's chain and the key, or throws ts-scep's ScepFailureError. */
  enroll(request: DeviceRequest): Promise<Enrolled>;
  /** Like `enroll`, with a new key, but a RenewalReq signed with what the device holds. */
  renew(request: DeviceRequest, current: Enrolled): Promise<Enrolled>;
  /** Asks after the request with the key and transaction ID (GetCertInitial, CertPoll in RFC 8894), as a client that was answered PENDING would. */
  poll(request: DeviceRequest & { privateKey: KeyObject; transactionId: string }): Promise<Enrolled>;
}

export interface DeviceOptions {
  /** PKIOperation by POST unless false. */
  usePost?: boolean;
  /** How it encrypts the content key to the RA: PKCS#1 v1.5 unless given. */
  keyTransport?: KeyTransportAlgorithm;
  /** How it encrypts its request: AES-128 unless given. */
  encryptionAlgorithm?: EncryptionAlgorithm;
  /** The digest it signs with: what GetCACaps offers unless given. */
  digestAlgorithm?: DigestAlgorithm;
}

/** The address every such device sends from, as the platform's TLS terminator would tell it in X-Forwarded-For. */
const DEVICE_ADDRESS = "192.0.2.1";

/** A device enrolling at `scepUrl`. */
export function scepDevice(h: Harness, scepUrl: string, { usePost, keyTransport = "rsa-pkcs1", encryptionAlgorithm = "aes-128-cbc", digestAlgorithm }: DeviceOptions = {}): ScepDevice {
  const client = new ScepClient({
    url: scepUrl,
    usePost,
    keyTransport,
    encryptionAlgorithm,
    digestAlgorithm,
    headers: { "x-forwarded-for": DEVICE_ADDRESS },
    fetch: async (input, init) => h.app.request(String(input), init),
  });
  const csrOf = ({ subject, subjectAltNames, challengePassword, extendedKeyUsage, extensions }: DeviceRequest, privateKey: KeyObject) =>
    createCsr({ subject, privateKey, challengePassword, subjectAltNames, extendedKeyUsage, extensions });
  async function send(request: DeviceRequest, current?: Enrolled): Promise<Enrolled> {
    const { transactionId, keyBits = 2048 } = request;
    const privateKey = request.privateKey ?? generateRsaKeyPair(keyBits).privateKey;
    const csr = csrOf(request, privateKey);
    const result = await client.enroll({ csr, privateKey, transactionId, ...(current && { signer: current, renewal: true }) });
    if (result.status !== 0) throw new Error(`the platform answered PENDING, which it never should`);
    return { certificate: result.certificate, certificates: result.certificates, privateKey };
  }
  async function poll(request: DeviceRequest & { privateKey: KeyObject; transactionId: string }): Promise<Enrolled> {
    const { privateKey, transactionId } = request;
    const csr = csrOf(request, privateKey);
    const { ca } = await client.getCACert();
    const subject = parseCsr(csr).subject;
    const identity = { certificate: createSelfSignedCertificate({ subject, privateKey }), privateKey };
    const result = await client.poll({ transactionId, issuer: certificateSubject(ca), subject, identity, csr });
    if (result.status !== 0) throw new Error(`the platform answered PENDING, which it never should`);
    return { certificate: result.certificate, certificates: result.certificates, privateKey };
  }
  return { client, enroll: (request) => send(request), renew: (request, current) => send(request, current), poll };
}
