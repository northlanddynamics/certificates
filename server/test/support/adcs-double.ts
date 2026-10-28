// An Active Directory Certificate Services CA, in memory, for Seam A: what an Agent on a domain-joined Windows host reaches
// with MS-WCCE, as its gMSA. It holds a CA key and chain (an issuing CA under a root, with a CRL Distribution Point), the
// templates it publishes with their facts, and which of them the gMSA may enroll on. The Agent stand-in (agent-double.ts)
// answers ADCS work items from it. (The Go Agent has its own fake behind the same contract; Seam B.)
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import type { TemplateFacts } from "../../src/adcs/adcs-kinds";
import { CLIENT_AUTHENTICATION, SERVER_AUTHENTICATION } from "../../src/adcs/adcs-kinds";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/** How an ADCS operation failed: ADCS answered and said no, or it could not be reached. */
export class AdcsDoubleError extends Error {
  constructor(
    readonly kind: "rejected" | "unreachable",
    message: string,
  ) {
    super(message);
  }
}

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;
const DAY_MS = 24 * 3600_000;

export const CDP_URL = "http://pki.corp.example/CertEnroll/Corp%20Issuing%20CA.crl";

/** The templates a freshly made double publishes: one for TLS, one for devices, and one that builds its subject from Active Directory. */
export const defaultTemplates = (): TemplateFacts[] => [
  {
    name: "CorpWebServer",
    oid: "1.3.6.1.4.1.311.21.8.1.1",
    displayName: "Corp Web Server",
    extendedKeyUsages: [SERVER_AUTHENTICATION],
    validityDays: 365,
    minimumKeySize: 2048,
    keyAlgorithms: ["rsa", "ecdsa-p256"],
    managerApproval: false,
    subjectFromRequest: true,
    enrollable: true,
    published: true,
  },
  {
    name: "CorpDevice",
    oid: "1.3.6.1.4.1.311.21.8.1.2",
    displayName: "Corp Device",
    extendedKeyUsages: [CLIENT_AUTHENTICATION],
    validityDays: 730,
    minimumKeySize: 2048,
    keyAlgorithms: ["rsa"],
    managerApproval: true,
    subjectFromRequest: true,
    enrollable: true,
    published: true,
  },
  {
    name: "Workstation",
    oid: "1.3.6.1.4.1.311.21.8.1.3",
    displayName: "Workstation Authentication",
    extendedKeyUsages: [CLIENT_AUTHENTICATION],
    validityDays: 365,
    minimumKeySize: 2048,
    keyAlgorithms: ["rsa"],
    managerApproval: false,
    subjectFromRequest: false,
    enrollable: true,
    published: true,
  },
];

async function makeCa(subject: string, issuer: { subject: string; keys: CryptoKeyPair } | null, now: Date, extensions: x509.Extension[] = []) {
  const keys = (await webcrypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;
  const certificate = await x509.X509CertificateGenerator.create({
    serialNumber: "01" + Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString("hex"),
    subject,
    issuer: issuer?.subject ?? subject,
    notBefore: new Date(now.getTime() - DAY_MS),
    notAfter: new Date(now.getTime() + 5 * 365 * DAY_MS),
    signingAlgorithm: ALGORITHM,
    publicKey: keys.publicKey,
    signingKey: (issuer?.keys ?? keys).privateKey,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true), ...extensions],
  });
  return { subject, keys, certificate };
}

export class AdcsDouble {
  /** The templates it publishes and knows of, with their facts. */
  templates: TemplateFacts[] = defaultTemplates();
  /** When set, every operation fails this way, as a CA that is down (`unreachable`) or refuses the gMSA (`rejected`) does. */
  failure: AdcsDoubleError | null = null;
  /** When set, the chain discovery reports in place of its own, as a misbehaving Agent or CA might. */
  reportedChain: string[] | null = null;
  /** How often it was asked to discover. */
  discoveries = 0;

  private constructor(
    /** Its config string, `host\CA Name`. */
    readonly configString: string,
    readonly root: { subject: string; keys: CryptoKeyPair; certificate: x509.X509Certificate },
    readonly ca: { subject: string; keys: CryptoKeyPair; certificate: x509.X509Certificate },
  ) {}

  static async create(configString = "ca01.corp.example\\Corp Issuing CA", now = new Date()) {
    const root = await makeCa("CN=Corp Root CA, DC=corp, DC=example", null, now);
    const ca = await makeCa("CN=Corp Issuing CA, DC=corp, DC=example", root, now, [new x509.CRLDistributionPointsExtension([CDP_URL])]);
    return new AdcsDouble(configString, root, ca);
  }

  /** The CA certificate, then the root, PEM. */
  get chainPem() {
    return [this.ca.certificate.toString("pem"), this.root.certificate.toString("pem")];
  }

  /** The CA at `configString`, or how reaching it fails: an unknown host cannot be reached, and an unknown CA name on it is refused. */
  private reach(configString: string) {
    if (this.failure) throw this.failure;
    const [host, name] = configString.split("\\");
    const [myHost, myName] = this.configString.split("\\");
    if (host?.toLowerCase() !== myHost!.toLowerCase()) throw new AdcsDoubleError("unreachable", `the RPC server is unavailable at ${host}`);
    if (name?.toLowerCase() !== myName!.toLowerCase()) throw new AdcsDoubleError("rejected", `${host} has no CA named ${name}`);
  }

  /** What `adcs.discover` finds: the chain, and the templates with their facts. */
  discover(configString: string) {
    this.reach(configString);
    this.discoveries++;
    return { chain: this.reportedChain ?? this.chainPem, templates: this.templates.map((t) => ({ ...t })) };
  }
}
