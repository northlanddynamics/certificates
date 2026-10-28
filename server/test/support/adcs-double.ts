// An Active Directory Certificate Services CA, in memory, for Seam A: what an Agent on a domain-joined Windows host reaches
// with MS-WCCE, as its gMSA. It holds a CA key and chain (an issuing CA under a root, with a CRL Distribution Point), the
// templates it publishes with their facts, and which of them the gMSA may enroll on, and it issues what is submitted under a
// template it publishes and the gMSA may enroll on, with the names the request supplies and the template's validity. A
// request under a template that needs CA manager approval, or any while `hold` is set, is held pending until a CA manager
// approves or denies it (`approve`, `deny`); while `denyWith` is set, every request is denied at once. The Agent stand-in
// (agent-double.ts) answers ADCS work items from it. (The Go Agent has its own fake behind the same contract; Seam B.)
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

/** What ADCS answers a request with, or holds it as, as `adcs.submit` and `adcs.check` report it. */
export type Disposition = { status: "issued"; requestId: string; certificate: string } | { status: "pending"; requestId: string } | { status: "denied"; requestId: string; message: string };

export class AdcsDouble {
  /** The templates it publishes and knows of, with their facts. */
  templates: TemplateFacts[] = defaultTemplates();
  /** When set, every operation fails this way, as a CA that is down (`unreachable`) or refuses the gMSA (`rejected`) does. */
  failure: AdcsDoubleError | null = null;
  /** When set, the chain discovery reports in place of its own, as a misbehaving Agent or CA might. */
  reportedChain: string[] | null = null;
  /** How often it was asked to discover. */
  discoveries = 0;
  /** Its clock, which what it issues is valid from. */
  now: () => Date = () => new Date();
  /** What it issued, in order: ADCS's request ID, the template's name and the Certificate. */
  readonly issued: { requestId: string; template: string; certificate: x509.X509Certificate }[] = [];
  /** Holds every request it is submitted pending, for a CA manager, as a template that needs approval does. */
  hold = false;
  /** When set, denies every request it is submitted, with this disposition message, as its policy module might. */
  denyWith: string | null = null;
  /** The requests it holds pending, by ADCS's request ID, and those it denied, with why. */
  readonly pending = new Map<string, { template: TemplateFacts; csrPem: string }>();
  readonly denied = new Map<string, string>();
  /** How often it was asked where a request stands. */
  checks = 0;
  private nextRequestId = 100;

  private constructor(
    /** Its config string, `host\CA Name`. */
    readonly configString: string,
    readonly root: { subject: string; keys: CryptoKeyPair; certificate: x509.X509Certificate },
    public ca: { subject: string; keys: CryptoKeyPair; certificate: x509.X509Certificate },
  ) {}

  static async create(configString = "ca01.corp.example\\Corp Issuing CA", now = new Date()) {
    const root = await makeCa("CN=Corp Root CA, DC=corp, DC=example", null, now);
    const ca = await makeCa("CN=Corp Issuing CA, DC=corp, DC=example", root, now, [new x509.CRLDistributionPointsExtension([CDP_URL])]);
    return new AdcsDouble(configString, root, ca);
  }

  /** Renews its CA certificate, with a new key, under the same root and with the same subject, as ADCS does. */
  async renew(now = new Date()) {
    this.ca = await makeCa(this.ca.subject, this.root, now, [new x509.CRLDistributionPointsExtension([CDP_URL])]);
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

  /**
   * What `adcs.submit` gets: the CSR (PEM) submitted under the template, issued at once with the names the request supplies,
   * the template's EKUs and validity (never past the CA's end), signed by its CA certificate; held pending under a template
   * that needs CA manager approval, or while `hold` is set; or denied while `denyWith` is. A template it does not publish,
   * or the gMSA may not enroll on, is refused, as ADCS refuses it.
   */
  async submit(configString: string, templateName: string, csrPem: string): Promise<Disposition> {
    this.reach(configString);
    const template = this.templates.find((t) => t.name.toLowerCase() === templateName.toLowerCase());
    if (!template?.published) throw new AdcsDoubleError("rejected", `The requested certificate template is not supported by this CA: ${templateName}`);
    if (!template.enrollable) throw new AdcsDoubleError("rejected", `Access is denied: the account may not enroll on ${templateName}`);
    if (!template.subjectFromRequest) throw new AdcsDoubleError("rejected", `${templateName} builds the subject from Active Directory`);
    const requestId = String(this.nextRequestId++);
    if (this.denyWith !== null) {
      this.denied.set(requestId, this.denyWith);
      return { status: "denied", requestId, message: this.denyWith };
    }
    if (this.hold || template.managerApproval) {
      this.pending.set(requestId, { template, csrPem });
      return { status: "pending", requestId };
    }
    return this.issue(requestId, template, csrPem);
  }

  /** What `adcs.check` gets: where the request stands now. A request it never had is refused. */
  async check(configString: string, requestId: string): Promise<Disposition> {
    this.reach(configString);
    this.checks++;
    if (this.pending.has(requestId)) return { status: "pending", requestId };
    const denial = this.denied.get(requestId);
    if (denial !== undefined) return { status: "denied", requestId, message: denial };
    const issued = this.issued.find((i) => i.requestId === requestId);
    if (!issued) throw new AdcsDoubleError("rejected", `the CA has no request ${requestId}`);
    return { status: "issued", requestId, certificate: issued.certificate.toString("pem") };
  }

  /** A CA manager approves the pending request: it is issued. */
  async approve(requestId: string) {
    const held = this.pending.get(requestId);
    if (!held) throw new Error(`no pending request ${requestId}`);
    this.pending.delete(requestId);
    await this.issue(requestId, held.template, held.csrPem);
  }

  /** A CA manager denies the pending request, saying why. */
  deny(requestId: string, message: string) {
    if (!this.pending.delete(requestId)) throw new Error(`no pending request ${requestId}`);
    this.denied.set(requestId, message);
  }

  /** Issues the request: the CSR's subject and names, the template's EKUs and validity (never past the CA's end). */
  private async issue(requestId: string, template: TemplateFacts, csrPem: string): Promise<Disposition> {
    const now = this.now();
    const csr = new x509.Pkcs10CertificateRequest(csrPem);
    // The subject alternative names the request supplies, as it has them.
    const requested = csr.getExtension("2.5.29.17");
    const notAfter = Math.min(now.getTime() + template.validityDays * DAY_MS, this.ca.certificate.notAfter.getTime());
    const certificate = await x509.X509CertificateGenerator.create({
      serialNumber: "61" + Buffer.from(webcrypto.getRandomValues(new Uint8Array(9))).toString("hex"),
      subject: csr.subject,
      issuer: this.ca.subject,
      notBefore: new Date(now.getTime() - 60_000),
      notAfter: new Date(notAfter),
      signingAlgorithm: ALGORITHM,
      publicKey: csr.publicKey,
      signingKey: this.ca.keys.privateKey,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.ExtendedKeyUsageExtension(template.extendedKeyUsages),
        new x509.CRLDistributionPointsExtension([CDP_URL]),
        ...(requested ? [requested] : []),
      ],
    });
    this.issued.push({ requestId, template: template.name, certificate });
    return { status: "issued", requestId, certificate: certificate.toString("pem") };
  }
}
