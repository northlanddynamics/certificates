// An Agent as the platform sees it, for Seam A: it makes its own identity key, registers, and speaks the protocol
// with its identity certificate in the header a TLS terminator would pass it in. (The real Agent is the Go program
// in agent/, which Seam B runs against a stub of the platform.)
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import type { Harness } from "./harness";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export const CERTIFICATE_HEADER = "x-client-cert";
const SIGNING = { name: "ECDSA", hash: "SHA-256" } as const;

/** A fresh key with a CSR for it, as an Agent would send; `curve` is P-256 unless a test wants a key the platform must refuse. */
export async function newIdentityRequest(curve: "P-256" | "P-384" = "P-256") {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: "CN=agent",
    keys,
    signingAlgorithm: { name: "ECDSA", hash: curve === "P-256" ? "SHA-256" : "SHA-384" },
  } as Parameters<typeof x509.Pkcs10CertificateRequestGenerator.create>[0]);
  return { keys, csr: csr.toString("pem") };
}

/** A certificate for `agentId` that the identity CA never issued: signed by a CA of the test's own. */
export async function forgedIdentity(agentId: string) {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${agentId}`,
    notBefore: new Date("2025-01-01"),
    notAfter: new Date("2030-01-01"),
    signingAlgorithm: SIGNING,
    keys,
  } as Parameters<typeof x509.X509CertificateGenerator.createSelfSigned>[0]);
  return cert.toString("pem");
}

export const asHeader = (certificatePem: string) => ({ [CERTIFICATE_HEADER]: encodeURIComponent(certificatePem) });

export interface Registration {
  token: string;
  hostName?: string;
  os?: string;
  arch?: string;
  version?: string;
}

export class TestAgent {
  private constructor(
    private readonly h: Harness,
    readonly id: string,
    readonly organizationId: string,
    /** The identity certificate it presents (PEM). */
    public certificate: string,
    public notAfter: string,
  ) {}

  /** Registers an Agent with the token, as the Agent does; returns it, or the refusal. */
  static async register(h: Harness, reg: Registration, csr?: string) {
    const res = await h.api("/api/agent/registration", {
      body: { token: reg.token, csr: csr ?? (await newIdentityRequest()).csr, hostName: reg.hostName ?? "host-1", os: reg.os ?? "linux", arch: reg.arch ?? "amd64", version: reg.version ?? "0.1.0" },
    });
    return { res, agent: res.status === 201 ? new TestAgent(h, res.body.agentId, "", res.body.certificate, res.body.notAfter) : undefined };
  }

  /** Registers with a token made by the Organization's administrator; throws when it is refused. */
  static async registered(h: Harness, adminCookie: string, orgId: string, reg: Omit<Registration, "token"> = {}) {
    const made = await h.api(`/api/organizations/${orgId}/agent-registration-tokens`, { cookie: adminCookie, method: "POST", body: {} });
    if (made.status !== 201) throw new Error(`no registration token: ${made.status}`);
    const { res, agent } = await TestAgent.register(h, { ...reg, token: made.body.token });
    if (!agent) throw new Error(`registration refused: ${res.status} ${JSON.stringify(res.body)}`);
    return agent;
  }

  /** A call to the Agent protocol with a certificate in the terminator's header: this Agent's, unless given another (or none). */
  call(path: string, body: unknown, certificate: string | null = this.certificate) {
    return this.h.api(path, { body, headers: certificate ? asHeader(certificate) : undefined });
  }

  poll(version = "0.1.0", certificate?: string | null) {
    return this.call("/api/agent/poll", { version }, certificate);
  }

  /** Asks for a new identity certificate for a new key; this Agent takes the new one when it is issued. */
  async rotate(certificate: string | null = this.certificate) {
    const res = await this.call("/api/agent/identity", { csr: (await newIdentityRequest()).csr }, certificate);
    if (res.status === 200) {
      this.certificate = res.body.certificate;
      this.notAfter = res.body.notAfter;
    }
    return res;
  }
}
