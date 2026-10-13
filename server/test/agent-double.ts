// An Agent as the platform sees it, for Seam A: it makes its own identity key, registers, and speaks the protocol
// with its identity certificate in the header a TLS terminator would pass it in. (The real Agent is the Go program
// in agent/, which Seam B runs against a stub of the platform.)
import * as x509 from "@peculiar/x509";
import * as acme from "acme-client";
import { createHash, webcrypto } from "node:crypto";
import { DnsProviderError } from "../src/dns-provider";
import { DNS_PROVIDER_KINDS } from "../src/dns-provider-kinds";
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

export interface WorkItem {
  id: string;
  type: string;
  payload: any;
}

/** What the stand-in's "script" does when it is run: it runs nothing, it reports this. */
export interface ScriptOutcome {
  exitCode: number | null;
  output: string;
  outputTruncated?: boolean;
}

/** A Deployment the stand-in was asked to carry out, as it saw it. */
export interface DeployedRun {
  item: WorkItem;
  /** Whether the script's content hashed to the hash it was given: the Agent runs it only if so. */
  hashMatched: boolean;
  /** The private key it holds for the Certificate's Managed Certificate (PEM): it never sends this anywhere. */
  keyPem: string | undefined;
}

const KEY_MAKERS = {
  "ecdsa-p256": () => acme.crypto.createPrivateEcdsaKey("P-256"),
  "ecdsa-p384": () => acme.crypto.createPrivateEcdsaKey("P-384"),
  "rsa-2048": () => acme.crypto.createPrivateRsaKey(2048),
  "rsa-3072": () => acme.crypto.createPrivateRsaKey(3072),
  "rsa-4096": () => acme.crypto.createPrivateRsaKey(4096),
} as const;

export class TestAgent {
  /** Every work item this Agent has been given, in order. */
  readonly received: WorkItem[] = [];
  /** The work items it carried out (to the end, whatever the outcome), in order. */
  readonly executed: WorkItem[] = [];
  /** Makes it take work items and never answer them, as an Agent that stalled or lost its connection does. */
  stalled = false;
  /** The private keys it generated, by Managed Certificate (PEM); they stay here, as on the Agent's host. */
  readonly keys = new Map<string, string>();
  /** The Deployments it carried out, in order. */
  readonly deployed: DeployedRun[] = [];
  /** Makes the script reach it altered, as one corrupted on its way does: it must see that it does not match its hash and not run it. */
  corruptScripts = false;
  /** What the script it "runs" does. */
  scriptOutcome: ScriptOutcome = { exitCode: 0, output: "installed" };

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

  /** Reports how a work item went. */
  report(id: string, result: Record<string, unknown> & { ok: boolean }, certificate: string | null = this.certificate) {
    return this.call(`/api/agent/work-items/${id}/result`, result, certificate);
  }

  /**
   * Polls once and carries out the DNS Provider work items it is given, as the Agent does: with the provider code the
   * platform itself runs (the Agent proper is Go, which has its own; Seam B), and reports how each went.
   */
  async work(): Promise<WorkItem[]> {
    const polled = await this.poll();
    if (polled.status !== 200) return [];
    const items = polled.body.items as WorkItem[];
    this.received.push(...items);
    if (this.stalled) return items;
    for (const item of items) {
      await this.carryOut(item);
      this.executed.push(item);
    }
    return items;
  }

  private async carryOut(item: WorkItem) {
    if (item.type === "deployment.generate_key") return this.generateKey(item);
    if (item.type === "deployment.run") return this.runDeployment(item);
    const { provider, record } = item.payload;
    try {
      const kind = DNS_PROVIDER_KINDS[provider.type as keyof typeof DNS_PROVIDER_KINDS];
      const dns = kind.create(kind.settings.parse(provider.settings), provider.secret);
      if (item.type === "dns.present") await dns.presentTxt(record);
      else if (item.type === "dns.cleanup") await dns.cleanUpTxt(record);
      else if (item.type === "dns.test") await dns.testConnection();
      else throw new Error(`a work item of a type this Agent does not know: ${item.type}`);
      await this.report(item.id, { ok: true });
    } catch (err) {
      if (!(err instanceof DnsProviderError)) throw err;
      await this.report(item.id, { ok: false, kind: err.kind, error: err.message });
    }
  }

  /** Makes the key for the Managed Certificate here and reports a CSR for it, as the Agent does. */
  private async generateKey(item: WorkItem) {
    const { managedCertificateId, names, keyAlgorithm } = item.payload as { managedCertificateId: string; names: string[]; keyAlgorithm: keyof typeof KEY_MAKERS };
    const key = await KEY_MAKERS[keyAlgorithm]();
    const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
    this.keys.set(managedCertificateId, key.toString());
    await this.report(item.id, { ok: true, csr: csr.toString() });
  }

  /** Checks the script against its hash and, if it matches, "runs" it: reports `scriptOutcome`. */
  private async runDeployment(item: WorkItem) {
    const { managedCertificateId, script } = item.payload as { managedCertificateId: string; script: { content: string; hash: string } };
    const content = this.corruptScripts ? `${script.content}\n# altered` : script.content;
    const hashMatched = createHash("sha256").update(content, "utf8").digest("hex") === script.hash;
    this.deployed.push({ item, hashMatched, keyPem: this.keys.get(managedCertificateId) });
    const startedAt = new Date().toISOString();
    const outcome: ScriptOutcome = hashMatched ? this.scriptOutcome : { exitCode: null, output: "the script does not match its hash, so it was not run" };
    await this.report(item.id, {
      ok: outcome.exitCode === 0,
      ...(outcome.exitCode !== 0 && { error: outcome.exitCode === null ? outcome.output : `the script exited with ${outcome.exitCode}` }),
      run: { startedAt, finishedAt: new Date().toISOString(), exitCode: outcome.exitCode, output: outcome.output, outputTruncated: outcome.outputTruncated ?? false },
    });
  }

  /** Has the Agent poll and work every `everyMs` until the returned function is called, which waits for what it is doing. */
  startWorking(everyMs = 20): () => Promise<void> {
    let running = true;
    const loop = (async () => {
      while (running) {
        await this.work();
        await new Promise((resolve) => setTimeout(resolve, everyMs));
      }
    })();
    return async () => {
      running = false;
      await loop;
    };
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
