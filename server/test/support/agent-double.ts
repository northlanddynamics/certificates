// An Agent as the platform sees it, for Seam A: it registers and speaks the protocol with the credential it was given
// (ADR 0006). (The real Agent is the Go program in agent/, which Seam B runs against a stub of the platform.)
import * as acme from "acme-client";
import * as x509 from "@peculiar/x509";
import { createHash, webcrypto } from "node:crypto";
import { DnsProviderError } from "../../src/issuance/dcv/dns-provider";
import { DNS_PROVIDER_KINDS } from "../../src/issuance/dcv/dns-provider-kinds";
import { isMlDsa, type KeyAlgorithm } from "../../src/pki/key-algorithms";
import type { Harness } from "./harness";
import { AdcsDoubleError, type AdcsDouble } from "./adcs-double";

/** The headers of a call that carries `credential`. */
export const asBearer = (credential: string) => ({ authorization: `Bearer ${credential}` });

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

/** An ML-DSA key (with Bun's native ML-DSA) and a CSR for it, as the Agent makes them: the key as a PEM, and the CSR as a PEM. */
async function mlDsaKeyAndCsr(keyAlgorithm: KeyAlgorithm, names: string[]) {
  const algorithm = { name: keyAlgorithm.toUpperCase() };
  const keys = (await webcrypto.subtle.generateKey(algorithm, true, ["sign", "verify"])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create(
    { name: `CN=${names[0]}`, keys, signingAlgorithm: algorithm, extensions: [new x509.SubjectAlternativeNameExtension(names.map((value) => ({ type: "dns" as const, value })))] },
    webcrypto as unknown as Crypto,
  );
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  return { key: `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`, csr: csr.toString("pem") };
}

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
  /** The ADCS it reaches, as a domain-joined Windows host does; none, and it answers ADCS work items as an Agent off Windows does. */
  adcs: AdcsDouble | null = null;

  private constructor(
    private readonly h: Harness,
    readonly id: string,
    readonly organizationId: string,
    /** The credential it presents. */
    public credential: string,
    public expiresAt: string,
  ) {}

  /** Registers an Agent with the token, as the Agent does; returns it, or the refusal. */
  static async register(h: Harness, reg: Registration) {
    const res = await h.api("/api/agent/registration", {
      body: { token: reg.token, hostName: reg.hostName ?? "host-1", os: reg.os ?? "linux", arch: reg.arch ?? "amd64", version: reg.version ?? "0.1.0" },
    });
    return { res, agent: res.status === 201 ? new TestAgent(h, res.body.agentId, "", res.body.credential, res.body.expiresAt) : undefined };
  }

  /** Registers with a token made by the Organization's administrator; throws when it is refused. */
  static async registered(h: Harness, adminCookie: string, orgId: string, reg: Omit<Registration, "token"> = {}) {
    const made = await h.api(`/api/organizations/${orgId}/agent-registration-tokens`, { cookie: adminCookie, method: "POST", body: {} });
    if (made.status !== 201) throw new Error(`no registration token: ${made.status}`);
    const { res, agent } = await TestAgent.register(h, { ...reg, token: made.body.token });
    if (!agent) throw new Error(`registration refused: ${res.status} ${JSON.stringify(res.body)}`);
    return agent;
  }

  /** A call to the Agent protocol with a credential: this Agent's, unless given another (or none). */
  call(path: string, body: unknown, credential: string | null = this.credential) {
    return this.h.api(path, { method: "POST", body: body ?? undefined, headers: credential ? asBearer(credential) : undefined });
  }

  poll(version = "0.1.0", credential?: string | null) {
    return this.call("/api/agent/poll", { version }, credential);
  }

  /** Reports how a work item went. */
  report(id: string, result: Record<string, unknown> & { ok: boolean }, credential: string | null = this.credential) {
    return this.call(`/api/agent/work-items/${id}/result`, result, credential);
  }

  /**
   * Polls once and carries out the work items it is given, as the Agent does: DNS Provider operations with the provider
   * code the platform itself runs, ADCS operations against its ADCS double (the Agent proper is Go, which has its own;
   * Seam B), and reports how each went.
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
    if (item.type.startsWith("adcs.")) return this.carryOutAdcs(item);
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

  /** Carries out an ADCS operation against its ADCS, as the Agent does with MS-WCCE, and reports how it went. */
  private async carryOutAdcs(item: WorkItem) {
    if (!this.adcs) return this.report(item.id, { ok: false, kind: "rejected", error: "this Agent cannot reach ADCS: it does not run on Windows" });
    try {
      if (item.type === "adcs.discover") await this.report(item.id, { ok: true, discovery: this.adcs.discover(item.payload.configString) });
      else if (item.type === "adcs.submit") await this.report(item.id, { ok: true, submission: await this.adcs.submit(item.payload.configString, item.payload.template, item.payload.csr) });
      else throw new Error(`a work item of a type this Agent does not know: ${item.type}`);
    } catch (err) {
      if (!(err instanceof AdcsDoubleError)) throw err;
      await this.report(item.id, { ok: false, kind: err.kind, error: err.message });
    }
  }

  /** Makes the key for the Managed Certificate here and reports a CSR for it, as the Agent does. */
  private async generateKey(item: WorkItem) {
    const { managedCertificateId, names, keyAlgorithm } = item.payload as { managedCertificateId: string; names: string[]; keyAlgorithm: KeyAlgorithm };
    if (isMlDsa(keyAlgorithm)) {
      const made = await mlDsaKeyAndCsr(keyAlgorithm, names);
      this.keys.set(managedCertificateId, made.key);
      return this.report(item.id, { ok: true, csr: made.csr });
    }
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

  /** Asks for a new credential; this Agent takes the new one when it is issued. */
  async rotate(credential: string | null = this.credential) {
    const res = await this.call("/api/agent/credential", undefined, credential);
    if (res.status === 200) {
      this.credential = res.body.credential;
      this.expiresAt = res.body.expiresAt;
    }
    return res;
  }
}
