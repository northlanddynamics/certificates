// The platform's own CA for Agent identity. It is not a Private CA (CONTEXT.md): it issues one kind of certificate, the
// mTLS client certificate by which an Agent proves who it is, and nothing else trusts it. Its key is made the first
// time it is needed and kept wrapped by the KMS (the platform's, not an Organization's, so with no Organization as context).
// An Agent generates its own key and sends a CSR; the platform signs the public key and never sees the private one (ADR 0002).
import * as x509 from "@peculiar/x509";
import { createPublicKey, randomBytes, webcrypto } from "node:crypto";
import { eq } from "drizzle-orm";
import type { Db } from "./db/client";
import { agentIdentityCa } from "./db/schema";
import type { Kms } from "./kms";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALGORITHM = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGNING = { name: "ECDSA", hash: "SHA-256" } as const;
const CA_NAME = "CN=Certificate Platform Agent Identity CA";
const CA_YEARS = 10;
const KMS_CONTEXT = "agent-identity-ca";
/** A little slack for a clock that is behind the platform's, so a certificate is usable the moment it is issued. */
const BACKDATE_MS = 5 * 60_000;
const DAY_MS = 24 * 3600_000;
const MAX_CSR_LENGTH = 4000;

export class AgentCsrError extends Error {}

export interface AgentIdentity {
  /** The Agent the certificate was issued to: its subject's common name. */
  agentId: string;
  /** Upper-case hex. */
  serial: string;
}

export interface AgentIdentityCa {
  /** The CA's own certificate, PEM: what a TLS terminator verifies Agents' client certificates against. */
  certificate(): Promise<string>;
  /** Issues an identity certificate for the key in `csr` (which must be an ECDSA P-256 CSR, signed by that key), naming `agentId`. Throws AgentCsrError. */
  issue(input: { csr: string; agentId: string; now: Date; validityDays: number }): Promise<{ certificate: string; serial: string; notAfter: Date }>;
  /** Who the certificate (PEM) proves, or null when this CA did not issue it, it is not valid at `now`, or it is not one of its identity certificates. */
  verify(certificate: string, now: Date): Promise<AgentIdentity | null>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function createAgentIdentityCa(deps: { db: Db; kms: Kms; clock: () => Date }): AgentIdentityCa {
  const { db, kms, clock } = deps;

  async function load() {
    const [row] = await db.select().from(agentIdentityCa).where(eq(agentIdentityCa.id, 1));
    if (!row) return null;
    const pkcs8 = new Uint8Array(await kms.unwrap(row.wrappedKey, KMS_CONTEXT));
    return {
      certificate: new x509.X509Certificate(row.certificatePem),
      pem: row.certificatePem,
      key: await crypto.subtle.importKey("pkcs8", pkcs8, ALGORITHM, false, ["sign"]),
    };
  }

  async function create() {
    const keys = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
    const now = clock();
    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: newSerial(),
      name: CA_NAME,
      notBefore: new Date(now.getTime() - BACKDATE_MS),
      notAfter: new Date(now.getTime() + CA_YEARS * 365 * DAY_MS),
      signingAlgorithm: SIGNING,
      keys,
      extensions: [
        new x509.BasicConstraintsExtension(true, 0, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    } as Parameters<typeof x509.X509CertificateGenerator.createSelfSigned>[0]);
    const wrappedKey = Buffer.from(await kms.wrap(new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.privateKey)), KMS_CONTEXT));
    // Two first uses at once: the second finds the first's CA and uses that one.
    await db.insert(agentIdentityCa).values({ id: 1, certificatePem: certificate.toString("pem"), wrappedKey }).onConflictDoNothing();
  }

  // The CA never changes once made, so it is read once.
  let cached: ReturnType<typeof ensure> | undefined;
  async function ensure() {
    const existing = await load();
    if (existing) return existing;
    await create();
    return (await load())!;
  }
  const ca = () =>
    (cached ??= ensure().catch((err) => {
      cached = undefined;
      throw err;
    }));

  return {
    async certificate() {
      return (await ca()).pem;
    },

    async issue({ csr: pem, agentId, now, validityDays }) {
      if (pem.length > MAX_CSR_LENGTH) throw new AgentCsrError("the CSR is too large");
      let csr: x509.Pkcs10CertificateRequest;
      try {
        csr = new x509.Pkcs10CertificateRequest(pem);
      } catch {
        throw new AgentCsrError("not a PEM-encoded certificate signing request");
      }
      // Signed by its own key: whoever sent it holds the private key it names.
      if (!(await csr.verify().catch(() => false))) throw new AgentCsrError("the CSR's signature does not verify against its own public key");
      const key = createPublicKey({ key: Buffer.from(csr.publicKey.rawData), format: "der", type: "spki" });
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new AgentCsrError("an Agent's identity key must be ECDSA P-256");

      const { certificate: issuer, key: signingKey } = (await ca());
      const serial = newSerial();
      const notAfter = new Date(now.getTime() + validityDays * DAY_MS);
      const leaf = await x509.X509CertificateGenerator.create({
        serialNumber: serial,
        subject: `CN=${agentId}`,
        issuer: issuer.subject,
        notBefore: new Date(now.getTime() - BACKDATE_MS),
        notAfter,
        signingAlgorithm: SIGNING,
        publicKey: csr.publicKey,
        signingKey,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
          new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth], true),
        ],
      } as Parameters<typeof x509.X509CertificateGenerator.create>[0]);
      return { certificate: leaf.toString("pem"), serial: serial.toUpperCase(), notAfter };
    },

    async verify(pem, now) {
      let leaf: x509.X509Certificate;
      try {
        leaf = new x509.X509Certificate(pem);
      } catch {
        return null;
      }
      const { certificate: issuer } = (await ca());
      if (leaf.issuer !== issuer.subject) return null;
      if (!(await leaf.verify({ date: now, publicKey: issuer.publicKey }).catch(() => false))) return null;
      const agentId = leaf.subjectName.getField("CN")[0];
      if (!agentId || !UUID.test(agentId)) return null;
      return { agentId, serial: leaf.serialNumber.toUpperCase() };
    },
  };
}

/** 16 random bytes as hex, the first never zero or with its top bit set, so that it is a positive number whose encoding keeps its length. */
function newSerial(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0]! % 0x7f) + 1;
  return bytes.toString("hex");
}
