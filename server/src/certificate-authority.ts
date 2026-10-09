// The Certificate Authority interface Issuance uses, with Let's Encrypt (production and staging) as its only
// implementation. It holds no state: callers pass in the account they act as. It knows about accounts and about
// obtaining a Certificate for a CSR; revocation joins it with the ticket that needs it.
import { AuthorityKeyIdentifierExtension, X509Certificate } from "@peculiar/x509";
import acme from "acme-client";
import { Agent } from "node:https";
import { rootCertificates } from "node:tls";

export const ACME_ENVIRONMENTS = ["staging", "production"] as const;
export type AcmeEnvironment = (typeof ACME_ENVIRONMENTS)[number];

export class CertificateAuthorityError extends Error {
  constructor(
    /** "rejected": the CA answered and said no. "unreachable": it did not answer. */
    readonly kind: "rejected" | "unreachable",
    message: string,
  ) {
    super(message);
  }
}

/** An Organization's account with a CA: where it lives and the key it acts with (PEM, a secret). */
export interface CaAccount {
  accountUrl: string;
  accountKey: string;
}

/** What a CA's DNS challenges are answered with while an order is placed; DCV (dcv.ts) is the implementation. */
export interface DnsChallengeResponder {
  /** Publishes the challenge `value` for `domain` and resolves once it is in place for the CA to see. */
  present(domain: string, value: string): Promise<void>;
  /** Takes it away again. Called whether or not the challenge succeeded, and a failure of its own is not the order's. */
  cleanUp(domain: string, value: string): Promise<void>;
}

/** What a CA's ACME Renewal Information (ARI) says about one Certificate: when it suggests renewing it, and when to ask again. */
export interface RenewalInfo {
  /** The CA's suggested window for renewing; a window already begun, or past, asks for Renewal now. */
  window: { start: Date; end: Date };
  /** How long the CA asks to wait before asking again (its Retry-After), if it said. */
  retryAfterMs: number | null;
}

export interface CertificateAuthority {
  /** What the CA calls itself in a Certificate's record of where it came from. */
  readonly name: string;
  /** Registers a new account under a new key, with the Organization's agreement to the CA's terms of service. */
  createAccount(environment: AcmeEnvironment, input: { contactEmail?: string }): Promise<CaAccount>;
  /** Resolves when the CA accepts `account.accountKey` as the key of `account.accountUrl`; throws a CertificateAuthorityError when not. */
  checkAccount(environment: AcmeEnvironment, account: CaAccount): Promise<void>;
  /**
   * Places an order for the names in `request.csr`, answers the CA's DNS challenges through `request.responder`, and
   * finalizes the order with the CSR. Resolves with the Certificate and the intermediates the CA served (PEM, the
   * Certificate first). Throws a CertificateAuthorityError when the CA says no or does not answer; whatever the
   * responder throws is thrown as it was. `request.replaces` is the Certificate (PEM, its chain or the leaf alone) the
   * order renews, which a CA with ARI treats as a coordinated Renewal; an order the CA will not take for it is placed
   * again without.
   */
  issue(environment: AcmeEnvironment, account: CaAccount, request: { csr: string; responder: DnsChallengeResponder; replaces?: string }): Promise<string>;
  /**
   * What the CA's ARI says about the Certificate (PEM, its chain or the leaf alone); null when the CA offers none, or
   * does not know the Certificate. Throws a CertificateAuthorityError when the CA does not answer.
   */
  renewalInfo(environment: AcmeEnvironment, certificate: string): Promise<RenewalInfo | null>;
  /**
   * The root certificates (PEM) the CA's chains end in, as far as the platform knows them. A CA serves a Certificate
   * with its intermediates and leaves the root out, so an export that includes the root takes it from here.
   */
  roots(environment: AcmeEnvironment): Promise<string[]>;
}

export interface LetsEncryptConfig {
  /** Directory URLs by environment; the real Let's Encrypt ones unless overridden (tests point them at Pebble). */
  directoryUrls?: Partial<Record<AcmeEnvironment, string>>;
  /** A PEM CA certificate to trust besides the system's, for a test CA with a private root such as Pebble. */
  trustedCa?: string;
  /**
   * The roots of each environment's chains, for exports that include the root. Production defaults to the system's
   * trusted roots, which hold Let's Encrypt's; staging's roots are in none, so a deployment that exports staging
   * chains with their root gives them here.
   */
  roots?: Partial<Record<AcmeEnvironment, () => Promise<string[]>>>;
  /** How long to wait between looks at an order or a challenge the CA is still working on (acme-client's 5 to 30 seconds unless overridden). */
  pollMs?: { min: number; max: number };
}

const LETS_ENCRYPT_DIRECTORIES: Record<AcmeEnvironment, string> = {
  staging: "https://acme-staging-v02.api.letsencrypt.org/directory",
  production: "https://acme-v02.api.letsencrypt.org/directory",
};

/** The ARI identifier of a Certificate (RFC 9773): its authority key identifier and serial number, each base64url, joined by a dot. */
export function certificateId(pem: string): string {
  const leaf = pem.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/)?.[0];
  if (!leaf) throw new CertificateAuthorityError("rejected", "there is no certificate to ask about");
  const cert = new X509Certificate(leaf);
  const keyId = cert.getExtension(AuthorityKeyIdentifierExtension)?.keyId;
  if (!keyId) throw new CertificateAuthorityError("rejected", "the certificate has no authority key identifier, so the CA's renewal information cannot be asked about it");
  // The serial number as the content of a DER INTEGER: no leading zeros, but one where the top bit would make it negative.
  let serial = cert.serialNumber.replace(/^(00)+/, "");
  if (serial.length % 2) serial = `0${serial}`;
  if (parseInt(serial.slice(0, 2), 16) >= 0x80) serial = `00${serial}`;
  return `${Buffer.from(keyId, "hex").toString("base64url")}.${Buffer.from(serial, "hex").toString("base64url")}`;
}

/** A Retry-After header as milliseconds: seconds, or a date. */
function retryAfterMs(header: string | null): number | null {
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const at = Date.parse(header);
  return Number.isNaN(at) ? null : Math.max(0, at - Date.now());
}

export function createLetsEncrypt({ directoryUrls = {}, trustedCa, roots = {}, pollMs }: LetsEncryptConfig = {}): CertificateAuthority {
  // acme-client makes its requests through one shared axios instance, so this is process-wide.
  if (trustedCa) acme.axios.defaults.httpsAgent = new Agent({ ca: [...rootCertificates, trustedCa] });
  const directoryUrl = (environment: AcmeEnvironment) => directoryUrls[environment] ?? LETS_ENCRYPT_DIRECTORIES[environment];

  // acme-client reports a network failure as an unrelated TypeError (and, under Bun, its axios never gives up on a
  // refused connection), so reachability is checked first, by itself.
  async function reach(environment: AcmeEnvironment): Promise<{ renewalInfo?: string }> {
    try {
      const res = await fetch(directoryUrl(environment), { signal: AbortSignal.timeout(10_000), tls: trustedCa ? { ca: trustedCa } : undefined });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err: any) {
      throw unreachable(environment, err);
    }
  }

  // Whatever the CA says no to comes back from acme-client as an Error carrying the CA's own explanation.
  const rejected = (err: unknown) => new CertificateAuthorityError("rejected", err instanceof Error ? err.message : String(err));

  const unreachable = (environment: AcmeEnvironment, err: any) => new CertificateAuthorityError("unreachable", `could not reach the ${environment} CA: ${err?.code ?? err?.message}`);

  const clientFor = (environment: AcmeEnvironment, { accountUrl, accountKey }: CaAccount) =>
    new acme.Client({
      directoryUrl: directoryUrl(environment),
      accountKey,
      accountUrl,
      // Left out when not set: acme-client would take an explicit undefined over its default.
      ...(pollMs && { backoffMin: pollMs.min, backoffMax: pollMs.max }),
    });

  return {
    name: "lets-encrypt",
    async roots(environment) {
      return roots[environment]?.() ?? (environment === "production" ? [...rootCertificates] : []);
    },
    async createAccount(environment, { contactEmail }) {
      await reach(environment);
      const accountKey = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
      const client = new acme.Client({ directoryUrl: directoryUrl(environment), accountKey });
      try {
        await client.createAccount({ termsOfServiceAgreed: true, contact: contactEmail ? [`mailto:${contactEmail}`] : undefined });
      } catch (err) {
        throw rejected(err);
      }
      return { accountUrl: client.getAccountUrl(), accountKey };
    },
    async checkAccount(environment, { accountUrl, accountKey }) {
      await reach(environment);
      const client = clientFor(environment, { accountUrl, accountKey });
      try {
        const account = await client.updateAccount({});
        if (account.status !== "valid") throw new Error(`the account is ${account.status}`);
      } catch (err) {
        throw rejected(err);
      }
    },
    async renewalInfo(environment, certificatePem) {
      const { renewalInfo } = await reach(environment);
      if (!renewalInfo) return null;
      let res: Response;
      try {
        res = await fetch(`${renewalInfo.replace(/\/$/, "")}/${certificateId(certificatePem)}`, { signal: AbortSignal.timeout(10_000), tls: trustedCa ? { ca: trustedCa } : undefined });
      } catch (err) {
        throw unreachable(environment, err);
      }
      // A CA that does not know the Certificate has no information about it.
      if (res.status === 404) return null;
      if (!res.ok) throw new CertificateAuthorityError("rejected", `the ${environment} CA's renewal information answered HTTP ${res.status}`);
      const body = (await res.json().catch(() => null)) as { suggestedWindow?: { start?: string; end?: string } } | null;
      const start = new Date(body?.suggestedWindow?.start ?? NaN);
      const end = new Date(body?.suggestedWindow?.end ?? NaN);
      if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) throw new CertificateAuthorityError("rejected", `the ${environment} CA's renewal information has no suggested window`);
      return { window: { start, end }, retryAfterMs: retryAfterMs(res.headers.get("retry-after")) };
    },
    async issue(environment, account, { csr, responder, replaces }) {
      const directory = await reach(environment);
      const client = clientFor(environment, account);
      // Only a CA that offers ARI is told what an order replaces.
      if (replaces && directory.renewalInfo) {
        // acme-client's auto mode takes no extra order fields, so the order it places is given the one it needs; an order
        // the CA will not take for it (the Certificate is not known there, or already replaced) is placed without.
        const place = client.createOrder.bind(client);
        const replacedId = certificateId(replaces);
        client.createOrder = (data) => place({ ...data, replaces: replacedId } as typeof data).catch(() => place(data));
      }
      // acme-client rethrows what a challenge callback throws, so those are told apart from the CA's own errors here.
      const fromResponder = new Set<unknown>();
      const answering = async <T>(call: () => Promise<T>) => {
        try {
          return await call();
        } catch (err) {
          fromResponder.add(err);
          throw err;
        }
      };
      try {
        return await client.auto({
          csr,
          termsOfServiceAgreed: true,
          challengePriority: ["dns-01"],
          // The responder has waited for the record to be visible, so there is nothing for acme-client to wait for.
          skipChallengeVerification: true,
          challengeCreateFn: (authz, _challenge, value) => answering(() => responder.present(authz.identifier.value, value)),
          challengeRemoveFn: (authz, _challenge, value) => answering(() => responder.cleanUp(authz.identifier.value, value)),
        });
      } catch (err: any) {
        if (fromResponder.has(err)) throw err;
        // acme-client reports a connection lost half way through as a bare axios error.
        if (err?.isAxiosError && !err.response) throw new CertificateAuthorityError("unreachable", `lost the connection to the ${environment} CA: ${err.code ?? err.message}`);
        throw rejected(err);
      }
    },
  };
}
