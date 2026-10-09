// The Certificate Authority interface Issuance will use, with Let's Encrypt (production and staging) as its only
// implementation. It holds no state: callers pass in the account they act as. So far it knows only about accounts;
// orders, DCV and revocation join it as the tickets that need them arrive.
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

export interface CertificateAuthority {
  /** Registers a new account under a new key, with the Organization's agreement to the CA's terms of service. */
  createAccount(environment: AcmeEnvironment, input: { contactEmail?: string }): Promise<CaAccount>;
  /** Resolves when the CA accepts `account.accountKey` as the key of `account.accountUrl`; throws a CertificateAuthorityError when not. */
  checkAccount(environment: AcmeEnvironment, account: CaAccount): Promise<void>;
}

export interface LetsEncryptConfig {
  /** Directory URLs by environment; the real Let's Encrypt ones unless overridden (tests point them at Pebble). */
  directoryUrls?: Partial<Record<AcmeEnvironment, string>>;
  /** A PEM CA certificate to trust besides the system's, for a test CA with a private root such as Pebble. */
  trustedCa?: string;
}

const LETS_ENCRYPT_DIRECTORIES: Record<AcmeEnvironment, string> = {
  staging: "https://acme-staging-v02.api.letsencrypt.org/directory",
  production: "https://acme-v02.api.letsencrypt.org/directory",
};

export function createLetsEncrypt({ directoryUrls = {}, trustedCa }: LetsEncryptConfig = {}): CertificateAuthority {
  // acme-client makes its requests through one shared axios instance, so this is process-wide.
  if (trustedCa) acme.axios.defaults.httpsAgent = new Agent({ ca: [...rootCertificates, trustedCa] });
  const directoryUrl = (environment: AcmeEnvironment) => directoryUrls[environment] ?? LETS_ENCRYPT_DIRECTORIES[environment];

  // acme-client reports a network failure as an unrelated TypeError (and, under Bun, its axios never gives up on a
  // refused connection), so reachability is checked first, by itself.
  async function reach(environment: AcmeEnvironment) {
    try {
      const res = await fetch(directoryUrl(environment), { signal: AbortSignal.timeout(10_000), tls: trustedCa ? { ca: trustedCa } : undefined });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (err: any) {
      throw new CertificateAuthorityError("unreachable", `could not reach the ${environment} CA: ${err?.code ?? err?.message}`);
    }
  }

  // Whatever the CA says no to comes back from acme-client as an Error carrying the CA's own explanation.
  const rejected = (err: unknown) => new CertificateAuthorityError("rejected", err instanceof Error ? err.message : String(err));

  return {
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
      const client = new acme.Client({ directoryUrl: directoryUrl(environment), accountKey, accountUrl });
      try {
        const account = await client.updateAccount({});
        if (account.status !== "valid") throw new Error(`the account is ${account.status}`);
      } catch (err) {
        throw rejected(err);
      }
    },
  };
}
