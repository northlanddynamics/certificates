// The Certificate Authority interface Issuance uses, with Let's Encrypt (production and staging) as its only
// implementation. It holds no state: callers pass in the account they act as. It knows about accounts and about
// obtaining a Certificate for a CSR; revocation joins it with the ticket that needs it.
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
   * responder throws is thrown as it was.
   */
  issue(environment: AcmeEnvironment, account: CaAccount, request: { csr: string; responder: DnsChallengeResponder }): Promise<string>;
}

export interface LetsEncryptConfig {
  /** Directory URLs by environment; the real Let's Encrypt ones unless overridden (tests point them at Pebble). */
  directoryUrls?: Partial<Record<AcmeEnvironment, string>>;
  /** A PEM CA certificate to trust besides the system's, for a test CA with a private root such as Pebble. */
  trustedCa?: string;
  /** How long to wait between looks at an order or a challenge the CA is still working on (acme-client's 5 to 30 seconds unless overridden). */
  pollMs?: { min: number; max: number };
}

const LETS_ENCRYPT_DIRECTORIES: Record<AcmeEnvironment, string> = {
  staging: "https://acme-staging-v02.api.letsencrypt.org/directory",
  production: "https://acme-v02.api.letsencrypt.org/directory",
};

export function createLetsEncrypt({ directoryUrls = {}, trustedCa, pollMs }: LetsEncryptConfig = {}): CertificateAuthority {
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
    async issue(environment, account, { csr, responder }) {
      await reach(environment);
      const client = clientFor(environment, account);
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
