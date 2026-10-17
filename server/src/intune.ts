// The Intune Enrollment Validator: Microsoft Intune's SCEP API for third-party CAs, as docs/research/intune-scep-api.md
// pins it down from Microsoft's Intune-Resource-Access libraries. It signs in as the Organization's Entra app with the
// client credentials flow, discovers Intune's services from Microsoft Graph, and asks Intune's
// ScepRequestValidationFEService to validate each request (the challenge is the CSR's challengePassword, so the whole
// CSR is sent) and tells it of each outcome. Intune checks the challenge, the targeting and the CSR's names, so the
// kind vouches for names. Its API never says which device asked: the device ID is read from the CSR's
// `IntuneDeviceId://` URI SAN, which Microsoft recommends Intune SCEP profiles carry for NAC.
//
// Its revocation feed is Intune's queue of the certificates of devices it retired, wiped or unenrolled, downloaded from
// its PkiConnectorFEService at most hourly per tenant (Intune cools down for an hour after each download), each
// revoked for cessationOfOperation, since Intune gives no reason, and a result uploaded for each once revoked.
//
// Tokens and the discovered services are kept a while per app, and the services forgotten whenever Intune cannot be
// reached at the HTTP level, since they may have moved (as the libraries do). No error says what the secret or a token
// is (should Entra quote the secret, it is taken out); what Entra and Intune say is wrong is kept short.
import { z } from "@hono/zod-openapi";
import { createHash, randomUUID } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { EnrollmentValidatorError, type EnrollmentValidator, type EnrollmentValidatorKind, type RevocationOutcome, type RevocationRequest } from "./enrollment-validator";
import { sha256Hex } from "./sha256";

/** What the platform tells Intune it is, as `callerInfo` and `UserAgent`. */
export const INTUNE_CALLER_INFO = "northland-certificates/1.0";

const LOGIN = "https://login.microsoftonline.com";
const GRAPH = "https://graph.microsoft.com";
/** Microsoft Intune's first-party app ID, whose service principal publishes Intune's endpoints. */
const INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000";
const GRAPH_SCOPE = `${GRAPH}/.default`;
// The libraries append "/.default" to a resource with a trailing slash, and that double slash is what Entra is sent.
const INTUNE_SCOPE = "https://api.manage.microsoft.com//.default";
/** Where Intune's services are, which Graph's answer must keep to. */
const INTUNE_HOSTS = ".manage.microsoft.com";
const VALIDATION_SERVICE = "scepRequestValidationFEService";
const PKI_CONNECTOR_SERVICE = "pkiConnectorFEService";
const VALIDATION_API_VERSION = "2018-02-20";
// The libraries' literal default, odd year and all.
const PKI_CONNECTOR_API_VERSION = "5019-05-05";
/** The most downloadRevocationRequests hands over at once. */
const MAX_REVOCATION_REQUESTS = 500;
/** How often a tenant's queue may be downloaded: Intune's cool-down. */
const REVOCATION_INTERVAL_MS = 60 * 60_000;
/**
 * The result Intune is given for each outcome (IRA `CARequestErrorCode.cs`, as the Java library sends codes): an
 * already-revoked certificate is a success, an unknown one CertificateNotFoundError, and one the platform could not
 * revoke RetryableServiceException.
 */
const REVOCATION_RESULTS: Record<RevocationOutcome["outcome"], { succeeded: boolean; errorCode: string; errorMessage?: string }> = {
  revoked: { succeeded: true, errorCode: "0" },
  already_revoked: { succeeded: true, errorCode: "0" },
  not_found: { succeeded: false, errorCode: "4004", errorMessage: "No such certificate" },
  failed: { succeeded: false, errorCode: "4100" },
};
/** E_FAIL: what Intune is told a refused request failed with; it shows it in its reports. */
const E_FAIL = 0x80004005;
const MAX_DESCRIPTION = 255;
const MAX_ANSWER_BYTES = 1_000_000;
/** How long discovered services are trusted before Graph is asked again. */
const SERVICES_TTL_MS = 3_600_000;
/** How long before a token's end it is no longer used. */
const TOKEN_MARGIN_MS = 5 * 60_000;

const guid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, "must be a GUID");
const domain = z.string().regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i, "must be a GUID or a domain name");

/** What an Intune Enrollment Validator is configured with, besides its secret: the Entra app. */
export const IntuneSettings = z
  .object({
    tenantId: z.union([guid, domain]).openapi({ description: "The Entra tenant: its ID, or a domain of it such as contoso.onmicrosoft.com." }),
    appId: guid.openapi({ description: "The Entra app's application (client) ID, which has the Intune scep_challenge_provider and Graph Application.Read.All application permissions." }),
  })
  .strict();
export type IntuneSettings = z.infer<typeof IntuneSettings>;

export interface IntuneOptions {
  /** How it reaches Microsoft; the global fetch unless given (tests give the Intune double's). */
  fetch?: typeof fetch;
  /** How long to wait for an answer. */
  timeoutMs?: number;
  clock?: () => number;
}

const fail = (message: string) => new EnrollmentValidatorError(message);
/** What a service said, short, with nothing that could be taken for markup. */
const short = (text: unknown, max = 200) => (typeof text === "string" ? text.replace(/[\u0000-\u001f]/g, " ").split(/\r?\n|Trace ID:/)[0]!.trim().slice(0, max) : "");

/** The device ID in an `IntuneDeviceId://<id>` URI SAN, the scheme in any case. */
function intuneDeviceIdOf(names: { type: string; value: string }[]) {
  for (const { type, value } of names) {
    const match = type === "url" ? /^intunedeviceid:\/\/([^/?#\s]+)$/i.exec(value) : null;
    if (match) return match[1];
  }
  return undefined;
}

/** The Intune kind, reaching Microsoft through `options.fetch`. */
export function createIntuneKind(options: IntuneOptions = {}): EnrollmentValidatorKind<IntuneSettings> {
  const { fetch: send = fetch, timeoutMs = 15_000, clock = Date.now } = options;
  const tokens = new Map<string, { token: string; until: number }>();
  const services = new Map<string, { validation: string; pkiConnector: string; until: number }>();

  /** One HTTP call to Microsoft: its status and JSON (or text) answer, or an EnrollmentValidatorError saying it could not be made. */
  async function call(where: string, url: string, init: RequestInit) {
    let response: Response;
    try {
      response = await send(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      const e = err as { name?: string; code?: string };
      throw fail(e.name === "TimeoutError" ? `${where} did not answer within ${timeoutMs / 1000} seconds` : `${where} could not be reached${e.code ? ` (${e.code})` : ""}`);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (let next = await reader?.read(); next && !next.done; next = await reader!.read()) {
        size += next.value.length;
        if (size > MAX_ANSWER_BYTES) {
          await reader!.cancel().catch(() => {});
          throw fail(`${where} sent an answer larger than any it should`);
        }
        chunks.push(next.value);
      }
    } catch (err) {
      if (err instanceof EnrollmentValidatorError) throw err;
      throw fail(`${where} stopped answering part way`);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // Not JSON: an error page, say.
    }
    return { status: response.status, ok: response.ok, body };
  }

  return {
    settings: IntuneSettings,
    secret: z.string().min(1).max(1024),
    vouchesForNames: true,
    deviceIdOf: intuneDeviceIdOf,
    // Intune's queue is the tenant's, whichever Entra app downloads it, so the tenant's profiles share one feed and a
    // request is matched among all their Device Certificates. A tenant named once by ID and once by domain is two feeds.
    revocationFeed: { intervalMs: REVOCATION_INTERVAL_MS, sourceOf: ({ tenantId }) => tenantId.toLowerCase() },

    create({ tenantId, appId }, secret): EnrollmentValidator {
      const app = `${tenantId.toLowerCase()} ${appId.toLowerCase()}`;
      const secretHash = sha256Hex(secret);
      const tokenKey = (scope: string) => `${app} ${secretHash} ${scope}`;
      /** What Entra said, with the secret taken out should it ever be quoted. */
      const said = (text: unknown, max?: number) => short(text, max).split(secret).join("[secret]");

      /** A token for the scope, from Entra with the client credentials flow; a kept one unless `fresh`. */
      async function token(scope: string, fresh = false) {
        const kept = tokens.get(tokenKey(scope));
        if (!fresh && kept && kept.until > clock()) return kept.token;
        const { ok, status, body } = await call("Entra ID", `${LOGIN}/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
          body: new URLSearchParams({ grant_type: "client_credentials", client_id: appId, client_secret: secret, scope }).toString(),
        });
        const answer = (body ?? {}) as { access_token?: unknown; expires_in?: unknown; error?: unknown; error_description?: unknown };
        if (!ok || typeof answer.access_token !== "string") {
          const why = [said(answer.error, 60), said(answer.error_description)].filter(Boolean).join(": ");
          throw fail(`Entra ID would not sign the app in for ${scope === GRAPH_SCOPE ? "Microsoft Graph" : "Intune"} (${status})${why ? `: ${why}` : ""}; check the tenant ID, app ID and secret`);
        }
        const seconds = typeof answer.expires_in === "number" ? answer.expires_in : Number(answer.expires_in) || 0;
        // Spent tokens go, so that the secrets of old ones are not kept by their keys.
        for (const [key, kept] of tokens) if (kept.until <= clock()) tokens.delete(key);
        tokens.set(tokenKey(scope), { token: answer.access_token, until: clock() + seconds * 1000 - TOKEN_MARGIN_MS });
        return answer.access_token;
      }

      /** Intune's services for the tenant, as Graph publishes them; kept ones unless `fresh`. */
      async function discover(fresh = false) {
        const kept = services.get(app);
        if (!fresh && kept && kept.until > clock()) return kept;
        const { ok, status, body } = await call("Microsoft Graph", `${GRAPH}/v1.0/servicePrincipals/appId=${INTUNE_APP_ID}/endpoints`, {
          method: "GET",
          headers: { authorization: `Bearer ${await token(GRAPH_SCOPE, fresh)}`, accept: "application/json", "client-request-id": randomUUID() },
        });
        if (status === 401) tokens.delete(tokenKey(GRAPH_SCOPE));
        if (status === 403) throw fail("Microsoft Graph would not list Intune's services (403): grant the app the Graph Application.Read.All application permission, with admin consent");
        const code = said((body as { error?: { code?: unknown } } | null)?.error?.code, 80);
        if (!ok) throw fail(`Microsoft Graph would not list Intune's services (${status})${code ? `: ${code}` : ""}`);
        const value = (body as { value?: unknown })?.value;
        const map = new Map<string, string>();
        if (Array.isArray(value)) for (const e of value) if (typeof e?.providerName === "string" && typeof e?.uri === "string") map.set(e.providerName.toLowerCase(), e.uri);
        const https = (name: string) => {
          const uri = map.get(name.toLowerCase());
          if (!uri) throw fail(`Microsoft Graph lists no ${name} for the tenant: is Intune licensed in it?`);
          // The Intune token is sent there, so only to Intune's own hosts.
          if (!URL.canParse(uri) || new URL(uri).protocol !== "https:" || !new URL(uri).hostname.endsWith(INTUNE_HOSTS)) throw fail(`Microsoft Graph gave a ${name} that is not an https URL under ${INTUNE_HOSTS.slice(1)}`);
          return uri.replace(/\/+$/, "");
        };
        const found = { validation: https(VALIDATION_SERVICE), pkiConnector: https(PKI_CONNECTOR_SERVICE), until: clock() + SERVICES_TTL_MS };
        services.set(app, found);
        return found;
      }

      /** One call to an Intune service; resolves with its answer, or throws when Intune could not be asked or answered an HTTP error. */
      async function intuneCall(service: "validation" | "pkiConnector", path: string, apiVersion: string, payload: Record<string, unknown>) {
        const base = (await discover())[service];
        const { ok, status, body } = await call("Intune", `${base}/${path}`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${await token(INTUNE_SCOPE)}`,
            "content-type": "application/json",
            accept: "application/json",
            "client-request-id": randomUUID(),
            "api-version": apiVersion,
            UserAgent: INTUNE_CALLER_INFO,
          },
          body: JSON.stringify(payload),
        }).catch((err) => {
          services.delete(app);
          throw err;
        });
        if (!ok) {
          // The service may have moved, or the token been revoked: both are found again next time.
          services.delete(app);
          if (status === 401) tokens.delete(tokenKey(INTUNE_SCOPE));
          const permission = service === "validation" ? "the Intune scep_challenge_provider application permission" : "Intune's application permissions";
          throw fail(`Intune answered ${status}${status === 401 || status === 403 ? `: check that the app has ${permission}, with admin consent` : ""}`);
        }
        return body;
      }

      /** One ScepActions call; resolves with Intune's code and description, or throws when Intune could not be asked. */
      async function scepAction(action: string, payload: Record<string, unknown>) {
        const { code, errorDescription } = ((await intuneCall("validation", `ScepActions/${action}`, VALIDATION_API_VERSION, payload)) ?? {}) as { code?: unknown; errorDescription?: unknown };
        if (typeof code !== "string" || code === "") throw fail("Intune answered without a code, as it never should");
        return { code: said(code, 80), description: said(errorDescription) };
      }

      const csrOf = (csr: Uint8Array) => Buffer.from(csr).toString("base64");
      /** A notification Intune must have answered Success to; anything else is told again. */
      async function notify(action: string, notification: Record<string, unknown>) {
        const { code, description } = await scepAction(action, { notification: { ...notification, callerInfo: INTUNE_CALLER_INFO } });
        if (code !== "Success") throw fail(`Intune did not take the ${action}: ${code}${description ? `: ${description}` : ""}`);
      }

      return {
        async validate(request) {
          const { code, description } = await scepAction("validateRequest", { request: { transactionId: request.transactionId, certificateRequest: csrOf(request.csr), callerInfo: INTUNE_CALLER_INFO } });
          // Intune's code is the reason: it is what Intune's reports and its documentation name.
          return code === "Success" ? { allowed: true } : { allowed: false, reason: code };
        },
        async issued(request, certificate) {
          const cert = new x509.X509Certificate(certificate.pem);
          await notify("successNotification", {
            transactionId: request.transactionId,
            certificateRequest: csrOf(request.csr),
            certificateThumbprint: createHash("sha1").update(new Uint8Array(cert.rawData)).digest("hex").toUpperCase(),
            certificateSerialNumber: certificate.serial,
            certificateExpirationDateUtc: certificate.notAfter.toISOString(),
            issuingCertificateAuthority: certificate.issuer,
            caConfiguration: null,
            certificateAuthority: null,
          });
        },
        async failed(request, reason) {
          await notify("failureNotification", {
            transactionId: request.transactionId,
            certificateRequest: csrOf(request.csr),
            hResult: E_FAIL,
            errorDescription: reason.slice(0, MAX_DESCRIPTION) || "refused",
          });
        },
        revocations: {
          async pull() {
            const body = await intuneCall("pkiConnector", "CertificateAuthorityRequests/downloadRevocationRequests", PKI_CONNECTOR_API_VERSION, {
              // No issuer filter: its form is undocumented, so each request is matched by serial and issuer instead.
              downloadParameters: { maxRequests: MAX_REVOCATION_REQUESTS, issuerName: null },
            });
            const value = (body as { value?: unknown } | null)?.value;
            if (!Array.isArray(value)) throw fail("Intune answered the revocation download without a list of requests");
            return value.flatMap((r): RevocationRequest[] => {
              const { requestContext, serialNumber, issuerName } = (r ?? {}) as { requestContext?: unknown; serialNumber?: unknown; issuerName?: unknown };
              // Without its requestContext, a request cannot be answered, so is left out; any other is answered, if only not found.
              if (typeof requestContext !== "string" || requestContext === "") return [];
              return [{ ref: requestContext, serial: typeof serialNumber === "string" ? serialNumber : "", ...(typeof issuerName === "string" && issuerName !== "" ? { issuer: issuerName } : {}), reason: "cessationOfOperation" }];
            });
          },
          async report(outcomes) {
            const results = outcomes.map(({ ref, outcome, message }) => {
              const { succeeded, errorCode, errorMessage } = REVOCATION_RESULTS[outcome];
              return { requestContext: ref, succeeded, errorCode, errorMessage: succeeded ? null : (errorMessage ?? message ?? outcome).slice(0, MAX_DESCRIPTION) };
            });
            const body = await intuneCall("pkiConnector", "CertificateAuthorityRequests/uploadRevocationResults", PKI_CONNECTOR_API_VERSION, { results });
            if ((body as { value?: unknown } | null)?.value !== true) throw fail("Intune did not record the revocation results");
          },
        },
        async test() {
          // Never validateRequest (it would show in Intune's reports) nor downloadRevocationRequests (it would start Intune's cool-down).
          await discover(true);
          await token(INTUNE_SCOPE, true);
          return { note: "Signed in for Microsoft Graph and Intune, and found Intune's services. The Intune scep_challenge_provider permission is only proven by the first enrollment." };
        },
      };
    },
  };
}

/** The Intune kind the platform runs. */
export const intune = createIntuneKind();
