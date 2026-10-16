// A test double for the Microsoft services the Intune Enrollment Validator talks to, at the HTTP boundary: a `fetch` that
// answers as Entra ID's token endpoint (client credentials), Microsoft Graph's endpoint discovery for the Intune service
// principal, and Intune's ScepRequestValidationFEService and PkiConnectorFEService, per docs/research/intune-scep-api.md.
// Nothing leaves the process. It takes only its own tenant, app ID and secret, records what it was asked and told, and
// can be told to refuse every request, to fail (answer 503) or to be unreachable (no connection at all). Revocations are
// queued as Intune queues them when a device is retired, wiped or unenrolled, handed over once by
// downloadRevocationRequests, and their results recorded from uploadRevocationResults.
import { randomUUID } from "node:crypto";

export const INTUNE = {
  tenantId: "8f0c2a4e-1b3d-4c5e-9f7a-0123456789ab",
  appId: "2b7e4c1d-3a5f-4e6b-8c9d-abcdef012345",
  secret: "entra-app-secret~value",
  /** A second Entra app of the same tenant, as an Organization with two apps has. */
  otherApp: { appId: "3c8f5d2e-4b6a-4f7c-9d0e-bcdef0123456", secret: "other-app-secret~value" },
};
const APP_SECRETS = new Map([
  [INTUNE.appId, INTUNE.secret],
  [INTUNE.otherApp.appId, INTUNE.otherApp.secret],
]);

const LOGIN = "https://login.microsoftonline.com";
const GRAPH = "https://graph.microsoft.com";
const INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000";
const GRAPH_SCOPE = "https://graph.microsoft.com/.default";
const INTUNE_SCOPE = "https://api.manage.microsoft.com//.default";
/** Where it says Intune's services are, as Graph would for a tenant. */
const SERVICE_HOST = "https://fef.msua01.manage.microsoft.com";
const VALIDATION = `${SERVICE_HOST}/RACerts/ScepRequestValidationFEService/Gateway/StatelessScepRequestValidationService`;
const PKI_CONNECTOR = `${SERVICE_HOST}/RACerts/StatelessPkiConnectorService/Gateway/StatelessPkiConnectorService`;

export interface IntuneValidation {
  transactionId: string;
  /** Base64 of the CSR's DER. */
  certificateRequest: string;
  callerInfo: string;
}
export interface IntuneSuccess extends IntuneValidation {
  certificateThumbprint: string;
  certificateSerialNumber: string;
  certificateExpirationDateUtc: string;
  issuingCertificateAuthority: string;
}
export interface IntuneFailure extends IntuneValidation {
  hResult: number;
  errorDescription: string;
}
/** A revocation request as Intune queues and hands it over. */
export interface IntuneRevocationRequest {
  requestContext: string;
  serialNumber: string;
  issuerName?: string;
  caConfiguration?: string | null;
}
export interface IntuneRevocationResult {
  requestContext: string;
  succeeded: boolean;
  errorCode: string;
  errorMessage: string | null;
}

export interface IntuneRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
}

export class IntuneDouble {
  /** Every request that reached it, in order. */
  readonly requests: IntuneRequest[] = [];
  readonly validations: IntuneValidation[] = [];
  readonly successes: IntuneSuccess[] = [];
  readonly failures: IntuneFailure[] = [];
  /** What downloadRevocationRequests was asked for, each time it was called. */
  readonly downloads: { maxRequests: number; issuerName: string | null }[] = [];
  /** The results uploadRevocationResults was given, in order. */
  readonly revocationResults: IntuneRevocationResult[] = [];
  /** Queued, not yet handed over. */
  private revocationQueue: IntuneRevocationRequest[] = [];
  /** When unset, uploadRevocationResults answers `{ value: false }`, as when Intune did not record them. */
  recordsResults = true;
  /** When set, Intune refuses every request with this code. */
  refusing: string | null = null;
  /** When set, every call is answered 503. */
  failing = false;
  /** When set, no call connects. */
  unreachable = false;
  /** When unset, the app has no Graph `Application.Read.All` consent, so discovery is forbidden. */
  graphConsented = true;
  /** The tokens it issued, for which resource; kept across resets, as Entra's would stay valid. */
  private tokens = new Map<string, string>();

  reset() {
    this.requests.length = this.validations.length = this.successes.length = this.failures.length = 0;
    this.downloads.length = this.revocationResults.length = 0;
    this.revocationQueue = [];
    this.recordsResults = true;
    this.refusing = null;
    this.failing = false;
    this.unreachable = false;
    this.graphConsented = true;
  }

  /** Queues a revocation of the serial, as Intune does for a device it retired; with the issuer unless none. Its requestContext. */
  queueRevocation(serialNumber: string, issuerName?: string) {
    const requestContext = randomUUID();
    this.revocationQueue.push({ requestContext, serialNumber, ...(issuerName === undefined ? {} : { issuerName }), caConfiguration: null });
    return requestContext;
  }

  /** The paths that reached Intune's own services (not Entra or Graph). */
  intuneCalls() {
    return this.requests.filter((r) => r.url.startsWith(SERVICE_HOST)).map((r) => new URL(r.url).pathname.split("/").slice(-2).join("/"));
  }

  readonly fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (this.unreachable) throw new TypeError(`Unable to connect. Is the computer able to access the url?`);
    this.requests.push({ method: request.method, url: request.url, headers: Object.fromEntries(request.headers) });
    if (this.failing) return Response.json({ error: "ServiceUnavailable" }, { status: 503 });
    const url = new URL(request.url);
    if (`${url.origin}${url.pathname}` === `${LOGIN}/${INTUNE.tenantId}/oauth2/v2.0/token`) return this.token(await request.text());
    if (url.origin === LOGIN) return Response.json({ error: "invalid_request", error_description: "AADSTS90002: Tenant not found." }, { status: 400 });
    const scope = this.tokens.get((request.headers.get("authorization") ?? "").replace(/^Bearer /, ""));
    if (`${url.origin}${url.pathname}` === `${GRAPH}/v1.0/servicePrincipals/appId=${INTUNE_APP_ID}/endpoints`) {
      if (scope !== GRAPH_SCOPE) return Response.json({ error: { code: "InvalidAuthenticationToken" } }, { status: 401 });
      if (!this.graphConsented) return Response.json({ error: { code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation." } }, { status: 403 });
      return Response.json({
        value: [
          { providerName: "ScepRequestValidationFEService", uri: VALIDATION },
          { providerName: "PkiConnectorFEService", uri: PKI_CONNECTOR },
          { providerName: "SomeOtherService", uri: `${SERVICE_HOST}/other` },
        ],
      });
    }
    if (request.url.startsWith(`${VALIDATION}/ScepActions/`) && request.method === "POST") {
      if (scope !== INTUNE_SCOPE) return new Response("unauthorized", { status: 401 });
      if (request.headers.get("api-version") !== "2018-02-20") return Response.json({ code: "Unknown", errorDescription: "unsupported api-version" }, { status: 400 });
      const body = (await request.json()) as { request?: IntuneValidation; notification?: IntuneSuccess & IntuneFailure };
      const action = url.pathname.split("/").pop();
      if (action === "validateRequest" && body.request) {
        this.validations.push(body.request);
        return Response.json(this.refusing ? { code: this.refusing, errorDescription: `the challenge was refused (${this.refusing})` } : { code: "Success", errorDescription: "" });
      }
      if (action === "successNotification" && body.notification) {
        this.successes.push(body.notification);
        return Response.json({ code: "Success", errorDescription: "" });
      }
      if (action === "failureNotification" && body.notification) {
        this.failures.push(body.notification);
        return Response.json({ code: "Success", errorDescription: "" });
      }
    }
    if (request.url.startsWith(`${PKI_CONNECTOR}/CertificateAuthorityRequests/`) && request.method === "POST") {
      if (scope !== INTUNE_SCOPE) return new Response("unauthorized", { status: 401 });
      if (request.headers.get("api-version") !== "5019-05-05") return new Response("unsupported api-version", { status: 400 });
      const action = url.pathname.split("/").pop();
      const body = (await request.json()) as { downloadParameters?: { maxRequests?: unknown; issuerName?: unknown }; results?: IntuneRevocationResult[] };
      if (action === "downloadRevocationRequests" && body.downloadParameters) {
        const { maxRequests, issuerName } = body.downloadParameters;
        if (typeof maxRequests !== "number" || maxRequests < 1 || maxRequests > 500) return new Response("maxRequests must be from 1 to 500", { status: 400 });
        this.downloads.push({ maxRequests, issuerName: (issuerName as string | null) ?? null });
        return Response.json({ value: this.revocationQueue.splice(0, maxRequests) });
      }
      if (action === "uploadRevocationResults" && Array.isArray(body.results)) {
        if (!this.recordsResults) return Response.json({ value: false });
        this.revocationResults.push(...body.results);
        return Response.json({ value: true });
      }
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  private token(form: string) {
    const params = new URLSearchParams(form);
    if (params.get("grant_type") !== "client_credentials") return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
    const secret = APP_SECRETS.get(params.get("client_id") ?? "");
    if (secret === undefined) return Response.json({ error: "unauthorized_client", error_description: "AADSTS700016: Application with identifier was not found in the directory." }, { status: 400 });
    if (params.get("client_secret") !== secret) return Response.json({ error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." }, { status: 401 });
    const scope = params.get("scope") ?? "";
    if (scope !== GRAPH_SCOPE && scope !== INTUNE_SCOPE) return Response.json({ error: "invalid_scope", error_description: "AADSTS70011: The provided value for scope is not valid." }, { status: 400 });
    const token = `eyJ.${randomUUID()}`;
    this.tokens.set(token, scope);
    return Response.json({ token_type: "Bearer", expires_in: 3599, access_token: token });
  }
}
