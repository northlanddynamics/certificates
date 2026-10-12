// The Infoblox DNS Provider: TXT records published and removed through the NIOS WAPI (REST over HTTPS, HTTP Basic
// authentication). The WAPI URL carries the version it is spoken in (https://<grid master>/wapi/v2.12). Nothing is
// sent over a connection whose certificate is not trusted, which is the system's roots, or the one certificate
// authority the settings name for a grid with its own; and nothing is followed to somewhere else, since the
// credentials go with each request.
import { z } from "@hono/zod-openapi";
import { X509Certificate } from "node:crypto";
import { DnsProviderError, domainName, nameInZone, testByThrowawayRecord, type DnsProvider, type DnsProviderKind, type TxtRecord } from "./dns-provider";

const WAPI_PATH = /^\/wapi\/v\d+(\.\d+)*$/;
const TXT_TTL = 60;

const wapiUrl = z
  .string()
  .refine((s) => URL.canParse(s), "not a URL")
  .transform((s) => new URL(s))
  .refine((u) => u.protocol === "https:", "must be https: the credentials are sent with every request")
  .refine((u) => !u.username && !u.password, "must not carry credentials: they are the secret")
  .refine((u) => !u.search && !u.hash, "must have no query or fragment")
  .refine((u) => WAPI_PATH.test(u.pathname.replace(/\/$/, "")), "must be the WAPI's, such as https://gm.example.com/wapi/v2.12")
  .transform((u) => `${u.origin}${u.pathname.replace(/\/$/, "")}`)
  .openapi({ description: "The WAPI's URL including its version, such as https://gm.example.com/wapi/v2.12." });

const pemCertificate = z.string().refine((pem) => {
  try {
    new X509Certificate(pem);
    return true;
  } catch {
    return false;
  }
}, "not a PEM certificate");

export const InfobloxSettings = z.object({
  url: wapiUrl,
  zone: domainName.openapi({ description: "The authoritative zone records are published in, and only there." }),
  view: z.string().trim().min(1).max(64).default("default").openapi({ description: "The DNS view the zone is in." }),
  caCertificate: pemCertificate
    .optional()
    .openapi({ description: "The certificate (PEM) of the authority the WAPI's certificate is signed by, for a grid whose own is not publicly trusted. Without it the system's roots are used." }),
});
export type InfobloxSettings = z.infer<typeof InfobloxSettings>;

/** `user:password`, as HTTP Basic joins them, so the user name has no colon. */
const WAPI_CREDENTIALS = z.string().refine((s) => {
  const colon = s.indexOf(":");
  return colon > 0 && colon < s.length - 1;
}, "must be the WAPI user's name and password as `user:password`");

export interface InfobloxOptions {
  /** How long to wait for the WAPI, to connect and then to answer. */
  timeoutMs?: number;
}

/** What the WAPI says is wrong, as it puts it, without the request's own details. */
function wapiText(body: unknown): string {
  if (typeof body === "string") return body.slice(0, 300);
  if (body && typeof body === "object") {
    const { text, Error: error } = body as { text?: unknown; Error?: unknown };
    for (const candidate of [text, error]) if (typeof candidate === "string" && candidate) return candidate.slice(0, 300);
  }
  return "";
}

export function createInfoblox(settings: InfobloxSettings, secret: string, { timeoutMs = 10_000 }: InfobloxOptions = {}): DnsProvider {
  const { url, zone, view, caCertificate } = settings;
  const authorization = `Basic ${Buffer.from(secret).toString("base64")}`;
  const where = new URL(url).host;
  const rejected = (message: string) => new DnsProviderError("rejected", message);

  /** One WAPI call; resolves with its JSON answer, or throws a DnsProviderError saying why not. */
  async function call(method: "GET" | "POST" | "DELETE", path: string, body?: unknown): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(`${url}/${path}`, {
        method,
        headers: { authorization, accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
        ...(caCertificate ? { tls: { ca: caCertificate } } : {}),
      });
    } catch (err) {
      const e = err as { name?: string; code?: string; message?: string };
      throw new DnsProviderError(
        "unreachable",
        e.name === "TimeoutError" ? `${where} did not answer within ${timeoutMs / 1000} seconds` : `${where} could not be reached: ${e.code ?? e.message ?? "unknown error"}`,
      );
    }
    const text = await response.text().catch(() => "");
    let answer: unknown = text;
    try {
      answer = JSON.parse(text);
    } catch {
      // Not JSON: an error page, say; what it says is kept as text.
    }
    if (response.ok) return answer;
    const reason = wapiText(answer);
    if (response.status === 401) throw rejected(`Infoblox refused the credentials (401): check the user name and password`);
    if (response.status === 403) throw rejected(`Infoblox does not allow the WAPI user to do that (403)${reason ? `: ${reason}` : ""}`);
    if (response.status >= 300 && response.status < 400) throw rejected(`${where} answered with a redirect (${response.status}): check the WAPI URL`);
    throw rejected(`Infoblox answered ${response.status}${reason ? `: ${reason}` : ""}`);
  }

  const txtQuery = (name: string, value: string) => new URLSearchParams({ name, text: value, view }).toString();

  /** The references of the TXT records in this view with exactly that name and text. */
  async function find(name: string, value: string): Promise<string[]> {
    const found = await call("GET", `record:txt?${txtQuery(name, value)}`);
    if (!Array.isArray(found)) throw rejected(`${where} did not answer as a WAPI does`);
    return found.map((r) => (r as { _ref?: unknown })?._ref).filter((ref): ref is string => typeof ref === "string");
  }

  async function present(record: TxtRecord) {
    const name = nameInZone(zone, record);
    if ((await find(name, record.value)).length > 0) return;
    try {
      await call("POST", "record:txt", { name, text: record.value, view, ttl: TXT_TTL, use_ttl: true });
    } catch (err) {
      // Another present of the same record in between is a success, not Infoblox's "already exists".
      if (err instanceof DnsProviderError && err.kind === "rejected" && (await find(name, record.value)).length > 0) return;
      throw err;
    }
  }

  async function cleanUp(record: TxtRecord) {
    const name = nameInZone(zone, record);
    for (const ref of await find(name, record.value)) {
      // The reference comes from the server and goes into a path: only a TXT record's is followed.
      if (!ref.startsWith("record:txt/") || ref.split("/").some((part) => part === ".." || part === ".")) throw rejected(`${where} named something other than a TXT record to delete`);
      // A reference has colons in it, which WAPI takes as they are.
      await call("DELETE", ref.split("/").map((part) => encodeURIComponent(part).replaceAll("%3A", ":")).join("/"));
    }
  }

  return { presentTxt: present, cleanUpTxt: cleanUp, testConnection: () => testByThrowawayRecord(zone, { presentTxt: present, cleanUpTxt: cleanUp }) };
}

export const infoblox: DnsProviderKind<InfobloxSettings> = {
  settings: InfobloxSettings,
  secret: WAPI_CREDENTIALS,
  create: (settings, secret) => createInfoblox(settings, secret),
  zoneOf: ({ zone }, name) => (name === zone || name.endsWith(`.${zone}`) ? zone : null),
};
