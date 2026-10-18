// A test double for Infoblox's WAPI, at the provider boundary: an HTTPS server that speaks the slice of WAPI the
// Infoblox DNS Provider uses (record:txt, searched, created and deleted by reference, behind HTTP Basic
// authentication) and answers as NIOS does, errors included. It keeps its records in memory; `mirror` can also have
// them published somewhere a CA's DNS checks read (BIND), so the provider can be used for a real Issuance.
import { X509CertificateGenerator, SubjectAlternativeNameExtension } from "@peculiar/x509";
import { randomUUID } from "node:crypto";
import type { DnsProvider } from "../../src/issuance/dcv/dns-provider";

export const INFOBLOX = { username: "wapi-user", password: "wapi-password", secret: "wapi-user:wapi-password" };

export interface WapiRecord {
  ref: string;
  name: string;
  text: string;
  view: string;
  ttl?: number;
}

export interface InfobloxDouble {
  /** The WAPI base URL a DNS Provider is configured with. */
  url: string;
  /** The certificate it serves, as PEM, for the provider's `caCertificate`. */
  caCertificate: string;
  /** The zones it is authoritative for, each in the views it has them in. Adding a record anywhere else is a WAPI error. */
  zones: { name: string; view: string }[];
  /** The TXT records it holds. */
  records: WapiRecord[];
  /** Every request it received, for what the platform may and may not have sent. */
  requests: { method: string; path: string; authorization: string | null; body: unknown }[];
  /** Answer every request with this status and body, until it is set back to null. */
  failing: { status: number; body?: unknown } | null;
  /** Answer every deletion with a server error, and keep the record. */
  deletesFailing: boolean;
  /** Create each record here as well, and delete it from here too, as the DNS service behind the WAPI. */
  mirror: DnsProvider | null;
  close(): Promise<void>;
}

const certificateFor = async () => {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=infoblox.test",
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
    extensions: [new SubjectAlternativeNameExtension([{ type: "ip", value: "127.0.0.1" }, { type: "dns", value: "localhost" }])],
  });
  const key = Buffer.from(await crypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  return { cert: certificate.toString("pem"), key: `-----BEGIN PRIVATE KEY-----\n${key.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n` };
};

export async function startInfobloxDouble(version = "v2.12"): Promise<InfobloxDouble> {
  const { cert, key } = await certificateFor();
  const double: Omit<InfobloxDouble, "url" | "close"> = {
    caCertificate: cert,
    zones: [],
    records: [],
    requests: [],
    failing: null,
    deletesFailing: false,
    mirror: null,
  };
  const base = `/wapi/${version}`;
  const expected = `Basic ${Buffer.from(`${INFOBLOX.username}:${INFOBLOX.password}`).toString("base64")}`;
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  const respond = (status: number, body: unknown) => Response.json(body, { status });
  const refused = (text: string) => respond(400, { Error: `AdmConDataError: None (IBDataConflictError: ${text})`, code: "Client.Ibap.Data.Conflict", text });

  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    tls: { cert, key },
    async fetch(request) {
      const url = new URL(request.url);
      const raw = request.method === "POST" ? await request.text() : "";
      const body = raw ? JSON.parse(raw) : undefined;
      double.requests.push({ method: request.method, path: `${url.pathname}${url.search}`, authorization: request.headers.get("authorization"), body });
      if (double.failing) return respond(double.failing.status, double.failing.body ?? { Error: "failing" });
      if (request.headers.get("authorization") !== expected) return respond(401, { Error: "AdmConProtoError: Authorization Required", code: "Client.Ibap.Proto", text: "Authorization Required" });
      if (!url.pathname.startsWith(`${base}/`)) return respond(404, { Error: "AdmConProtoError: Invalid version", code: "Client.Ibap.Proto", text: "Invalid version" });
      // As sent: WAPI takes a reference's colons raw, so a client that escapes them is not understood.
      const target = url.pathname.slice(base.length + 1);

      if (request.method === "GET" && target === "record:txt") {
        const view = url.searchParams.get("view");
        const found = double.records.filter(
          (r) =>
            (!url.searchParams.has("name") || same(r.name, url.searchParams.get("name")!)) &&
            (!url.searchParams.has("text") || r.text === url.searchParams.get("text")) &&
            (!view || r.view === view),
        );
        return respond(200, found.map((r) => ({ _ref: r.ref, name: r.name, text: r.text, view: r.view })));
      }
      if (request.method === "POST" && target === "record:txt") {
        const { name, text, view = "default", ttl } = body as { name: string; text: string; view?: string; ttl?: number };
        if (!double.zones.some((z) => z.view === view)) return respond(400, { Error: `AdmConDataNotFoundError: The DNS view '${view}' is not found.`, code: "Client.Ibap.Data.NotFound", text: `The DNS view '${view}' is not found.` });
        if (!double.zones.some((z) => z.view === view && (same(name, z.name) || name.toLowerCase().endsWith(`.${z.name.toLowerCase()}`))))
          return respond(400, { Error: `AdmConDataError: None (IBDataConflictError: IB.Data.Conflict:The record '${name}' is not in an authoritative zone)`, code: "Client.Ibap.Data.Conflict", text: `The record '${name}' is not in an authoritative zone` });
        if (double.records.some((r) => same(r.name, name) && r.text === text && r.view === view)) return refused(`The record '${name}' already exists.`);
        const ref = `record:txt/${Buffer.from(randomUUID()).toString("base64url")}:${name.toLowerCase()}/${view}`;
        await double.mirror?.presentTxt({ name, value: text });
        double.records.push({ ref, name: name.toLowerCase(), text, view, ttl });
        return respond(201, ref);
      }
      if (request.method === "DELETE" && double.deletesFailing) return respond(500, { Error: "AdmConDataError: could not delete", text: "could not delete" });
      if (request.method === "DELETE" && target.startsWith("record:txt/")) {
        const at = double.records.findIndex((r) => r.ref === target);
        if (at < 0) return respond(404, { Error: `AdmConDataNotFoundError: Cannot find 'record:txt' object with reference '${target}'`, code: "Client.Ibap.Data.NotFound", text: "Not found" });
        const [gone] = double.records.splice(at, 1);
        await double.mirror?.cleanUpTxt({ name: gone!.name, value: gone!.text });
        return respond(200, target);
      }
      return respond(400, { Error: "AdmConProtoError: Unsupported request", code: "Client.Ibap.Proto", text: "Unsupported request" });
    },
  });
  return Object.assign(double, { url: `https://127.0.0.1:${server.port}${base}`, close: async () => void (await server.stop(true)) });
}
