// The audit transport at its own seam: forwarded Audit Events written to a real syslog receiver over TLS (a local TLS
// server reading RFC 5425 frames) and posted to a real webhook (a local HTTP server).
import { SubjectAlternativeNameExtension, X509CertificateGenerator } from "@peculiar/x509";
import { afterEach, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:tls";
import { createAuditTransport } from "../src/audit-transport";

const certificateFor = async (name: string) => {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const certificate = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${name}`,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys,
    extensions: [new SubjectAlternativeNameExtension([{ type: "dns", value: name }])],
  });
  const key = Buffer.from(await crypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  return { cert: certificate.toString("pem"), key: `-----BEGIN PRIVATE KEY-----\n${key.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n` };
};

/** Splits an RFC 5425 stream into its messages: each is its length in octets, a space, and that many octets. */
function frames(stream: Buffer): string[] {
  const out: string[] = [];
  let at = 0;
  while (at < stream.length) {
    const space = stream.indexOf(0x20, at);
    const length = Number(stream.subarray(at, space).toString());
    out.push(stream.subarray(space + 1, space + 1 + length).toString());
    at = space + 1 + length;
  }
  return out;
}

/** A syslog receiver over TLS on localhost; `streams` resolves each connection's stream, in order, once the sender has ended it. */
async function startReceiver(cert: string, key: string) {
  const resolvers: ((stream: Buffer) => void)[] = [];
  const streams = Array.from({ length: 4 }, () => new Promise<Buffer>((resolve) => resolvers.push(resolve)));
  let connections = 0;
  const server: Server = createServer({ cert, key }, (socket) => {
    const resolve = resolvers[connections++]!;
    const chunks: Buffer[] = [];
    socket.on("data", (c: Buffer) => chunks.push(c));
    socket.on("end", () => {
      resolve(Buffer.concat(chunks));
      socket.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as { port: number }).port, streams, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

const event = (id: string, action: string) => ({
  schema: "certificate-platform.audit/1",
  id,
  occurredAt: "2026-02-01T09:00:00.000Z",
  organization: { id: "org-1" },
  actor: { id: "u1", email: "admin@acme.test" },
  action,
  target: { type: "team", id: "t1" },
  detail: { name: "Wéb" },
});

const cleanup: (() => unknown)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
});

describe("syslog over TLS", () => {
  test("writes each event as an RFC 5424 message carrying its JSON, framed by its length in octets", async () => {
    const { cert, key } = await certificateFor("localhost");
    const receiver = await startReceiver(cert, key);
    cleanup.push(receiver.close);
    const transport = createAuditTransport({ syslogCa: [cert], syslogHostname: "platform-1" });

    const events = [event("1", "team.created"), event("2", "team.deleted")];
    expect(await transport.deliver({ kind: "syslog", host: "localhost", port: receiver.port }, events)).toEqual({ delivered: 2 });

    const messages = frames(await receiver.streams[0]!);
    expect(messages).toEqual([
      `<110>1 2026-02-01T09:00:00.000Z platform-1 certificate-platform - audit - ${JSON.stringify(events[0])}`,
      `<110>1 2026-02-01T09:00:00.000Z platform-1 certificate-platform - audit - ${JSON.stringify(events[1])}`,
    ]);
    expect(JSON.parse(messages[0]!.slice(messages[0]!.indexOf("{")))).toEqual(events[0]);
  });

  test("delivers nothing to a receiver whose certificate is not trusted, or that is not there", async () => {
    const { cert, key } = await certificateFor("localhost");
    const receiver = await startReceiver(cert, key);
    cleanup.push(receiver.close);

    const untrusted = await createAuditTransport().deliver({ kind: "syslog", host: "localhost", port: receiver.port }, [event("1", "team.created")]);
    expect(untrusted.delivered).toBe(0);
    expect(untrusted.error).toBeString();

    await receiver.close();
    cleanup.length = 0;
    const gone = await createAuditTransport({ syslogCa: [cert] }).deliver({ kind: "syslog", host: "localhost", port: receiver.port }, [event("1", "team.created")]);
    expect(gone.delivered).toBe(0);
    expect(gone.error).toBeString();
  });
});

describe("webhook", () => {
  test("posts each event as JSON with the Authorization header, and stops at the first that is not taken", async () => {
    const received: { authorization: string | null; body: unknown }[] = [];
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch(req) {
        const body = await req.json();
        received.push({ authorization: req.headers.get("authorization"), body });
        return new Response(null, { status: received.length === 2 ? 503 : 204 });
      },
    });
    cleanup.push(() => server.stop(true));

    const events = [event("1", "team.created"), event("2", "team.renamed"), event("3", "team.deleted")];
    const outcome = await createAuditTransport().deliver({ kind: "webhook", url: `http://127.0.0.1:${server.port}/collector`, authorization: "Bearer t0k3n" }, events);
    expect(outcome).toEqual({ delivered: 1, error: "the webhook answered 503" });
    expect(received).toEqual([
      { authorization: "Bearer t0k3n", body: events[0] },
      { authorization: "Bearer t0k3n", body: events[1] },
    ]);
  });
});
