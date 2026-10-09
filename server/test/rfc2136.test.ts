// The RFC 2136 DNS Provider at its boundary: the DNS wire protocol, spoken to a real server (BIND, docker-compose)
// and checked by asking that server's DNS what it now holds.
import { createServer, type Server } from "node:net";
import { Resolver } from "node:dns/promises";
import { afterAll, describe, expect, test } from "bun:test";
import { DnsProviderError, type DnsProvider } from "../src/dns-provider";
import { DNS_PROVIDER_KINDS } from "../src/dns-provider-kinds";
import { createRfc2136, type Rfc2136Settings } from "../src/rfc2136";
import { BIND } from "./harness";

// A resolver of its own for each question, so that nothing is answered from a cache.
const resolve = (name: string) => {
  const resolver = new Resolver({ timeout: 3000, tries: 1 });
  resolver.setServers([`${BIND.server}:${BIND.port}`]);
  return resolver.resolveTxt(name);
};
/** What the DNS server answers for `name`'s TXT records, one string per record. */
const txtAt = async (name: string) =>
  (await resolve(name).catch((err) => (err.code === "ENODATA" || err.code === "ENOTFOUND" ? [] : Promise.reject(err)))).map((r) => r.join("")).sort();

const settings = (over: Partial<Rfc2136Settings> = {}): Rfc2136Settings => ({
  server: BIND.server,
  port: BIND.port,
  zone: BIND.zone,
  keyName: BIND.keyName,
  algorithm: "hmac-sha256",
  ...over,
});
const provider = (over: Partial<Rfc2136Settings> = {}, secret = BIND.keySecret): DnsProvider =>
  DNS_PROVIDER_KINDS.rfc2136.create(DNS_PROVIDER_KINDS.rfc2136.settings.parse(settings(over)), secret);

/** What `fn` rejects with, which must be a DnsProviderError. */
async function failure(fn: Promise<unknown>) {
  const err = await fn.then(
    () => {
      throw new Error("expected a DnsProviderError, but it succeeded");
    },
    (e) => e,
  );
  expect(err).toBeInstanceOf(DnsProviderError);
  return err as DnsProviderError;
}

let n = 0;
/** A name nothing else in this run uses, in the zone. */
const fresh = (zone = BIND.zone) => `_acme-challenge.t${Date.now().toString(36)}${n++}.${zone}`;

describe("publishing and removing TXT records", () => {
  test("a published record is served until it is cleaned up", async () => {
    const name = fresh();
    const dns = provider();
    await dns.presentTxt({ name, value: "token-one" });
    expect(await txtAt(name)).toEqual(["token-one"]);

    await dns.cleanUpTxt({ name, value: "token-one" });
    expect(await txtAt(name)).toEqual([]);
  });

  test("a name may carry several records, and cleaning one up leaves the others", async () => {
    const name = fresh();
    const dns = provider();
    await dns.presentTxt({ name, value: "for-the-wildcard" });
    await dns.presentTxt({ name, value: "for-the-name" });
    expect(await txtAt(name)).toEqual(["for-the-name", "for-the-wildcard"]);

    await dns.cleanUpTxt({ name, value: "for-the-wildcard" });
    expect(await txtAt(name)).toEqual(["for-the-name"]);
    await dns.cleanUpTxt({ name, value: "for-the-name" });
  });

  test("publishing twice, and cleaning up what is not there, both succeed", async () => {
    const name = fresh();
    const dns = provider();
    await dns.presentTxt({ name, value: "again" });
    await dns.presentTxt({ name, value: "again" });
    expect(await txtAt(name)).toEqual(["again"]);
    await dns.cleanUpTxt({ name, value: "again" });
    await dns.cleanUpTxt({ name, value: "again" });
    await dns.cleanUpTxt({ name: fresh(), value: "never-there" });
  });

  test("names are taken as written, in any case and with or without the trailing dot", async () => {
    const name = fresh();
    const dns = provider();
    await dns.presentTxt({ name: `${name.toUpperCase()}.`, value: "dotted" });
    expect(await txtAt(name)).toEqual(["dotted"]);
    await dns.cleanUpTxt({ name, value: "dotted" });
    expect(await txtAt(name)).toEqual([]);
  });

  test("a value longer than one DNS string is kept whole", async () => {
    const name = fresh();
    const value = "x".repeat(300);
    const dns = provider();
    await dns.presentTxt({ name, value });
    // The server holds it as one record of two strings; Bun's resolver hands those back as separate entries.
    expect((await resolve(name)).flat().join("")).toBe(value);
    await dns.cleanUpTxt({ name, value });
    expect(await txtAt(name)).toEqual([]);
  });

  test("a name outside the zone is refused without asking the server", async () => {
    const dns = provider({ server: "192.0.2.1" }); // unroutable: asking it would time out, not answer
    const err = await failure(dns.presentTxt({ name: "_acme-challenge.example.org", value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toContain(BIND.zone);
    // A name that merely ends the same way is not inside the zone.
    await failure(dns.cleanUpTxt({ name: `evil${BIND.zone}`, value: "v" }));
  });
});

describe("TSIG algorithms", () => {
  for (const [algorithm, short] of Object.entries(BIND.otherKeys)) {
    test(`${algorithm}`, async () => {
      const name = `${short}.${BIND.zone}`;
      const dns = provider({ algorithm: algorithm as Rfc2136Settings["algorithm"], keyName: `${short}-key` }, BIND.otherKeySecret);
      await dns.presentTxt({ name, value: algorithm });
      expect(await txtAt(name)).toEqual([algorithm]);
      await dns.cleanUpTxt({ name, value: algorithm });
      expect(await txtAt(name)).toEqual([]);
    });
  }
});

describe("what goes wrong, in words", () => {
  test("a wrong secret is a TSIG failure", async () => {
    const dns = provider({}, Buffer.from("not the key at all").toString("base64"));
    const err = await failure(dns.presentTxt({ name: fresh(), value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toMatch(/TSIG/);
    expect(err.message).toMatch(/secret|signature/i);
  });

  test("a key name the server does not know is a TSIG failure", async () => {
    const err = await failure(provider({ keyName: "nobody" }).presentTxt({ name: fresh(), value: "v" }));
    expect(err.message).toMatch(/TSIG/);
    expect(err.message).toMatch(/key/i);
  });

  test("a key the server knows but does not allow to update there is refused", async () => {
    const dns = provider({ keyName: "sha1-key", algorithm: "hmac-sha1" }, BIND.otherKeySecret);
    const err = await failure(dns.presentTxt({ name: fresh(), value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toMatch(/refused/i);
  });

  test("a zone with no dynamic updates is refused", async () => {
    const err = await failure(provider({ zone: BIND.readonlyZone }).presentTxt({ name: fresh(BIND.readonlyZone), value: "v" }));
    expect(err.message).toMatch(/refused/i);
  });

  test("a zone the server does not serve is not authoritative", async () => {
    const err = await failure(provider({ zone: "elsewhere.test" }).presentTxt({ name: fresh("elsewhere.test"), value: "v" }));
    expect(err.message).toMatch(/not authoritative/i);
    expect(err.message).toContain("elsewhere.test");
  });

  test("a server that is not there is unreachable", async () => {
    const err = await failure(provider({ port: 1 }).presentTxt({ name: fresh(), value: "v" }));
    expect(err.kind).toBe("unreachable");
    expect(err.message).toContain(`${BIND.server}:1`);
  });

  test("a server that does not answer is unreachable too", async () => {
    const silent = await listen(() => {});
    const err = await failure(createRfc2136(settings({ port: silent.port }), BIND.keySecret, { timeoutMs: 300 }).presentTxt({ name: fresh(), value: "v" }));
    expect(err.kind).toBe("unreachable");
    expect(err.message).toMatch(/did not answer/);
  });
});

// A server that says yes to everything, without a valid signature: what someone between the platform and the real
// server could send. The platform must not take it for the server's word.
describe("an answer that is not signed by the key", () => {
  /** The DNS message of the request and a reply to it: same id, UPDATE opcode, response flag, no error, nothing else. */
  const unsignedYes = (request: Buffer) => {
    const reply = Buffer.alloc(12);
    request.copy(reply, 0, 0, 2);
    reply.writeUInt16BE(0x8000 | (5 << 11), 2);
    return reply;
  };

  test("is not believed", async () => {
    const liar = await listen((socket, request) => socket.write(frame(unsignedYes(request))));
    const err = await failure(provider({ port: liar.port }).presentTxt({ name: fresh(), value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toMatch(/not signed|unsigned|authenticat/i);
  });
});

const frame = (message: Buffer) => Buffer.concat([Buffer.from([message.length >> 8, message.length & 0xff]), message]);
const servers: Server[] = [];
afterAll(() => Promise.all(servers.map((s) => new Promise((done) => s.close(done)))));

/** A TCP server that hands each DNS request (without its length prefix) to `onRequest`. */
function listen(onRequest: (socket: import("node:net").Socket, request: Buffer) => void): Promise<{ port: number }> {
  return new Promise((resolve) => {
    const server = createServer((socket) => {
      let buffered = Buffer.alloc(0);
      socket.on("error", () => {});
      socket.on("data", (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (buffered.length >= 2 && buffered.length >= 2 + buffered.readUInt16BE(0)) onRequest(socket, buffered.subarray(2, 2 + buffered.readUInt16BE(0)));
      });
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => resolve({ port: (server.address() as { port: number }).port }));
  });
}
