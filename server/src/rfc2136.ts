// The RFC 2136 DNS Provider: dynamic updates (BIND, Knot, PowerDNS, Windows DNS and appliances that take them)
// authenticated with a TSIG key (RFC 8945). The protocol is spoken directly, over TCP, which every such server
// accepts and which needs no retries: the reply is the server's answer or the connection's failure. Every reply
// must carry a valid signature, or a man in the middle could say yes for the server.
import { z } from "@hono/zod-openapi";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { connect, isIP } from "node:net";
import { DnsProviderError, type DnsProvider, type DnsProviderKind, type TxtRecord } from "./dns-provider";

export const TSIG_ALGORITHMS = ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1", "hmac-md5"] as const;
type TsigAlgorithm = (typeof TSIG_ALGORITHMS)[number];

const DOMAIN_NAME = /^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/;
/** A domain name as the platform keeps it: lower case, no trailing dot. */
const domainName = z
  .string()
  .transform((name) => name.toLowerCase().replace(/\.$/, ""))
  .refine((name) => DOMAIN_NAME.test(name), "not a domain name");

export const Rfc2136Settings = z.object({
  server: domainName.or(z.string().refine((s) => isIP(s) !== 0, "not a host name or IP address")).openapi({ description: "Host name or IP address of the DNS server." }),
  port: z.number().int().min(1).max(65535).default(53),
  zone: domainName.openapi({ description: "The zone the server accepts updates for; records are published only inside it." }),
  keyName: domainName.openapi({ description: "The name of the TSIG key, as the server knows it." }),
  algorithm: z.enum(TSIG_ALGORITHMS).default("hmac-sha256"),
});
export type Rfc2136Settings = z.infer<typeof Rfc2136Settings>;

const TSIG_SECRET = z
  .string()
  .refine((s) => /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0, "must be base64, as the TSIG key is written in the server's configuration");

export interface Rfc2136Options {
  /** How long to wait for the server, to connect and then to answer. */
  timeoutMs?: number;
}

// --- DNS messages (RFC 1035, RFC 2136) ---------------------------------------------------------------------------

const TYPE_SOA = 6;
const TYPE_TXT = 16;
const TYPE_TSIG = 250;
const CLASS_IN = 1;
const CLASS_NONE = 254;
const CLASS_ANY = 255;
const OPCODE_UPDATE = 5;
const TXT_TTL = 60;

const u16 = (n: number) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const u32 = (n: number) => Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const u48 = (n: number) => Buffer.concat([u16(Math.floor(n / 2 ** 32)), u32(n % 2 ** 32)]);

/** A name in wire format, uncompressed and lower case (which is also its canonical form for TSIG). */
function encodeName(name: string): Buffer {
  const labels = name.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  return Buffer.concat([...labels.flatMap((label) => [Buffer.from([label.length]), Buffer.from(label, "ascii")]), Buffer.from([0])]);
}

/** A name from `buf` at `pos`, following compression pointers; `next` is where the name ends in the message. */
function readName(buf: Buffer, pos: number): { name: string; next: number } {
  const labels: string[] = [];
  let next = -1;
  for (let hops = 0; hops < 128; hops++) {
    const length = buf[pos];
    if (length === undefined) break;
    if (length === 0) return { name: labels.join(".").toLowerCase(), next: next < 0 ? pos + 1 : next };
    if ((length & 0xc0) === 0xc0) {
      if (next < 0) next = pos + 2;
      pos = ((length & 0x3f) << 8) | (buf[pos + 1] ?? 0);
    } else {
      labels.push(buf.toString("latin1", pos + 1, pos + 1 + length));
      pos += 1 + length;
    }
  }
  throw new Error("malformed name");
}

/** TXT rdata: the value in strings of at most 255 bytes each. */
function txtRdata(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const strings: Buffer[] = [];
  for (let at = 0; at === 0 || at < bytes.length; at += 255) {
    const chunk = bytes.subarray(at, at + 255);
    strings.push(Buffer.from([chunk.length]), chunk);
  }
  return Buffer.concat(strings);
}

const resourceRecord = (name: string, type: number, rrClass: number, ttl: number, rdata: Buffer) =>
  Buffer.concat([encodeName(name), u16(type), u16(rrClass), u32(ttl), u16(rdata.length), rdata]);

/** An UPDATE message for `zone`, with `update` as its one change, and no signature yet. */
function updateMessage(zone: string, update: Buffer): { id: number; message: Buffer } {
  const id = randomBytes(2).readUInt16BE(0);
  // id, flags (UPDATE), one zone, no prerequisites, one update, no additional records.
  const header = Buffer.concat([u16(id), u16(OPCODE_UPDATE << 11), u16(1), u16(0), u16(1), u16(0)]);
  return { id, message: Buffer.concat([header, encodeName(zone), u16(TYPE_SOA), u16(CLASS_IN), update]) };
}

// --- TSIG (RFC 8945) -----------------------------------------------------------------------------------------------

const HMAC: Record<TsigAlgorithm, { hash: string; wireName: string }> = {
  "hmac-sha256": { hash: "sha256", wireName: "hmac-sha256" },
  "hmac-sha384": { hash: "sha384", wireName: "hmac-sha384" },
  "hmac-sha512": { hash: "sha512", wireName: "hmac-sha512" },
  "hmac-sha1": { hash: "sha1", wireName: "hmac-sha1" },
  "hmac-md5": { hash: "md5", wireName: "hmac-md5.sig-alg.reg.int" },
};
const FUDGE_SECONDS = 300;
const TSIG_ERRORS: Record<number, string> = { 16: "BADSIG", 17: "BADKEY", 18: "BADTIME" };

interface TsigKey {
  name: string;
  algorithm: TsigAlgorithm;
  secret: Buffer;
}

/** What a TSIG signature covers besides the message itself. */
const tsigVariables = (key: TsigKey, timeSigned: number, fudge: number, error: number, other: Buffer) =>
  Buffer.concat([
    encodeName(key.name),
    u16(CLASS_ANY),
    u32(0),
    encodeName(HMAC[key.algorithm].wireName),
    u48(timeSigned),
    u16(fudge),
    u16(error),
    u16(other.length),
    other,
  ]);

const mac = (key: TsigKey, ...parts: Buffer[]): Buffer =>
  createHmac(HMAC[key.algorithm].hash, key.secret).update(Buffer.concat(parts)).digest() as Buffer;

/** `message` with a TSIG record appended, and the MAC it carries (which the reply's own MAC is computed over). */
function signed(key: TsigKey, message: Buffer, timeSigned: number): { message: Buffer; mac: Buffer } {
  const requestMac = mac(key, message, tsigVariables(key, timeSigned, FUDGE_SECONDS, 0, Buffer.alloc(0)));
  const rdata = Buffer.concat([
    encodeName(HMAC[key.algorithm].wireName),
    u48(timeSigned),
    u16(FUDGE_SECONDS),
    u16(requestMac.length),
    requestMac,
    message.subarray(0, 2), // the original id
    u16(0), // no error
    u16(0), // no other data
  ]);
  const withTsig = Buffer.concat([message, resourceRecord(key.name, TYPE_TSIG, CLASS_ANY, 0, rdata)]);
  withTsig.writeUInt16BE(1, 10); // one additional record: the TSIG
  return { message: withTsig, mac: requestMac };
}

interface Reply {
  id: number;
  rcode: number;
  tsig?: { keyName: string; algorithm: string; timeSigned: number; fudge: number; mac: Buffer; originalId: number; error: number; other: Buffer; start: number };
}

function parseReply(buf: Buffer): Reply {
  if (buf.length < 12) throw new Error("short message");
  const counts = [4, 6, 8, 10].map((at) => buf.readUInt16BE(at)) as [number, number, number, number];
  let pos = 12;
  for (let i = 0; i < counts[0]; i++) pos = readName(buf, pos).next + 4;
  const reply: Reply = { id: buf.readUInt16BE(0), rcode: buf.readUInt16BE(2) & 0xf };
  const records = counts[1] + counts[2] + counts[3];
  for (let i = 0; i < records; i++) {
    const start = pos;
    const owner = readName(buf, pos);
    const type = buf.readUInt16BE(owner.next);
    const rdlength = buf.readUInt16BE(owner.next + 8);
    const rdata = owner.next + 10;
    if (type === TYPE_TSIG) {
      const algorithm = readName(buf, rdata);
      let at = algorithm.next;
      const macSize = buf.readUInt16BE(at + 8);
      reply.tsig = {
        keyName: owner.name,
        algorithm: algorithm.name,
        timeSigned: buf.readUIntBE(at, 6),
        fudge: buf.readUInt16BE(at + 6),
        mac: buf.subarray(at + 8 + 2, at + 10 + macSize),
        originalId: buf.readUInt16BE((at += 10 + macSize)),
        error: buf.readUInt16BE(at + 2),
        other: buf.subarray(at + 6, at + 6 + buf.readUInt16BE(at + 4)),
        start,
      };
    }
    pos = rdata + rdlength;
  }
  return reply;
}

/** Whether `reply` (parsed from `raw`) is signed with `key` as the answer to the request whose MAC was `requestMac`. */
function replyIsAuthentic(key: TsigKey, raw: Buffer, reply: Reply, requestMac: Buffer, now: number): boolean {
  const tsig = reply.tsig;
  if (!tsig || tsig.keyName !== key.name || tsig.algorithm !== HMAC[key.algorithm].wireName) return false;
  if (Math.abs(now - tsig.timeSigned) > tsig.fudge) return false;
  const message = Buffer.from(raw.subarray(0, tsig.start));
  message.writeUInt16BE(tsig.originalId, 0);
  message.writeUInt16BE(message.readUInt16BE(10) - 1, 10); // the message as it was before the TSIG was added
  const expected = mac(key, u16(requestMac.length), requestMac, message, tsigVariables(key, tsig.timeSigned, tsig.fudge, tsig.error, tsig.other));
  return expected.length === tsig.mac.length && timingSafeEqual(expected, tsig.mac);
}

// --- Transport -------------------------------------------------------------------------------------------------------

/** Sends one DNS message over TCP and returns the one that answers it. Rejects with a DnsProviderError("unreachable"). */
function exchange(host: string, port: number, message: Buffer, timeoutMs: number): Promise<Buffer> {
  const where = `${host}:${port}`;
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    let received = Buffer.alloc(0);
    const fail = (why: string) => {
      socket.destroy();
      reject(new DnsProviderError("unreachable", `${where} ${why}`));
    };
    socket.setTimeout(timeoutMs, () => fail(`did not answer within ${timeoutMs / 1000} seconds`));
    socket.on("error", (err: NodeJS.ErrnoException) => fail(`could not be reached: ${err.code ?? err.message}`));
    socket.on("close", () => fail("closed the connection without answering"));
    socket.on("connect", () => socket.write(Buffer.concat([u16(message.length), message])));
    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (received.length >= 2 && received.length >= 2 + received.readUInt16BE(0)) {
        socket.removeAllListeners("close");
        socket.end();
        resolve(received.subarray(2, 2 + received.readUInt16BE(0)));
      }
    });
  });
}

// --- The provider ----------------------------------------------------------------------------------------------------

const REFUSALS: Record<number, string> = {
  1: "did not understand the update (FORMERR)",
  2: "failed to process the update (SERVFAIL)",
  4: "does not support dynamic updates (NOTIMP)",
};

export function createRfc2136(settings: Rfc2136Settings, secret: string, { timeoutMs = 10_000 }: Rfc2136Options = {}): DnsProvider {
  const { server, port, zone, keyName, algorithm } = settings;
  const key: TsigKey = { name: keyName, algorithm, secret: Buffer.from(secret, "base64") };

  const rejected = (message: string) => new DnsProviderError("rejected", message);

  /** Makes the server apply `update` to the zone, or throws a DnsProviderError saying why not. */
  async function send(update: Buffer) {
    const { id, message } = updateMessage(zone, update);
    const timeSigned = Math.floor(Date.now() / 1000);
    const request = signed(key, message, timeSigned);

    const raw = await exchange(server, port, request.message, timeoutMs);
    let reply: Reply;
    try {
      reply = parseReply(raw);
    } catch {
      throw rejected(`${server}:${port} sent something that is not a DNS message`);
    }
    if (reply.id !== id) throw rejected(`${server}:${port} answered a different request`);

    const tsigError = reply.tsig && TSIG_ERRORS[reply.tsig.error];
    if (tsigError === "BADKEY") throw rejected(`the server does not know the TSIG key "${keyName}" (BADKEY)`);
    if (tsigError === "BADSIG")
      throw rejected(`the server rejected the TSIG signature (BADSIG): the key's secret or algorithm differs from the server's`);
    if (tsigError === "BADTIME")
      throw rejected(`the server rejected the TSIG time (BADTIME): the platform's clock and the server's are more than ${FUDGE_SECONDS / 60} minutes apart`);
    if (reply.tsig?.error) throw rejected(`the server rejected the TSIG signature (error code ${reply.tsig.error})`);
    if (!reply.tsig) {
      if (reply.rcode === 0) throw rejected(`the server's reply was not signed with the TSIG key, so it cannot be trusted`);
    } else if (!replyIsAuthentic(key, raw, reply, request.mac, Math.floor(Date.now() / 1000))) {
      throw rejected(`the server's reply was not signed correctly with the TSIG key, so it cannot be trusted`);
    }

    switch (reply.rcode) {
      case 0:
        return;
      case 5:
        throw rejected(`the server refused the update (REFUSED): the TSIG key "${keyName}" may not update that name in ${zone}, or the zone takes no dynamic updates`);
      case 9:
        throw rejected(`the server is not authoritative for ${zone} (NOTAUTH)`);
      case 10:
        throw rejected(`the name is not inside the zone ${zone} as the server has it (NOTZONE)`);
      default:
        throw rejected(`the server ${REFUSALS[reply.rcode] ?? `answered with error code ${reply.rcode}`}`);
    }
  }

  /** The record's name as kept here, which must be the zone or inside it. */
  function nameIn(record: TxtRecord) {
    const name = record.name.toLowerCase().replace(/\.$/, "");
    if (name !== zone && !name.endsWith(`.${zone}`)) throw rejected(`${name} is not inside the zone ${zone}`);
    return name;
  }

  const present = async (record: TxtRecord) => send(resourceRecord(nameIn(record), TYPE_TXT, CLASS_IN, TXT_TTL, txtRdata(record.value)));
  // Class NONE deletes exactly this record from the name's set, which is what lets several challenges share a name.
  const cleanUp = async (record: TxtRecord) => send(resourceRecord(nameIn(record), TYPE_TXT, CLASS_NONE, 0, txtRdata(record.value)));

  return {
    presentTxt: present,
    cleanUpTxt: cleanUp,
    async testConnection() {
      // Where a challenge for the zone's own name goes, which any policy that lets this key do its job allows.
      const record = { name: `_acme-challenge.${zone}`, value: `certificate-platform-connection-test-${randomBytes(8).toString("hex")}` };
      await present(record);
      await cleanUp(record).catch((err) => {
        if (!(err instanceof DnsProviderError)) throw err;
        throw new DnsProviderError(err.kind, `the test record was published but not removed (${err.message}); remove the TXT record "${record.value}" at ${record.name} by hand`);
      });
    },
  };
}

export const rfc2136: DnsProviderKind<Rfc2136Settings> = {
  settings: Rfc2136Settings,
  secret: TSIG_SECRET,
  create: (settings, secret) => createRfc2136(settings, secret),
};
