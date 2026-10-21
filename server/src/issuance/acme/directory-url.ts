// Where a custom ACME CA's directory may be: https only, and not at a loopback or link-local address (which holds the
// cloud metadata address), so that an Organization Administrator cannot point the platform at the machine it runs on or
// its metadata service. Private ranges are allowed, for an ACME server inside the Organization's network. It is checked
// when the ACME CA is saved and again each time the platform connects to it, by the addresses its name resolves to then.
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/** Looks up every address a host name resolves to. */
export type AddressLookup = (hostname: string) => Promise<string[]>;

const systemLookup: AddressLookup = async (hostname) => (await lookup(hostname, { all: true })).map((a) => a.address);

/** Whether the address (IPv4 or IPv6) is one the platform will not connect to: unspecified, loopback or link-local, or a cloud metadata address. */
export function isRefusedAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number) as [number, number];
    // 0.0.0.0/8 (reaching it reaches this host), 127.0.0.0/8 loopback, 169.254.0.0/16 link-local (169.254.169.254 is the metadata address).
    return a === 0 || a === 127 || (a === 169 && b === 254);
  }
  if (isIP(address) !== 6) return false;
  const groups = expandIpv6(address);
  // An IPv4 address mapped (::ffff:a.b.c.d) or embedded (::a.b.c.d) into IPv6 is judged as IPv4.
  if (groups.slice(0, 5).every((g) => g === 0) && (groups[5] === 0xffff || groups[5] === 0)) {
    const v4 = `${groups[6]! >> 8}.${groups[6]! & 0xff}.${groups[7]! >> 8}.${groups[7]! & 0xff}`;
    if (groups[5] === 0xffff || groups[6] !== 0) return isRefusedAddress(v4);
  }
  // :: unspecified, ::1 loopback.
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7]! <= 1) return true;
  // fe80::/10 link-local.
  if ((groups[0]! & 0xffc0) === 0xfe80) return true;
  // fd00:ec2::254, AWS's IPv6 metadata address, which sits in the private range.
  return groups.join(":") === [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254].join(":");
}

/** The eight 16-bit groups of an IPv6 address, any trailing dotted IPv4 part and zone index included. */
function expandIpv6(address: string): number[] {
  let text = address.replace(/%.*$/, "").toLowerCase();
  const v4 = text.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [, a, b, c, d] = v4.map(Number) as [number, number, number, number, number];
    text = text.slice(0, v4.index) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split("::") as [string, string | undefined];
  const parse = (part: string) => (part ? part.split(":").map((g) => parseInt(g, 16)) : []);
  const front = parse(head);
  const back = tail === undefined ? [] : parse(tail);
  return [...front, ...Array(8 - front.length - back.length).fill(0), ...back];
}

/**
 * Why the platform will not use `url` as an ACME directory, or null when it may. A name that does not resolve is not
 * refused here: connecting to it fails on its own. `allowedOrigins` are exempt, for a deployment's own test CA.
 */
export async function directoryUrlRefusal(url: string, { allowedOrigins = [], lookup = systemLookup }: { allowedOrigins?: string[]; lookup?: AddressLookup } = {}): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "the directory URL is not a URL";
  }
  if (parsed.protocol !== "https:") return "the directory URL must be https";
  if (allowedOrigins.includes(parsed.origin)) return null;
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  let addresses: string[];
  if (isIP(host)) addresses = [host];
  else {
    try {
      addresses = await lookup(host);
    } catch {
      return null;
    }
  }
  return addresses.some(isRefusedAddress) ? "the directory URL must not point at a loopback or link-local address" : null;
}
