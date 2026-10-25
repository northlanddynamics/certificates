// Where a custom ACME CA's directory may be (directory-url.ts): https, and not at a loopback or link-local address, by
// what its name resolves to; private ranges are allowed. The API tests (acme-accounts.test.ts) cover the refusal as an
// administrator meets it; this covers the addresses a test CA cannot be reached at.
import { describe, expect, test } from "bun:test";
import { directoryUrlRefusal, isRefusedAddress } from "../src/issuance/acme/directory-url";

const LOOPBACK_OR_LINK_LOCAL = "the directory URL must not point at a loopback or link-local address";
const resolvingTo = (addresses: string[]) => ({ lookup: async () => addresses });

describe("the addresses a custom ACME CA may not be at", () => {
  test("loopback, link-local, unspecified and the metadata addresses are refused", () => {
    for (const address of ["127.0.0.1", "127.255.255.254", "0.0.0.0", "169.254.169.254", "169.254.0.1", "::1", "::", "fe80::1", "febf::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254", "fd00:ec2::254"]) {
      expect(isRefusedAddress(address)).toBe(true);
    }
  });

  test("private ranges and public addresses are allowed", () => {
    for (const address of ["10.0.0.1", "172.16.5.4", "192.168.1.10", "100.64.0.1", "8.8.8.8", "169.253.1.1", "fd00::1", "fc00::1", "fec0::1", "2001:db8::1", "::ffff:10.0.0.1"]) {
      expect(isRefusedAddress(address)).toBe(false);
    }
  });
});

describe("a directory URL", () => {
  test("must be https", async () => {
    expect(await directoryUrlRefusal("http://ca.internal/dir", resolvingTo(["10.0.0.1"]))).toBe("the directory URL must be https");
    expect(await directoryUrlRefusal("not a url")).toBe("the directory URL is not a URL");
  });

  test("is judged by every address its name resolves to", async () => {
    expect(await directoryUrlRefusal("https://ca.internal/dir", resolvingTo(["10.0.0.1"]))).toBeNull();
    expect(await directoryUrlRefusal("https://ca.internal/dir", resolvingTo(["10.0.0.1", "127.0.0.1"]))).toBe(LOOPBACK_OR_LINK_LOCAL);
    expect(await directoryUrlRefusal("https://metadata.internal/dir", resolvingTo(["169.254.169.254"]))).toBe(LOOPBACK_OR_LINK_LOCAL);
  });

  test("at an address is judged by it, however it is written", async () => {
    const never = { lookup: async () => expect.unreachable() as never };
    for (const url of ["https://127.0.0.1/dir", "https://2130706433/dir", "https://0x7f.1/dir", "https://[::1]/dir", "https://[::ffff:127.0.0.1]/dir", "https://169.254.169.254/dir"]) {
      expect(await directoryUrlRefusal(url, never)).toBe(LOOPBACK_OR_LINK_LOCAL);
    }
    expect(await directoryUrlRefusal("https://192.168.1.10:9000/acme/directory", never)).toBeNull();
  });

  test("a name that does not resolve is left to fail when connecting", async () => {
    expect(await directoryUrlRefusal("https://ca.invalid/dir", { lookup: async () => Promise.reject(new Error("ENOTFOUND")) })).toBeNull();
  });

  test("an allowed origin is exempt", async () => {
    expect(await directoryUrlRefusal("https://localhost:14000/dir", { allowedOrigins: ["https://localhost:14000"], lookup: async () => ["127.0.0.1"] })).toBeNull();
    expect(await directoryUrlRefusal("https://localhost:14001/dir", { allowedOrigins: ["https://localhost:14000"], lookup: async () => ["127.0.0.1"] })).toBe(LOOPBACK_OR_LINK_LOCAL);
  });
});
