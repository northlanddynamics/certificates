// The Infoblox DNS Provider at its boundary: WAPI over HTTPS, spoken to a double of Infoblox's WAPI
// (test/infoblox-double.ts) that checks the credentials and answers as NIOS does.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { DnsProviderError, type DnsProvider } from "../src/issuance/dcv/dns-provider";
import { DNS_PROVIDER_KINDS } from "../src/issuance/dcv/dns-provider-kinds";
import { INFOBLOX, startInfobloxDouble, type InfobloxDouble } from "./support/infoblox-double";

let wapi: InfobloxDouble;
beforeAll(async () => {
  wapi = await startInfobloxDouble();
});
afterAll(async () => {
  await wapi.close();
});
beforeEach(() => {
  wapi.zones.splice(0, wapi.zones.length, { name: "infoblox.test", view: "default" }, { name: "internal.test", view: "internal" });
  wapi.records.length = 0;
  wapi.requests.length = 0;
  wapi.failing = null;
  wapi.deletesFailing = false;
  wapi.mirror = null;
});

const kind = DNS_PROVIDER_KINDS.infoblox;
const settings = (over: Record<string, unknown> = {}) =>
  kind.settings.parse({ url: wapi.url, zone: "infoblox.test", caCertificate: wapi.caCertificate, ...over });
const provider = (over: Record<string, unknown> = {}, secret = INFOBLOX.secret): DnsProvider => kind.create(settings(over), secret);
const txt = () => wapi.records.map((r) => `${r.name} ${r.view} ${r.text}`).sort();

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

describe("publishing and removing TXT records", () => {
  test("a published record is served until it is cleaned up", async () => {
    const dns = provider();
    await dns.presentTxt({ name: "_acme-challenge.app.infoblox.test", value: "token-one" });
    expect(txt()).toEqual(["_acme-challenge.app.infoblox.test default token-one"]);
    expect(wapi.records[0]!.ttl).toBe(60);

    await dns.cleanUpTxt({ name: "_acme-challenge.app.infoblox.test", value: "token-one" });
    expect(txt()).toEqual([]);
  });

  test("a name may carry several records, and cleaning one up leaves the others", async () => {
    const dns = provider();
    const name = "_acme-challenge.wild.infoblox.test";
    await dns.presentTxt({ name, value: "for-the-wildcard" });
    await dns.presentTxt({ name, value: "for-the-name" });
    await dns.cleanUpTxt({ name, value: "for-the-wildcard" });
    expect(txt()).toEqual([`${name} default for-the-name`]);
  });

  test("publishing twice, and cleaning up what is not there, both succeed", async () => {
    const dns = provider();
    const record = { name: "_acme-challenge.again.infoblox.test", value: "again" };
    await dns.presentTxt(record);
    await dns.presentTxt(record);
    expect(txt()).toHaveLength(1);
    await dns.cleanUpTxt(record);
    await dns.cleanUpTxt(record);
    expect(txt()).toEqual([]);
  });

  test("names are taken as written, in any case and with or without the trailing dot", async () => {
    const dns = provider();
    await dns.presentTxt({ name: "_ACME-Challenge.Dotted.Infoblox.Test.", value: "dotted" });
    expect(txt()).toEqual(["_acme-challenge.dotted.infoblox.test default dotted"]);
    await dns.cleanUpTxt({ name: "_acme-challenge.dotted.infoblox.test", value: "dotted" });
    expect(txt()).toEqual([]);
  });

  test("records go in the configured view, and only that view's are touched", async () => {
    wapi.zones.push({ name: "infoblox.test", view: "internal" });
    const name = "_acme-challenge.split.infoblox.test";
    await provider({ view: "internal" }).presentTxt({ name, value: "inside" });
    await provider().presentTxt({ name, value: "outside" });
    expect(txt()).toEqual([`${name} default outside`, `${name} internal inside`]);

    await provider({ view: "internal" }).cleanUpTxt({ name, value: "outside" });
    expect(txt()).toHaveLength(2);
    await provider({ view: "internal" }).cleanUpTxt({ name, value: "inside" });
    expect(txt()).toEqual([`${name} default outside`]);
  });

  test("presenting the same record at the same moment succeeds for both", async () => {
    const record = { name: "_acme-challenge.race.infoblox.test", value: "same" };
    await Promise.all([provider().presentTxt(record), provider().presentTxt(record)]);
    expect(txt()).toEqual(["_acme-challenge.race.infoblox.test default same"]);
  });

  test("a name outside the zone is refused without asking Infoblox", async () => {
    const err = await failure(provider().presentTxt({ name: "_acme-challenge.example.org", value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toContain("infoblox.test");
    await failure(provider().cleanUpTxt({ name: "_acme-challenge.evilinfoblox.test", value: "v" }));
    expect(wapi.requests).toEqual([]);
  });

  test("a request carries the credentials, as HTTP Basic, and the records are asked for by exact name and text", async () => {
    await provider().presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" });
    const expected = `Basic ${Buffer.from(INFOBLOX.secret).toString("base64")}`;
    expect(wapi.requests.map((r) => r.authorization)).toEqual([expected, expected]);
    expect(wapi.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /wapi/v2.12/record:txt?name=_acme-challenge.x.infoblox.test&text=v&view=default",
      "POST /wapi/v2.12/record:txt",
    ]);
  });
});

describe("what goes wrong", () => {
  test("credentials Infoblox refuses are reported as such", async () => {
    const err = await failure(provider({}, "wapi-user:wrong").presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toMatch(/credentials/);
    expect(err.message).not.toContain("wrong");
  });

  test("a zone or view Infoblox does not have is reported with what Infoblox says", async () => {
    const noView = await failure(provider({ view: "nonexistent" }).presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(noView.kind).toBe("rejected");
    expect(noView.message).toContain("nonexistent");

    wapi.zones.splice(0);
    wapi.zones.push({ name: "other.test", view: "default" });
    const noZone = await failure(provider().presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(noZone.message).toContain("authoritative zone");
  });

  test("a server error is a rejection, and a server that is not there is unreachable", async () => {
    wapi.failing = { status: 503, body: "busy" };
    const busy = await failure(provider().presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(busy.kind).toBe("rejected");
    expect(busy.message).toContain("503");

    const gone = await failure(provider({ url: "https://127.0.0.1:1/wapi/v2.12" }).presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(gone.kind).toBe("unreachable");
  });

  test("an answer larger than any WAPI's is refused rather than read", async () => {
    wapi.failing = { status: 200, body: "x".repeat(1_500_000) };
    const err = await failure(provider().presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(err.kind).toBe("rejected");
    expect(err.message).toContain("larger");
  });

  test("a server whose certificate is not trusted is unreachable, not trusted anyway", async () => {
    const err = await failure(provider({ caCertificate: undefined }).presentTxt({ name: "_acme-challenge.x.infoblox.test", value: "v" }));
    expect(err.kind).toBe("unreachable");
    expect(wapi.requests).toEqual([]);
  });
});

describe("testing the connection", () => {
  test("publishes a throwaway record in the zone and removes it again", async () => {
    await provider().testConnection();
    expect(txt()).toEqual([]);
    expect(wapi.requests.some((r) => r.method === "POST" && (r.body as any).name === "_acme-challenge.infoblox.test")).toBe(true);
    expect(wapi.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  test("fails with Infoblox's reason when the record cannot be published", async () => {
    const err = await failure(provider({}, "wapi-user:wrong").testConnection());
    expect(err.message).toMatch(/credentials/);
    const zone = await failure(provider({ zone: "missing.test" }).testConnection());
    expect(zone.message).toContain("authoritative zone");
  });

  test("names the record to remove by hand when it was published but could not be removed", async () => {
    wapi.deletesFailing = true;
    const err = await failure(provider().testConnection());
    expect(err.message).toContain("remove the TXT record");
    expect(err.message).toContain("_acme-challenge.infoblox.test");
  });
});

describe("the kind", () => {
  test("settings are normalised, and the view defaults to `default`", () => {
    expect(kind.settings.parse({ url: "https://GM.Acme.Test/wapi/v2.12/", zone: "Acme.Test." })).toEqual({
      url: "https://gm.acme.test/wapi/v2.12",
      zone: "acme.test",
      view: "default",
    });
  });

  test("what cannot be an Infoblox DNS Provider is refused", () => {
    for (const bad of [
      { url: "http://gm.acme.test/wapi/v2.12" },
      { url: "https://gm.acme.test/" },
      { url: "https://gm.acme.test/wapi" },
      { url: "https://user:pass@gm.acme.test/wapi/v2.12" },
      { url: "https://gm.acme.test/wapi/v2.12?x=1" },
      { url: "gm.acme.test" },
      { zone: "not a zone" },
      { view: "" },
      { caCertificate: "not a certificate" },
    ])
      expect(kind.settings.safeParse({ url: "https://gm.acme.test/wapi/v2.12", zone: "acme.test", ...bad }).success).toBe(false);
  });

  test("the secret is a user name and a password, and nothing else", () => {
    expect(kind.secret.safeParse("user:pass").success).toBe(true);
    expect(kind.secret.safeParse("user:pa:ss").success).toBe(true);
    for (const bad of ["", "userpass", ":pass", "user:"]) expect(kind.secret.safeParse(bad).success).toBe(false);
  });

  test("it covers its zone and the names beneath it", () => {
    const s = settings();
    expect(kind.zoneOf(s, "infoblox.test")).toBe("infoblox.test");
    expect(kind.zoneOf(s, "a.b.infoblox.test")).toBe("infoblox.test");
    expect(kind.zoneOf(s, "evilinfoblox.test")).toBeNull();
  });
});
