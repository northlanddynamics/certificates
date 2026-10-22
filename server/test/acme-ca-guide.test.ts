// The ACME CAs guide (docs/acme-cas.md) names the built-in ACME CAs by their ids, directory URLs and tags; this keeps
// it in step with what the platform builds in (acme-cas.ts). What the guide says of adding, changing and deleting a
// custom one is what acme-accounts.test.ts tests through the API.
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import { BUILT_IN_ACME_CAS, DEFAULT_ACME_CA_ID } from "../src/issuance/acme/acme-cas";

const guide = readFileSync(new URL("../../docs/acme-cas.md", import.meta.url), "utf8");

describe("the ACME CAs guide", () => {
  test("its table of built-in ACME CAs is what the platform builds in", () => {
    const rows = [...guide.matchAll(/^\| (.+?) \| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|$/gm)].map(([, name, id, directoryUrl, tag]) => ({ name, id, directoryUrl, tag }));

    expect(rows).toEqual(BUILT_IN_ACME_CAS.map(({ name, id, directoryUrl, tag }) => ({ name, id, directoryUrl, tag })));
  });

  test("it names the default ACME CA", () => {
    expect(guide).toContain(`${BUILT_IN_ACME_CAS.find((ca) => ca.id === DEFAULT_ACME_CA_ID)!.name} is the default issuer`);
  });
});
