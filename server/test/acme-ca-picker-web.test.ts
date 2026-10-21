// The issuer picker's ACME CAs, as the new Managed Certificate and Deployment dialogs list them (web/src/lib): which are
// offered and which are shown disabled. It decides nothing; the server refuses to issue without an account.
import { describe, expect, test } from "bun:test";
import { acmeCaChoices } from "../../web/src/lib/acme-ca-choices";

const staging = { id: "letsencrypt-staging", tag: "staging" as const, hasAccount: true };
const production = { id: "letsencrypt-production", tag: "production" as const, hasAccount: false };
const internal = { id: "0b9c3c1e-7c43-4a59-9f1e-3f1b8a3c1d2e", tag: "production" as const, hasAccount: true };
const untagged = { id: "5d0e2a8f-1c7b-4f0e-8a51-6a2b9c4d7e10", tag: null, hasAccount: true };
const all = [staging, production, internal, untagged];

describe("the ACME CAs in the issuer picker", () => {
  test("every one is listed in order; one the Organization has no account with is disabled", () => {
    expect(acmeCaChoices(all, "all").map(({ ca, disabled }) => [ca.id, disabled])).toEqual([
      [staging.id, false],
      [production.id, true],
      [internal.id, false],
      [untagged.id, false],
    ]);
  });

  test("filtered by a tag, only those with it are listed, built-in and custom alike; untagged lists those with none", () => {
    expect(acmeCaChoices(all, "production").map(({ ca }) => ca.id)).toEqual([production.id, internal.id]);
    expect(acmeCaChoices(all, "staging").map(({ ca }) => ca.id)).toEqual([staging.id]);
    expect(acmeCaChoices(all, "untagged").map(({ ca }) => ca.id)).toEqual([untagged.id]);
    // Still disabled without an account, filtered or not.
    expect(acmeCaChoices(all, "production").map(({ disabled }) => disabled)).toEqual([true, false]);
  });
});
