// Where sign-in sends someone back to, as web/src/lib works it out: only a path on the platform's own origin.
import { describe, expect, test } from "bun:test";
import { safeRedirect } from "../../web/src/lib/sign-in-redirect";

const origin = "https://certs.example.com";

describe("the sign-in redirect", () => {
  test("goes back to a path on the platform, with its search and hash", () => {
    expect(safeRedirect("/organizations/acme/certificates?status=issued#top", origin)).toBe("/organizations/acme/certificates?status=issued#top");
    expect(safeRedirect("/accept-invitation/26171131-9c8e-44e3-9d40-3a61cca2ac36", origin)).toBe("/accept-invitation/26171131-9c8e-44e3-9d40-3a61cca2ac36");
  });

  test("ignores anything that could leave the platform", () => {
    for (const redirect of ["https://evil.example", "//evil.example/x", "/\\evil.example", "\\\\evil.example", "javascript:alert(1)", "evil", "", " /x"]) {
      expect(safeRedirect(redirect, origin)).toBe("/");
    }
  });

  test("ignores a missing value and sign-in itself", () => {
    expect(safeRedirect(undefined, origin)).toBe("/");
    expect(safeRedirect(["/x"], origin)).toBe("/");
    expect(safeRedirect("/sign-in?redirect=/x", origin)).toBe("/");
  });
});
