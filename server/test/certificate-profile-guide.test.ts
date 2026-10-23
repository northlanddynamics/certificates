// The Certificate Profiles guide comes twice: in the app, on the Certificate Profiles page (web/src/lib), and in
// docs/certificate-profiles.md. This keeps the two covering the same things, the guide pointing at ADR 0012, and
// its Audit Events those audit-events.md lists. What the guide says profiles do is what the certificate-profile-*
// tests test through the API.
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import { CERTIFICATE_PROFILE_GUIDE } from "../../web/src/lib/certificate-profile-guide";

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const guide = read("docs/certificate-profiles.md");
const headings = [...guide.matchAll(/^## (.+)$/gm)].map(([, heading]) => heading!);

describe("the Certificate Profiles guide", () => {
  test("the in-app guide has a section for each of the docs page's, in the same order", () => {
    expect(CERTIFICATE_PROFILE_GUIDE.map((section) => section.title)).toEqual(headings.filter((heading) => heading !== "Audit"));
  });

  test("covers setting one up, proposing through one, what disabling does to Renewal, and detaching", () => {
    const inApp = CERTIFICATE_PROFILE_GUIDE.flatMap((section) => [section.title, ...section.paragraphs]).join("\n");
    for (const text of [inApp, guide]) {
      expect(text).toMatch(/Renewal blocked/);
      expect(text).toMatch(/[Dd]etach/);
      expect(text).toMatch(/Proposal/);
      expect(text).toMatch(/name rules/);
    }
  });

  test("links ADR 0012", () => {
    const [, link] = guide.match(/\]\((adr\/0012-[^)]+\.md)\)/) ?? [];
    expect(link).toBeDefined();
    expect(existsSync(new URL(`../../docs/${link}`, import.meta.url))).toBe(true);
  });

  test("names each Certificate Profile Audit Event audit-events.md lists", () => {
    const listed = [...read("docs/audit-events.md").matchAll(/^\| `(certificate_profile\w*)` \| (.+) \|$/gm)].flatMap(([, resource, verbs]) =>
      [...verbs!.matchAll(/`(\w+)`/g)].map(([, verb]) => `${resource}.${verb}`),
    );
    expect(listed).toEqual(["certificate_profile.created", "certificate_profile.updated", "certificate_profile.disabled", "certificate_profile.enabled", "certificate_profile_settings.changed"]);
    for (const action of [...listed, "managed_certificate.profile_detached"]) expect(guide).toContain(`\`${action}\``);
  });
});
