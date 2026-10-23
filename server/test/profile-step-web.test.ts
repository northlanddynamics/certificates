// The New Managed Certificate dialog's profile step, as web/src/lib works it out: which choices it offers, which steps
// follow, and what the Key step offers on a profile. It decides nothing; the server refuses what a profile does not allow.
import { describe, expect, test } from "bun:test";
import { keyStepFor, nameRulesLabel, profileOptions, stepsFor } from "../../web/src/lib/profile-choice";

const web = { id: "6f1c2e0a-1b3d-4c5e-8f7a-9b0c1d2e3f4a", name: "Internal web", description: "TLS for internal web servers", allowedKeyAlgorithms: ["ecdsa-p256" as const], enabled: true };
const services = { id: "0a9b8c7d-6e5f-4a3b-2c1d-0e9f8a7b6c5d", name: "Services", description: "", allowedKeyAlgorithms: ["ecdsa-p384" as const, "rsa-3072" as const], enabled: true };
const retired = { id: "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", name: "Retired", description: "", allowedKeyAlgorithms: ["rsa-2048" as const], enabled: false };

const STEPS = [{ id: "profile" }, { id: "authority" }, { id: "names" }, { id: "key" }, { id: "review" }] as const;
const ids = (steps: readonly { id: string }[]) => steps.map((s) => s.id);

describe("the profile step", () => {
  test("offers the enabled profiles with their descriptions, then Custom when free-form proposing is open", () => {
    expect(profileOptions([web, retired, services], true)).toEqual([
      { value: web.id, title: "Internal web", description: "TLS for internal web servers" },
      { value: services.id, title: "Services", description: "" },
      { value: "custom", title: "Custom", description: expect.stringMatching(/Choose the Certificate Authority and key yourself/) },
    ]);
    expect(profileOptions([web], false).map((o) => o.value)).toEqual([web.id]);
  });

  test("is shown only when there is a profile to choose; on a profile the Authority step is skipped", () => {
    expect(ids(stepsFor(STEPS, { profilesOffered: true, profile: undefined }))).toEqual(["profile", "authority", "names", "key", "review"]);
    expect(ids(stepsFor(STEPS, { profilesOffered: true, profile: web }))).toEqual(["profile", "names", "key", "review"]);
    expect(ids(stepsFor(STEPS, { profilesOffered: false, profile: undefined }))).toEqual(["authority", "names", "key", "review"]);
  });
});

describe("the Key step on a profile", () => {
  const acme = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;

  test("is pre-filled with a profile's one key algorithm, with no choice", () => {
    expect(keyStepFor(web, acme)).toEqual({ keyAlgorithms: ["ecdsa-p256"], chosen: false });
  });

  test("is limited to a profile's list, and without a profile offers what the CA takes", () => {
    expect(keyStepFor(services, acme)).toEqual({ keyAlgorithms: ["ecdsa-p384", "rsa-3072"], chosen: true });
    expect(keyStepFor(undefined, acme)).toEqual({ keyAlgorithms: acme, chosen: true });
  });
});

describe("a profile's name rules, as the profile step and the names field show them", () => {
  test("say which names, how many and whether wildcards", () => {
    expect(nameRulesLabel({ exact: ["www.internal.acme"], zones: ["apps.internal.acme"], maxNames: 2, wildcards: false })).toBe(
      "Only www.internal.acme, or anything in apps.internal.acme; at most 2 names; no wildcards.",
    );
    expect(nameRulesLabel({ exact: [], zones: [], maxNames: 1, wildcards: true })).toBe("At most 1 name.");
  });

  test("are not shown when a profile has none", () => {
    expect(nameRulesLabel({ exact: [], zones: [], maxNames: null, wildcards: true })).toBeNull();
  });
});
