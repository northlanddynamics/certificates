// The confirmation an Organization Administrator sees before disabling a Certificate Profile, as web/src/lib words it:
// what stops, and how many pending decisions are held.
import { describe, expect, test } from "bun:test";
import { disableConsequence } from "../../web/src/lib/profile-disable";

describe("the disable confirmation", () => {
  test("says nothing more is requested through the profile, and that nothing is held when nothing is pending", () => {
    expect(disableConsequence({ proposals: 0, nameChanges: 0 })).toBe(
      "Nobody can request a certificate through it, Organization Administrators included, until it is enabled again. Nothing awaits Approval under it.",
    );
  });

  test("counts the pending Proposals and Name Changes it holds", () => {
    expect(disableConsequence({ proposals: 2, nameChanges: 1 })).toMatch(
      /2 Proposals and 1 Name Change awaiting Approval will be held: they can be rejected, but not approved until it is enabled again\.$/,
    );
    expect(disableConsequence({ proposals: 1, nameChanges: 0 })).toMatch(/ 1 Proposal awaiting Approval will be held: it can be rejected, but not approved until it is enabled again\.$/);
    expect(disableConsequence({ proposals: 0, nameChanges: 3 })).toMatch(/ 3 Name Changes awaiting Approval will be held: they can be rejected/);
  });
});
