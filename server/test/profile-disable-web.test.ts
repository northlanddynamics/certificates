// The confirmation an Organization Administrator sees before disabling a Certificate Profile, as web/src/lib words it:
// what stops, how many live certificates stop renewing, and how many pending decisions are held.
import { describe, expect, test } from "bun:test";
import { disableConsequence } from "../../web/src/lib/profile-disable";

const none = { proposals: 0, nameChanges: 0 };

describe("the disable confirmation", () => {
  test("says nothing more is requested through the profile, and that nothing is held when nothing is linked or pending", () => {
    expect(disableConsequence({ linked: 0, pending: none })).toBe(
      "Nobody can request a certificate through it, Organization Administrators included, until it is enabled again. No live certificate was made from it. Nothing awaits Approval under it.",
    );
  });

  test("counts the live certificates that will stop renewing", () => {
    expect(disableConsequence({ linked: 3, pending: none })).toMatch(/ 3 live certificates made from it will stop renewing: they show as Renewal blocked when due, and Renew now is refused\. Nothing awaits/);
    expect(disableConsequence({ linked: 1, pending: none })).toMatch(/ 1 live certificate made from it will stop renewing: it shows as Renewal blocked/);
  });

  test("counts the pending Proposals and Name Changes it holds", () => {
    expect(disableConsequence({ linked: 0, pending: { proposals: 2, nameChanges: 1 } })).toMatch(
      /2 Proposals and 1 Name Change awaiting Approval will be held: they can be rejected, but not approved until it is enabled again\.$/,
    );
    expect(disableConsequence({ linked: 0, pending: { proposals: 1, nameChanges: 0 } })).toMatch(/ 1 Proposal awaiting Approval will be held: it can be rejected, but not approved until it is enabled again\.$/);
    expect(disableConsequence({ linked: 0, pending: { proposals: 0, nameChanges: 3 } })).toMatch(/ 3 Name Changes awaiting Approval will be held: they can be rejected/);
  });
});
